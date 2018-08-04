/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997-2000 Paul Henson -- see COPYRIGHT file for details
 *
 */

#include <stdio.h>
#include <syslog.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <pwd.h>
#include <shadow.h>
#include <time.h>
#include <dce/binding.h>
#include <dce/acct.h>
#include <dce/pgo.h>
#include <dce/secsts.h>
#include <dce/pthread.h>
#include "nss_dced.h"
#include "nss_dced_protocol.h"

#ifdef DEBUG
#define syslog_d(X...) syslog(LOG_DEBUG, X);
#else
#define syslog_d(X...)
#endif

pid_t child_pid = -1;

int clean_up(int signal)
{
  syslog(LOG_NOTICE, "received SIGHUP or SIGTERM. Killing child and exiting.");
  if (child_pid > 0)
    kill(child_pid, SIGTERM);
  exit(0);
}

int main(int argc, char **argv)
{
  time_t start_time;
  int fail_count = 0;
  
  openlog("nss_dced", LOG_PID, LOG_DAEMON);

  syslog_d("initializing.");
  
  switch(fork())
    {
      case 0:
	syslog_d("successfully detached.");
	break;

      case -1:
	syslog(LOG_ERR, "fork failed - %m.");
	syslog(LOG_NOTICE, "failed to start. No naming services available!");
	exit(1);
	break;
	
      default:
	syslog_d("child spawned. Exiting.");
	exit(0);
	break;
    }
  
  if (setsid() == -1)
    {
      syslog(LOG_ERR, "setsid failed - %m.");
      syslog(LOG_NOTICE, "failed to start. No naming services available!");
      exit(1);
    }

  {
    FILE *pidfile;

    if ((pidfile = fopen(NSS_DCED_PIDFILE, "w")) != NULL)
      {
	fprintf(pidfile, "%d\n", getpid());
	fclose(pidfile);
      }
    else
      {
	syslog(LOG_ERR, "open of pidfile %s failed - %m.", NSS_DCED_PIDFILE);
	syslog(LOG_NOTICE, "failed to log pid.");
      }
  }

  start_time = time(NULL);

  syslog_d("entering child maintenance loop.");
  while (1) {
    signal(SIGHUP, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    switch(child_pid = fork())
      {
        case 0:
	  syslog_d("calling main request processing routine.");
	  nss_dced_main();
	  break;
	  
        case -1:
	  syslog(LOG_ERR, "unable to fork child - %m.");
	  break;

        default:
	  signal(SIGHUP, (void *)clean_up);
	  signal(SIGTERM, (void *)clean_up);
	  if (waitpid(child_pid, NULL, 0) == child_pid)
	    syslog(LOG_NOTICE, "child exited.");
	  else
	    syslog(LOG_NOTICE, "abnormal child termination.");
	  break;
      }

    if ((time(NULL) - start_time) > 30)
      {
	syslog_d("resetting failure count.");
	fail_count = 0;
	start_time = time(NULL);
      }
    
    fail_count++;
    if (fail_count > 10) {
      syslog(LOG_NOTICE, "too many failures. Sleeping.");
      sleep(60);
    }
  }
}

static sec_rgy_plcy_t rgy_policy;

void nss_dced_main()
{
  int sock;
  int request_sock;
  struct sockaddr_un name;
  pthread_t request_thread;
  struct rlimit fdlimit;
  error_status_t dce_st;

  syslog_d("increasing file descriptor limit.");
  getrlimit(RLIMIT_NOFILE, &fdlimit);
  fdlimit.rlim_cur = fdlimit.rlim_max;
  setrlimit(RLIMIT_NOFILE, &fdlimit);

  sec_rgy_plcy_get_info(sec_rgy_default_handle, "", &rgy_policy, &dce_st);
  if (dce_st)
    {
      syslog(LOG_ERR, "error looking up registry policy - %d.", dce_st);
      syslog(LOG_NOTICE, "using default policy values.");
      rgy_policy.passwd_lifetime = NSS_DCED_PASSWD_LIFETIME;
    }
  
  if ((sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)) < 0)
    {
      syslog(LOG_ERR, "error creating socket - %m.");
      syslog(LOG_NOTICE, "exiting due to socket creation failure.");
      exit(1);
    }
  
  unlink(NSS_DCED_SOCKETPATH);
  
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, NSS_DCED_SOCKETPATH);
  
  if (bind(sock, (struct sockaddr *)&name, sizeof(struct sockaddr_un)))
    {
      syslog(LOG_ERR, "error binding socket - %m.");
      syslog(LOG_NOTICE, "exiting due to socket bind failure.");
      exit(1);
    }
  
  if(listen(sock, 5))
    {
      syslog(LOG_ERR, "error listening to socket - %m.");
      syslog(LOG_NOTICE, "exiting due to socket listen failure.");
      exit(1);
    }
  
  syslog_d("entering service request loop.");
  while(1)
    {
      syslog_d("waiting for request connection.");
      if ((request_sock = accept(sock, NULL, 0)) < 0)
	{
	  syslog(LOG_ERR, "error in accept - %m.");
	  syslog(LOG_NOTICE, "exiting due to accept failure.");
	  exit(1);
	}
      syslog_d("creating thread to handle new request %d.", request_sock);
      if(pthread_create(&request_thread, pthread_attr_default, handle_request,
			(pthread_addr_t) request_sock))
	{
	  syslog(LOG_ERR, "error in pthread_create - %m.");
	  syslog(LOG_NOTICE, "exiting due to pthread creation failure.");
	  exit(1);
	}
      syslog_d("detaching from handler thread.");
      pthread_detach(&request_thread);
    }
}

pthread_addr_t handle_request(pthread_addr_t arg)
{
  int sock = (int)arg;
  sec_rgy_cursor_t passwd_cursor, shadow_cursor, group_cursor;
  sec_rgy_name_t pname;
  nss_dced_message_t request, response;
  int string_length;
  uid_t uid;
  gid_t gid;

  syslog_d("handle_request(%d): entering request loop.", sock);
  while (read(sock, &request, sizeof(request)))
    {
      switch (request)
        {
          case NSS_DCED_GETPWNAM:
	    syslog_d("handle_request(%d): received NSS_DCED_GETPWNAM.", sock);
	    read(sock, &string_length, sizeof(string_length));
	    if (string_length > sec_rgy_name_t_size) string_length = sec_rgy_name_t_size;
	    read(sock, pname, string_length);
	    sec_rgy_cursor_reset(&passwd_cursor);
	    syslog_d("handle_request(%d): lookup for username %s.", sock, pname);
	    nss_dced_passwd_lookup(&passwd_cursor, sock, pname);
	    break;
	    
          case NSS_DCED_GETPWUID:
	    syslog_d("handle_request(%d): received NSS_DCED_GETPWUID.", sock);
	    read(sock, &uid, sizeof(uid));
	    sec_rgy_cursor_reset(&passwd_cursor);
	    syslog_d("handle_request(%d): lookup for UID %d.", sock, uid);
	    nss_dced_getpwuid(&passwd_cursor, sock, uid);
	    break;
	    
          case NSS_DCED_SETPWENT:
	    syslog_d("handle_request(%d): received NSS_DCED_SETPWENT.", sock);
	    sec_rgy_cursor_reset(&passwd_cursor);
	    response = NSS_DCED_SUCCESS;
	    write(sock, &response, sizeof(response));
	    break;
	    
          case NSS_DCED_GETPWENT:
	    syslog_d("handle_request(%d): received NSS_DCED_GETPWENT.", sock);
	    nss_dced_passwd_lookup(&passwd_cursor, sock, "");
	    break;
          
          case NSS_DCED_ENDPWENT:
	    syslog_d("handle_request(%d): received NSS_DCED_ENDPWENT.", sock);
	    break;
          
          case NSS_DCED_GETGRNAM:
	    syslog_d("handle_request(%d): received NSS_DCED_GETGRNAM.", sock);
	    read(sock, &string_length, sizeof(string_length));
	    if (string_length > sec_rgy_name_t_size) string_length = sec_rgy_name_t_size;
	    read(sock, pname, string_length);
	    syslog_d("handle_request(%d): lookup for groupname %s.", sock, pname);
	    nss_dced_getgrnam(sock, pname);
	    break;
	    
          case NSS_DCED_GETGRGID:
	    syslog_d("handle_request(%d): received NSS_DCED_GETGRGID.", sock);
	    read(sock, &gid, sizeof(gid));
	    syslog_d("handle_request(%d): lookup for GID %d.", sock, gid);
	    nss_dced_getgrgid(sock, gid);
	    break;

          case NSS_DCED_SETGRENT:
	    syslog_d("handle_request(%d): received NSS_DCED_SETGRENT.", sock);
	    sec_rgy_cursor_reset(&group_cursor);
	    response = NSS_DCED_SUCCESS;
	    write(sock, &response, sizeof(response));
	    break;
	    
          case NSS_DCED_GETGRENT:
	    syslog_d("handle_request(%d): received NSS_DCED_GETGRENT.", sock);
	    nss_dced_getgrent(&group_cursor, sock);
	    break;
          
          case NSS_DCED_ENDGRENT:
	    syslog_d("handle_request(%d): received NSS_DCED_ENDGRENT.", sock);
	    break;

          case NSS_DCED_GETGROUPSBYMEMBER:
	    syslog_d("handle_request(%d): received NSS_DCED_GETGROUPSBYMEMBER.", sock);
	    read(sock, &string_length, sizeof(string_length));
	    if (string_length > sec_rgy_name_t_size) string_length = sec_rgy_name_t_size;
	    read(sock, pname, string_length);
	    syslog_d("handle_request(%d): groups lookup for username %s.", sock, pname);
	    nss_dced_getgroupsbymember(sock, pname);
	    break;

  	  case NSS_DCED_GETSPNAM:
	    syslog_d("handle_request(%d): received NSS_DCED_GETSPNAM.", sock);
	    read(sock, &string_length, sizeof(string_length));
	    if (string_length > sec_rgy_name_t_size) string_length = sec_rgy_name_t_size;
	    read(sock, pname, string_length);
	    sec_rgy_cursor_reset(&shadow_cursor);
	    syslog_d("handle_request(%d): shadow lookup for username %s.", sock, pname);
	    nss_dced_shadow_lookup(&shadow_cursor, sock, pname);
	    break;
	    
          case NSS_DCED_SETSPENT:
	    syslog_d("handle_request(%d): received NSS_DCED_SETSPENT.", sock);
	    sec_rgy_cursor_reset(&shadow_cursor);
	    response = NSS_DCED_SUCCESS;
	    write(sock, &response, sizeof(response));
	    break;
	    
          case NSS_DCED_GETSPENT:
	    syslog_d("handle_request(%d): received NSS_DCED_GETSPENT.", sock);
	    nss_dced_shadow_lookup(&shadow_cursor, sock, "");
	    break;
          
          case NSS_DCED_ENDSPENT:
	    syslog_d("handle_request(%d): received NSS_DCED_ENDSPENT.", sock);
	    break;
          
        }
    }
  syslog_d("handle_request(%d): remote closed connection.", sock);
  close(sock);
}

void nss_dced_passwd_lookup(sec_rgy_cursor_t *passwd_cursor, int sock, sec_rgy_name_t pname)
{
  sec_rgy_login_name_t name_key;
  sec_rgy_sid_t uuid_sid;
  sec_rgy_unix_sid_t unix_sid;
  sec_rgy_acct_key_t key_parts;
  sec_rgy_acct_user_t user_part;
  sec_rgy_acct_admin_t admin_part;
  error_status_t dce_status;
  nss_dced_message_t response;
  int string_length;
  uid_t uid;
  gid_t gid;

  syslog_d("passwd_lookup(%d): called for username %s.", sock, pname);

  strncpy(name_key.pname, pname, sec_rgy_name_t_size);
  *name_key.gname = '\0';
  *name_key.oname = '\0';

  sec_rgy_acct_lookup(sec_rgy_default_handle, &name_key, passwd_cursor,
                      &name_key, &uuid_sid, &unix_sid, &key_parts,
                      &user_part, &admin_part, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
        syslog_d("passwd_lookup(%d): returning NSS_DCED_SUCCESS.", sock);
        response = NSS_DCED_SUCCESS;
        write(sock, &response, sizeof(response));
        break;

      case sec_rgy_server_unavailable:
        syslog_d("passwd_lookup(%d): returning NSS_DCED_UNAVAIL.", sock);
        response = NSS_DCED_UNAVAIL;
        write(sock, &response, sizeof(response));
        return;

      case sec_rgy_no_more_entries:
      case sec_rgy_object_not_found:
      default:
        syslog_d("passwd_lookup(%d): returning NSS_DCED_NOTFOUND.", sock);
        response = NSS_DCED_NOTFOUND;
        write(sock, &response, sizeof(response));
        return;
    }

  string_length = strlen(name_key.pname)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, name_key.pname, string_length);

  string_length = 1+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, "x", string_length);
  
  uid = unix_sid.person;
  write(sock, &uid, sizeof(uid));

  gid = unix_sid.group;
  write(sock, &gid, sizeof(gid));

  string_length = strlen(user_part.gecos)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, user_part.gecos, string_length);

  string_length = strlen(user_part.homedir)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, user_part.homedir, string_length);

  string_length = strlen(user_part.shell)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, user_part.shell, string_length);
}

void nss_dced_shadow_lookup(sec_rgy_cursor_t *shadow_cursor, int sock, sec_rgy_name_t pname)
{
  sec_rgy_login_name_t name_key;
  sec_rgy_sid_t uuid_sid;
  sec_rgy_unix_sid_t unix_sid;
  sec_rgy_acct_key_t key_parts;
  sec_rgy_acct_user_t user_part;
  sec_rgy_acct_admin_t admin_part;
  error_status_t dce_status;
  nss_dced_message_t response;
  int string_length;
  long value;

  syslog_d("shadow_lookup(%d): called for username %s.", sock, pname);

  strncpy(name_key.pname, pname, sec_rgy_name_t_size);
  *name_key.gname = '\0';
  *name_key.oname = '\0';

  sec_rgy_acct_lookup(sec_rgy_default_handle, &name_key, shadow_cursor,
                      &name_key, &uuid_sid, &unix_sid, &key_parts,
                      &user_part, &admin_part, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
        syslog_d("shadow_lookup(%d): returning NSS_DCED_SUCCESS.", sock);
        response = NSS_DCED_SUCCESS;
        write(sock, &response, sizeof(response));
        break;

      case sec_rgy_server_unavailable:
        syslog_d("shadow_lookup(%d): returning NSS_DCED_UNAVAIL.", sock);
        response = NSS_DCED_UNAVAIL;
        write(sock, &response, sizeof(response));
        return;

      case sec_rgy_no_more_entries:
      case sec_rgy_object_not_found:
      default:
        syslog_d("shadow_lookup(%d): returning NSS_DCED_NOTFOUND.", sock);
        response = NSS_DCED_NOTFOUND;
        write(sock, &response, sizeof(response));
        return;
    }

  string_length = strlen(name_key.pname)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, name_key.pname, string_length);

  string_length = strlen(user_part.passwd)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, user_part.passwd, string_length);

  value = user_part.passwd_dtm / (24*60*60);
  write(sock, &value, sizeof(value));

  value = NSS_DCED_SP_MIN;
  write(sock, &value, sizeof(value));

  value = ((rgy_policy.passwd_lifetime != 0) ? rgy_policy.passwd_lifetime / (24*60*60) : -1);
  write(sock, &value, sizeof(value));

  value = NSS_DCED_SP_WARN;
  write(sock, &value, sizeof(value));

  value = NSS_DCED_SP_INACT;
  write(sock, &value, sizeof(value));

  value = admin_part.expiration_date / (24*60*60);
  write(sock, &value, sizeof(value));

  value = 0;
  write(sock, &value, sizeof(value));
}

void nss_dced_getpwuid(sec_rgy_cursor_t *passwd_cursor, int sock, uid_t uid)
{
  sec_rgy_name_t pgo_name;
  error_status_t dce_status;
  nss_dced_message_t response;

  syslog_d("getpwuid(%d): called for UID %d.", sock, uid);
  
  sec_rgy_pgo_unix_num_to_name(sec_rgy_default_handle, sec_rgy_domain_person,
                               uid, pgo_name, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
	break;

      case sec_rgy_server_unavailable:
	syslog_d("getpwuid(%d): returning NSS_DCED_UNAVAIL.", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_object_not_found:
      default:
	syslog_d("getpwuid(%d): returning NSS_DCED_NOTFOUND.", sock);
	response = NSS_DCED_NOTFOUND;
	write(sock, &response, sizeof(response));
	return;
    }

  syslog_d("getpwuid(%d): calling passwd_lookup for username %s.", sock, pgo_name);
  nss_dced_passwd_lookup(passwd_cursor, sock, pgo_name);
}

void nss_dced_getgrnam(int sock, sec_rgy_name_t pname)
{
  error_status_t dce_status;
  sec_rgy_pgo_item_t pgo_item;
  sec_rgy_cursor_t group_cursor;
  nss_dced_message_t response;
  int string_length;
  gid_t gid;

  syslog_d("getgrnam(%d): called for groupname %s.", sock, pname);
  
  sec_rgy_cursor_reset(&group_cursor);
  sec_rgy_pgo_get_by_name(sec_rgy_default_handle, sec_rgy_domain_group, pname, &group_cursor,
                          &pgo_item, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
	syslog_d("getgrnam(%d): returning NSS_DCED_SUCCESS.", sock);
	response = NSS_DCED_SUCCESS;
	write(sock, &response, sizeof(response));
	break;

      case sec_rgy_server_unavailable:
	syslog_d("getgrnam(%d): returning NSS_DCED_UNAVAIL.", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_no_more_entries:
      case sec_rgy_object_not_found:
      default:
	syslog_d("getgrnam(%d): returning NSS_DCED_NOTFOUND.", sock);
	response = NSS_DCED_NOTFOUND;
	write(sock, &response, sizeof(response));
	return;
    }

  string_length = strlen(pname)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, pname, string_length);

  gid = pgo_item.unix_num;
  write(sock, &gid, sizeof(gid));

  return;
}

void nss_dced_getgrgid(int sock, gid_t gid)
{
  sec_rgy_name_t pgo_name;
  error_status_t dce_status;
  nss_dced_message_t response;
  int string_length;

  syslog_d("getgrgid(%d): called for GID %d.", sock, gid);
  
  sec_rgy_pgo_unix_num_to_name(sec_rgy_default_handle, sec_rgy_domain_group, gid, 
                               pgo_name, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
	syslog_d("getgrnam(%d): returning NSS_DCED_SUCCESS.", sock);
	response = NSS_DCED_SUCCESS;
	write(sock, &response, sizeof(response));
	break;

      case sec_rgy_server_unavailable:
	syslog_d("getgrgid(%d): returning NSS_DCED_UNAVAILn", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_object_not_found:
      default:
	syslog_d("getgrgid(%d): returning NSS_DCED_NOTFOUND.", sock);
	response = NSS_DCED_NOTFOUND;
	write(sock, &response, sizeof(response));
	return;
    }

  string_length = strlen(pgo_name)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, pgo_name, string_length);

  write(sock, &gid, sizeof(gid));

  return;
}

void nss_dced_getgrent(sec_rgy_cursor_t *group_cursor, int sock)
{
  sec_rgy_name_t pgo_name;
  error_status_t dce_status;
  sec_rgy_pgo_item_t pgo_item;
  nss_dced_message_t response;
  int string_length;
  gid_t gid;

  sec_rgy_pgo_get_next(sec_rgy_default_handle, sec_rgy_domain_group, "", group_cursor, &pgo_item,
                       pgo_name, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
	syslog_d("getgrent(%d): returning NSS_DCED_SUCCESS.", sock);
	response = NSS_DCED_SUCCESS;
	write(sock, &response, sizeof(response));
	break;

      case sec_rgy_server_unavailable:
	syslog_d("getgrent(%d): returning NSS_DCED_UNAVAIL.", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_no_more_entries:
      default:
	syslog_d("getgrent(%d): returning NSS_DCED_NOTFOUND.", sock);
	response = NSS_DCED_NOTFOUND;
	write(sock, &response, sizeof(response));
	return;
    }

  string_length = strlen(pgo_name)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, pgo_name, string_length);

  gid = pgo_item.unix_num;
  write(sock, &gid, sizeof(gid));

  return;
}

/* Snag NGROUPS_MAX */
#include <limits.h>

void nss_dced_getgroupsbymember(int sock, sec_rgy_name_t pname)
{
  error_status_t dce_status;
  sec_rgy_pgo_item_t pgo_item;
  sec_rgy_cursor_t member_cursor, pgo_cursor;
  sec_rgy_member_t member_list[NGROUPS_MAX-1];
  gid_t gid_list[NGROUPS_MAX-1];
  signed32 number_members, number_supplied;
  nss_dced_message_t response;
  int return_count, index;
  
  syslog_d("getgroupsbymember(%d): called for username %s.", sock, pname);

  sec_rgy_cursor_reset(&member_cursor);
  sec_rgy_pgo_get_members(sec_rgy_default_handle, sec_rgy_domain_person, pname, &member_cursor,
			  NGROUPS_MAX-1, member_list, &number_supplied, &number_members, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
	syslog_d("getgroupsbymember(%d): returning NSS_DCED_SUCCESS.", sock);
	response = NSS_DCED_SUCCESS;
	write(sock, &response, sizeof(response));
	break;

      case sec_rgy_server_unavailable:
	syslog_d("getgroupsbymember(%d): returning NSS_DCED_UNAVAIL.", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_no_more_entries:
      case sec_rgy_object_not_found:
      default:
	syslog_d("getgroupsbymember(%d): returning NSS_DCED_NOTFOUND.", sock);
	response = NSS_DCED_NOTFOUND;
	write(sock, &response, sizeof(response));
	return;
    }

  return_count = 0;
  for (index = 0; index < number_supplied; index++)
    {
      sec_rgy_cursor_reset(&pgo_cursor);
      sec_rgy_pgo_get_by_name(sec_rgy_default_handle, sec_rgy_domain_group, member_list[index],
			      &pgo_cursor, &pgo_item, &dce_status);

      if (dce_status == error_status_ok)
	gid_list[return_count++] = pgo_item.unix_num;
    }

  syslog_d("getgroupsbymember(%d): returning %d groups.", sock, return_count);

  write(sock, &return_count, sizeof(return_count));

  for (index = 0; index < return_count; index++)
    write(sock, &gid_list[index], sizeof(gid_list[index]));
  
  return;
}
