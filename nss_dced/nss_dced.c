/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pwd.h>
#include <dce/binding.h>
#include <dce/acct.h>
#include <dce/pgo.h>
#include <dce/secsts.h>
#include <dce/pthread.h>
#include "nss_dced.h"
#include "nss_dced_protocol.h"

#ifdef DEBUG

static int debug = 0;
#define TRACE(X...) if (debug) fprintf(stderr, X)

#else

#define TRACE(X...)

#endif

int main(int argc, char **argv)
{
  int sock;
  int request_sock;
  struct sockaddr_un name;
  pthread_t request_thread;
  struct rlimit fdlimit;

#ifdef DEBUG
  if (argc > 1)
    debug = !strcmp(argv[1], "-d");
#endif
  
  TRACE("nss_dced: initializing\n");

  getrlimit(RLIMIT_NOFILE, &fdlimit);
  fdlimit.rlim_cur = fdlimit.rlim_max;
  setrlimit(RLIMIT_NOFILE, &fdlimit);

  if ((sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)) < 0)
    {
      TRACE("nss_dced: unable to create socket, exiting\n");
      perror("socket");
      exit(1);
    }

  unlink(NSS_DCED_SOCKETPATH);

  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, NSS_DCED_SOCKETPATH);

  if (bind(sock, (struct sockaddr *)&name, sizeof(struct sockaddr_un)))
    {
      TRACE("nss_dced: unable to bind socket, exiting\n");
      perror("bind");
      exit(1);
    }

  if(listen(sock, 5))
    {
      TRACE("nss_dced: unable to listen to socket, exiting\n");
      perror("listen");
      exit(1);
    }

  TRACE("nss_dced: entering service request loop\n");
  while(1)
    {
      TRACE("nss_dced: waiting for request connection\n");
      if ((request_sock = accept(sock, NULL, 0)) < 0)
        {
          TRACE("nss_dced: error accepting request connection, exiting\n");
          perror("accept");
          exit(1);
        }
      TRACE("nss_dced: accepted request %d\n", request_sock);
      TRACE("nss_dced: creating thread to handle request\n");
      if(pthread_create(&request_thread, pthread_attr_default, handle_request,
                        (pthread_addr_t) request_sock))
        {
          TRACE("nss_dced: error creating handler thread, exiting\n");
          perror("pthread_create");
          exit(1);
        }
      TRACE("nss_dced: detaching from handler thread\n");
      pthread_detach(&request_thread);
    }
}

pthread_addr_t handle_request(pthread_addr_t arg)
{
  int sock = (int)arg;
  sec_rgy_cursor_t account_cursor, group_cursor;
  sec_rgy_name_t pname;
  nss_dced_message_t request, response;
  int string_length;
  uid_t uid;
  gid_t gid;

  TRACE("nss_dced.handle_request(%d): entering request loop\n", sock);
  while (read(sock, &request, sizeof(request)))
    {
      switch (request)
        {
        case NSS_DCED_GETPWNAM:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_GETPWNAM\n", sock);
          read(sock, &string_length, sizeof(string_length));
	  if (string_length > sec_rgy_name_t_size) string_length = sec_rgy_name_t_size;
          read(sock, pname, string_length);
          sec_rgy_cursor_reset(&account_cursor);
          TRACE("nss_dced.handle_request(%d): lookup for username %s\n", sock, pname);
          nss_dced_acct_lookup(&account_cursor, sock, pname);
          break;

        case NSS_DCED_GETPWUID:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_GETPWUID\n", sock);
          read(sock, &uid, sizeof(uid));
          sec_rgy_cursor_reset(&account_cursor);
          TRACE("nss_dced.handle_request(%d): lookup for UID %d\n", sock, uid);
          nss_dced_getpwuid(&account_cursor, sock, uid);
          break;

        case NSS_DCED_SETPWENT:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_SETPWENT\n", sock);
          sec_rgy_cursor_reset(&account_cursor);
          response = NSS_DCED_SUCCESS;
          write(sock, &response, sizeof(response));
          break;
          
        case NSS_DCED_GETPWENT:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_GETPWENT\n", sock);
          nss_dced_acct_lookup(&account_cursor, sock, "");
          break;
          
        case NSS_DCED_ENDPWENT:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_ENDPWENT\n", sock);
          break;
          
        case NSS_DCED_GETGRNAM:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_GETGRNAM\n", sock);
          read(sock, &string_length, sizeof(string_length));
	  if (string_length > sec_rgy_name_t_size) string_length = sec_rgy_name_t_size;
          read(sock, pname, string_length);
          TRACE("nss_dced.handle_request(%d): lookup for groupname %s\n", sock, pname);
          nss_dced_getgrnam(sock, pname);
          break;

        case NSS_DCED_GETGRGID:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_GETGRGID\n", sock);
          read(sock, &gid, sizeof(gid));
          TRACE("nss_dced.handle_request(%d): lookup for GID %d\n", sock, gid);
          nss_dced_getgrgid(sock, gid);
          break;

        case NSS_DCED_SETGRENT:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_SETGRENT\n", sock);
          sec_rgy_cursor_reset(&group_cursor);
          response = NSS_DCED_SUCCESS;
          write(sock, &response, sizeof(response));
          break;
          
        case NSS_DCED_GETGRENT:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_GETGRENT\n", sock);
          nss_dced_getgrent(&group_cursor, sock);
          break;
          
        case NSS_DCED_ENDGRENT:
          TRACE("nss_dced.handle_request(%d): received NSS_DCED_ENDGRENT\n", sock);
          break;
        }
    }
  TRACE("nss_dced.handle_request(%d): remote closed connection\n", sock);
  close(sock);
}

void nss_dced_acct_lookup(sec_rgy_cursor_t *account_cursor, int sock, sec_rgy_name_t pname)
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

  TRACE("nss_dced.acct_lookup(%d): called for username %s\n", sock, pname);

  strncpy(name_key.pname, pname, sec_rgy_name_t_size);
  *name_key.gname = '\0';
  *name_key.oname = '\0';

  sec_rgy_acct_lookup(sec_rgy_default_handle, &name_key, account_cursor,
                      &name_key, &uuid_sid, &unix_sid, &key_parts,
                      &user_part, &admin_part, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
        TRACE("nss_dced.acct_lookup(%d): returning NSS_DCED_SUCCESS\n", sock);
        response = NSS_DCED_SUCCESS;
        write(sock, &response, sizeof(response));
        break;

      case sec_rgy_server_unavailable:
        TRACE("nss_dced.acct_lookup(%d): returning NSS_DCED_UNAVAIL\n", sock);
        response = NSS_DCED_UNAVAIL;
        write(sock, &response, sizeof(response));
        return;

      case sec_rgy_no_more_entries:
      case sec_rgy_object_not_found:
      default:
        TRACE("nss_dced.acct_lookup(%d): returning NSS_DCED_NOTFOUND\n", sock);
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

void nss_dced_getpwuid(sec_rgy_cursor_t *account_cursor, int sock, uid_t uid)
{
  sec_rgy_name_t pgo_name;
  error_status_t dce_status;
  nss_dced_message_t response;

  TRACE("nss_dced.getpwuid(%d): called for UID %d\n", sock, uid);
  
  sec_rgy_pgo_unix_num_to_name(sec_rgy_default_handle, sec_rgy_domain_person,
                               uid, pgo_name, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
	break;

      case sec_rgy_server_unavailable:
	TRACE("nss_dced.getpwuid(%d): returning NSS_DCED_UNAVAIL\n", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_object_not_found:
      default:
	TRACE("nss_dced.getpwuid(%d): returning NSS_DCED_NOTFOUND\n", sock);
	response = NSS_DCED_NOTFOUND;
	write(sock, &response, sizeof(response));
	return;
    }

  TRACE("nss_dced.getpwuid(%d): calling acct_lookup for username %s\n", sock, pgo_name);
  nss_dced_acct_lookup(account_cursor, sock, pgo_name);
}

void nss_dced_getgrnam(int sock, sec_rgy_name_t pname)
{
  error_status_t dce_status;
  sec_rgy_pgo_item_t pgo_item;
  sec_rgy_cursor_t group_cursor;
  nss_dced_message_t response;
  int string_length;
  gid_t gid;

  TRACE("nss_dced.getgrnam(%d): called for groupname %s\n", sock, pname);
  
  sec_rgy_cursor_reset(&group_cursor);
  sec_rgy_pgo_get_by_name(sec_rgy_default_handle, sec_rgy_domain_group, pname, &group_cursor,
                          &pgo_item, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
	TRACE("nss_dced.getgrnam(%d): returning NSS_DCED_SUCCESS\n", sock);
	response = NSS_DCED_SUCCESS;
	write(sock, &response, sizeof(response));
	break;

      case sec_rgy_server_unavailable:
	TRACE("nss_dced.getgrnam(%d): returning NSS_DCED_UNAVAIL\n", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_no_more_entries:
      case sec_rgy_object_not_found:
      default:
	TRACE("nss_dced.getgrnam(%d): returning NSS_DCED_NOTFOUND\n", sock);
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

  TRACE("nss_dced.getgrgid(%d): called for GID %d\n", sock, gid);
  
  sec_rgy_pgo_unix_num_to_name(sec_rgy_default_handle, sec_rgy_domain_group, gid, 
                               pgo_name, &dce_status);

  switch (dce_status)
    {
      case error_status_ok:
	TRACE("nss_dced.getgrnam(%d): returning NSS_DCED_SUCCESS\n", sock);
	response = NSS_DCED_SUCCESS;
	write(sock, &response, sizeof(response));
	break;

      case sec_rgy_server_unavailable:
	TRACE("nss_dced.getgrgid(%d): returning NSS_DCED_UNAVAILn", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_object_not_found:
      default:
	TRACE("nss_dced.getgrgid(%d): returning NSS_DCED_NOTFOUND\n", sock);
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
	TRACE("nss_dced.getgrent(%d): returning NSS_DCED_SUCCESS\n", sock);
	response = NSS_DCED_SUCCESS;
	write(sock, &response, sizeof(response));
	break;

      case sec_rgy_server_unavailable:
	TRACE("nss_dced.getgrent(%d): returning NSS_DCED_UNAVAIL\n", sock);
	response = NSS_DCED_UNAVAIL;
	write(sock, &response, sizeof(response));
	return;

      case sec_rgy_no_more_entries:
      default:
	TRACE("nss_dced.getgrent(%d): returning NSS_DCED_NOTFOUND\n", sock);
	response = NSS_DCED_NOTFOUND;
	write(sock, &response, sizeof(response));
	return;
    }

  string_length = strlen(pgo_name)+1;
  write(sock, &string_length, sizeof(string_length));
  write(sock, pgo_name, string_length);

  gid = pgo_item.unix_num;
  write(sock, &gid, sizeof(gid));
}
