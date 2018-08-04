/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
 *
 */

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <nss_dbdefs.h>
#include <pwd.h>
#include <dce/rgynbase.h>
#include "nss_dced_protocol.h"

#ifdef DEBUG
#define TRACE(X...) fprintf(stderr, X)
#else
#define TRACE(X...)
#endif

#define SOCKIO_OK (-1)

#define sock_read(X, Y, Z) { int ret_val = _sock_read(X, Y, Z); \
                             if (ret_val != SOCKIO_OK) return ret_val; }

#define sock_write(X, Y, Z) { int ret_val = _sock_write(X, Y, Z); \
                              if (ret_val != SOCKIO_OK) return ret_val; }

typedef	struct dce_backend *dce_backend_ptr_t;
typedef	nss_status_t (*dce_backend_op_t)(dce_backend_ptr_t, void *);

struct dce_backend
{
  dce_backend_op_t *ops;
  nss_dbop_t n_ops;

  int sock;
  struct passwd pwd;
};

static int bind_sock(dce_backend_ptr_t backend)
{
  struct sockaddr_un name;

  TRACE("nss_dce_passwd.bind_sock: entered\n");

  if (backend->sock)
    close(backend->sock);
  
  if ((backend->sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)) < 0)
    {
      TRACE("nss_dce_passwd.bind_sock: socket failed, returning NSS_UNAVAIL\n");
      return NSS_UNAVAIL;
    }

  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, NSS_DCED_SOCKETPATH);
  
  if (connect(backend->sock, (struct sockaddr *)&name, sizeof(struct sockaddr_un)))
    {
      TRACE("nss_dce_passwd.bind_sock: connect failed, returning NSS_UNAVAIL\n");
      close(backend->sock);
      return NSS_UNAVAIL;
    }

  TRACE("nss_dce_passwd.bind_sock: established connection, returning NSS_TRYAGAIN\n");
  return NSS_TRYAGAIN;
}

static int _sock_read(dce_backend_ptr_t backend, const void *buf, size_t nbytes)
{
  if (read(backend->sock, buf, nbytes) != nbytes)
    return bind_sock(backend);
  else
    return SOCKIO_OK;
}

static int _sock_write(dce_backend_ptr_t backend, const void *buf, size_t nbytes)
{
  void *pipe_orig = signal(SIGPIPE, SIG_IGN);
  int wbytes = write(backend->sock, buf, nbytes);
  
  signal(SIGPIPE, pipe_orig);
  return ((wbytes == nbytes) ? SOCKIO_OK : bind_sock(backend));
}

nss_status_t _nss_dce_getpwnam(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  nss_dced_message_t request;
  nss_dced_message_t response = NSS_DCED_UNAVAIL;
  int string_length;
  uid_t uid;
  gid_t gid;

  TRACE("nss_dce_passwd.getpwnam: called for username %s\n", lookup_data->key.name);
  
  if ((string_length = strlen(lookup_data->key.name)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_passwd.getpwnam: name too long, returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }
  
  request = NSS_DCED_GETPWNAM;
  sock_write(backend, &request, sizeof(request));
  
  sock_write(backend, &string_length, sizeof(string_length));
  sock_write(backend, lookup_data->key.name, string_length);

  sock_read(backend, &response, sizeof(response));

  switch(response)
    {
    case NSS_DCED_UNAVAIL:
      TRACE("nss_dce_passwd.getpwnam: returning NSS_UNAVAIL\n");
      return NSS_UNAVAIL;
      
    case NSS_DCED_NOTFOUND:
      TRACE("nss_dce_passwd.getpwnam: returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;

    case NSS_DCED_SUCCESS:
      break;
        
    default:
      TRACE("nss_dce_passwd.getpwnam: unknown result code received, returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_name, string_length);

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_passwd, string_length);

  sock_read(backend, &uid, sizeof(uid));
  backend->pwd.pw_uid = uid;
  
  sock_read(backend, &gid, sizeof(gid));
  backend->pwd.pw_gid = gid;
  
  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_gecos, string_length);
  
  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_dir, string_length);

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_shell, string_length);

  *((struct passwd *) lookup_data->buf.result) = backend->pwd;
  lookup_data->returnval = &(backend->pwd);

  TRACE("nss_dce_passwd.getpwnam: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;
}

nss_status_t _nss_dce_getpwuid(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  nss_dced_message_t request;
  nss_dced_message_t response = NSS_DCED_UNAVAIL;
  int string_length;
  uid_t uid;
  gid_t gid;

  TRACE("nss_dce_passwd.getpwuid: called for UID %d\n", lookup_data->key.uid);

  request = NSS_DCED_GETPWUID;
  sock_write(backend, &request, sizeof(request));

  uid = lookup_data->key.uid;
  sock_write(backend, &uid, sizeof(uid));

  sock_read(backend, &response, sizeof(response));

  switch(response)
    {
    case NSS_DCED_UNAVAIL:
      TRACE("nss_dce_passwd.getpwuid: returning NSS_UNAVAIL\n");
      return NSS_UNAVAIL;
      
    case NSS_DCED_NOTFOUND:
      TRACE("nss_dce_passwd.getpwuid: returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;

    case NSS_DCED_SUCCESS:
      break;
        
    default:
      TRACE("nss_dce_passwd.getpwuid: unknown result code received, returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_name, string_length);

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_passwd, string_length);

  sock_read(backend, &uid, sizeof(uid));
  backend->pwd.pw_uid = uid;
  
  sock_read(backend, &gid, sizeof(gid));
  backend->pwd.pw_gid = gid;
  
  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_gecos, string_length);
  
  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_dir, string_length);

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_shell, string_length);

  *((struct passwd *) lookup_data->buf.result) = backend->pwd;
  lookup_data->returnval = &(backend->pwd);

  TRACE("nss_dce_passwd.getpwuid: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;
}

nss_status_t _nss_dce_setpwent(dce_backend_ptr_t backend, void *data)
{
  nss_dced_message_t request;
  nss_dced_message_t response = NSS_DCED_UNAVAIL;

  TRACE("nss_dce_passwd.setpwent: called\n");
    
  request = NSS_DCED_SETPWENT;
  sock_write(backend, &request, sizeof(request));

  sock_read(backend, &response, sizeof(response));

  switch(response)
    {
    case NSS_DCED_UNAVAIL:
      TRACE("nss_dce_passwd.setpwent: returning NSS_UNAVAIL\n");
      return NSS_UNAVAIL;
        
    default:
      TRACE("nss_dce_passwd.setpwent: returning NSS_SUCCESS\n");
      return NSS_SUCCESS;
    }
}

nss_status_t _nss_dce_getpwent(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *) data;
  nss_dced_message_t request;
  nss_dced_message_t response = NSS_DCED_UNAVAIL;
  int string_length;
  uid_t uid;
  gid_t gid;

  TRACE("nss_dce_passwd.getpwent: called\n");
  
  request = NSS_DCED_GETPWENT;
  sock_write(backend, &request, sizeof(request));

  sock_read(backend, &response, sizeof(response));

  switch(response)
    {
    case NSS_DCED_UNAVAIL:
      TRACE("nss_dce_passwd.getpwent: returning NSS_UNAVAIL\n");
      *((struct passwd *) lookup_data->buf.result) = backend->pwd;
      lookup_data->returnval = NULL;
      return NSS_UNAVAIL;
      
    case NSS_DCED_SUCCESS:
      break;
        
    default:
      TRACE("nss_dce_passwd.getpwent: returning NSS_NOTFOUND\n");
      *((struct passwd *) lookup_data->buf.result) = backend->pwd;
      lookup_data->returnval = NULL;
      return NSS_NOTFOUND;
    }

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_name, string_length);

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_passwd, string_length);

  sock_read(backend, &uid, sizeof(uid));
  backend->pwd.pw_uid = uid;
  
  sock_read(backend, &gid, sizeof(gid));
  backend->pwd.pw_gid = gid;
  
  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_gecos, string_length);
  
  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_dir, string_length);

  sock_read(backend, &string_length, sizeof(string_length));
  sock_read(backend, backend->pwd.pw_shell, string_length);

  *((struct passwd *) lookup_data->buf.result) = backend->pwd;
  lookup_data->returnval = &(backend->pwd);

  TRACE("nss_dce_passwd.getpwent: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;
}


nss_status_t _nss_dce_endpwent(dce_backend_ptr_t backend, void *dummy)
{
  TRACE("nss_dce_passwd.endpwent: returning NSS_SUCCESS\n");
  
  return NSS_SUCCESS;
}

nss_status_t _nss_dce_passwd_destr(dce_backend_ptr_t backend, void *dummy)
{
  TRACE("nss_dce_passwd.passwd_destr: called\n");
  
  close(backend->sock);

  free(backend->pwd.pw_name);
  free(backend->pwd.pw_passwd);
  free(backend->pwd.pw_age);
  free(backend->pwd.pw_gecos);
  free(backend->pwd.pw_dir);
  free(backend->pwd.pw_shell);
  free(backend);

  TRACE("nss_dce_passwd.passwd_destr: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;
}

static dce_backend_op_t passwd_ops[] = {
	_nss_dce_passwd_destr,
	_nss_dce_endpwent,
	_nss_dce_setpwent,
	_nss_dce_getpwent,
	_nss_dce_getpwnam,
	_nss_dce_getpwuid
};

nss_backend_t *_nss_dce_passwd_constr(const char *dummy1, const char *dummy2,
                                      const char *dummy3)
{
  dce_backend_ptr_t backend;

  TRACE("nss_dce_passwd.passwd_constr: called\n");
  
  if (!(backend = (dce_backend_ptr_t) malloc(sizeof(*backend))))
    return (0);

  backend->ops = passwd_ops;
  backend->n_ops = (sizeof (passwd_ops) / sizeof(passwd_ops[0]));
  backend->sock = 0;
  
  if (bind_sock(backend) == NSS_UNAVAIL)
    return 0;
  
  if (!(backend->pwd.pw_name = (char *)malloc(sec_rgy_name_t_size)))
    return 0;

  if (!(backend->pwd.pw_passwd = (char *)malloc(sec_rgy_max_unix_passwd_len)))
    return 0;

  if (!(backend->pwd.pw_age = (char *)malloc(1)))
    return 0;
  strcpy(backend->pwd.pw_age, "");

  if (!(backend->pwd.pw_gecos = (char *)malloc(sec_rgy_pname_t_size)))
    return 0;
  backend->pwd.pw_comment = backend->pwd.pw_gecos;

  if (!(backend->pwd.pw_dir = (char *)malloc(sec_rgy_pname_t_size)))
    return 0;

  if (!(backend->pwd.pw_shell = (char *)malloc(sec_rgy_pname_t_size)))
    return 0;
  
  TRACE("nss_dce_passwd.passwd_constr: returning pointer to backend instance\n");
  return ((nss_backend_t *) backend);
}


