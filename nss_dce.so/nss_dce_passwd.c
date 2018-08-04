/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997-2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#include <stdio.h>
#include <nss_dbdefs.h>
#include <pwd.h>
#include <dce/rgynbase.h>
#include "nss_dced_protocol.h"
#include "nss_dce_common.h"
#include "nss_dce_passwd.h"


nss_status_t _nss_dce_getpwnam(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  int string_length;
  
  TRACE("nss_dce_passwd.getpwnam: called for username %s\n", lookup_data->key.name);

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_passwd.getpwnam: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  if ((string_length = strlen(lookup_data->key.name)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_passwd.getpwnam: name too long, returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }
  
  _nss_dce_request(backend, NSS_DCED_GETPWNAM);
  _nss_dce_sock_write_string(backend, lookup_data->key.name, string_length);
  
  return _nss_dce_read_response(backend, data, _nss_dce_pw_entry_reader);
}

nss_status_t _nss_dce_getpwuid(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  
  TRACE("nss_dce_passwd.getpwuid: called for UID %d\n", lookup_data->key.uid);

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_passwd.getpwuid: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  _nss_dce_request(backend, NSS_DCED_GETPWUID);
  _nss_dce_sock_write(backend, &lookup_data->key.uid, sizeof(lookup_data->key.uid));

  return _nss_dce_read_response(backend, data, _nss_dce_pw_entry_reader);
}

nss_status_t _nss_dce_setpwent(dce_backend_ptr_t backend, void *data)
{
  nss_dced_message_t request;

  TRACE("nss_dce_passwd.setpwent: called\n");

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_passwd.setpwent: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  _nss_dce_request(backend, NSS_DCED_SETPWENT);

  return _nss_dce_read_response(backend, data, _nss_dce_null_entry_reader);
}

nss_status_t _nss_dce_getpwent(dce_backend_ptr_t backend, void *data)
{
  TRACE("nss_dce_passwd.getpwent: called\n");

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_passwd.getpwent: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  _nss_dce_request(backend, NSS_DCED_GETPWENT);
  
  return _nss_dce_read_response(backend, data, _nss_dce_pw_entry_reader);
}

nss_status_t _nss_dce_endpwent(dce_backend_ptr_t backend, void *data)
{
  TRACE("nss_dce_passwd.endpwent: returning NSS_SUCCESS\n");
  
  return NSS_SUCCESS;
}

static dce_backend_op_t passwd_ops[] = {
	_nss_dce_destr,
	_nss_dce_endpwent,
	_nss_dce_setpwent,
	_nss_dce_getpwent,
	_nss_dce_getpwnam,
	_nss_dce_getpwuid
};

nss_backend_t *_nss_dce_passwd_constr(const char *db_name, const char *src_name, const char *cfg_args)
{
  dce_backend_ptr_t backend;

  TRACE("nss_dce_passwd.passwd_constr: called\n");
  
  if (!(backend = (dce_backend_ptr_t) malloc(sizeof(*backend))))
    return (0);

  backend->ops = passwd_ops;
  backend->n_ops = (sizeof (passwd_ops) / sizeof(passwd_ops[0]));
  backend->sock = 0;
  
  if (_nss_dce_bind_sock(backend) == NSS_UNAVAIL)
    {
      free(backend);
      return 0;
    }
  
  TRACE("nss_dce_passwd.passwd_constr: returning pointer to backend instance\n");
  return ((nss_backend_t *)backend);
}

nss_status_t _nss_dce_pw_entry_reader(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  struct passwd *pwd = (struct passwd *)lookup_data->buf.result;
  char *buffer_start = lookup_data->buf.buffer;
  int *buffer_length = &(lookup_data->buf.buflen);

  TRACE("nss_dce_passwd.pw_entry_reader: called\n");
  
  _nss_dce_sock_read_string(backend, &(pwd->pw_name), &buffer_start, buffer_length);
  _nss_dce_sock_read_string(backend, &(pwd->pw_passwd), &buffer_start, buffer_length);
  _nss_dce_sock_read(backend, &(pwd->pw_uid), sizeof(pwd->pw_uid));
  _nss_dce_sock_read(backend, &(pwd->pw_gid), sizeof(pwd->pw_gid));
  _nss_dce_sock_read_string(backend, &(pwd->pw_gecos), &buffer_start, buffer_length);
  _nss_dce_sock_read_string(backend, &(pwd->pw_dir), &buffer_start, buffer_length);
  _nss_dce_sock_read_string(backend, &(pwd->pw_shell), &buffer_start, buffer_length);
  pwd->pw_age = buffer_start - 1;
  pwd->pw_comment = pwd->pw_gecos;

  if (*buffer_length >= 0)
     lookup_data->returnval = pwd;
  else
    {
      lookup_data->erange = 1;
      lookup_data->returnval = NULL;
    }

  return NSS_SUCCESS;
}
