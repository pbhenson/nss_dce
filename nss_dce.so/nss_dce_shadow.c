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
#include <shadow.h>
#include <dce/rgynbase.h>
#include "nss_dced_protocol.h"
#include "nss_dce_common.h"
#include "nss_dce_shadow.h"


nss_status_t _nss_dce_getspnam(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  int string_length;
  
  TRACE("nss_dce_shadow.getspnam: called for username %s\n", lookup_data->key.name);

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_shadow.getspnam: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  if ((string_length = strlen(lookup_data->key.name)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_shadow.getspnam: name too long, returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }
  
  _nss_dce_request(backend, NSS_DCED_GETSPNAM);
  _nss_dce_sock_write_string(backend, lookup_data->key.name, string_length);
  
  return _nss_dce_read_response(backend, data, _nss_dce_shadow_entry_reader);
}

nss_status_t _nss_dce_setspent(dce_backend_ptr_t backend, void *data)
{
  nss_dced_message_t request;

  TRACE("nss_dce_shadow.setspent: called\n");

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_shadow.setspent: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  _nss_dce_request(backend, NSS_DCED_SETSPENT);

  return _nss_dce_read_response(backend, data, _nss_dce_null_entry_reader);
}

nss_status_t _nss_dce_getspent(dce_backend_ptr_t backend, void *data)
{
  TRACE("nss_dce_shadow.getspent: called\n");

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_shadow.getspent: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  _nss_dce_request(backend, NSS_DCED_GETSPENT);
  
  return _nss_dce_read_response(backend, data, _nss_dce_shadow_entry_reader);
}

nss_status_t _nss_dce_endspent(dce_backend_ptr_t backend, void *data)
{
  TRACE("nss_dce_shadow.endspent: returning NSS_SUCCESS\n");
  
  return NSS_SUCCESS;
}

static dce_backend_op_t shadow_ops[] = {
	_nss_dce_destr,
	_nss_dce_endspent,
	_nss_dce_setspent,
	_nss_dce_getspent,
	_nss_dce_getspnam
};

nss_backend_t *_nss_dce_shadow_constr(const char *db_name, const char *src_name, const char *cfg_args)
{
  dce_backend_ptr_t backend;

  TRACE("nss_dce_shadow.shadow_constr: called\n");
  
  if (!(backend = (dce_backend_ptr_t) malloc(sizeof(*backend))))
    return (0);

  backend->ops = shadow_ops;
  backend->n_ops = (sizeof (shadow_ops) / sizeof(shadow_ops[0]));
  backend->sock = 0;
  
  if (_nss_dce_bind_sock(backend) == NSS_UNAVAIL)
    {
      free(backend);
      return 0;
    }
  
  TRACE("nss_dce_shadow.shadow_constr: returning pointer to backend instance\n");
  return ((nss_backend_t *)backend);
}

nss_status_t _nss_dce_shadow_entry_reader(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  struct spwd *spwd = (struct spwd *)lookup_data->buf.result;
  char *buffer_start = lookup_data->buf.buffer;
  int *buffer_length = &(lookup_data->buf.buflen);

  TRACE("nss_dce_shadow.shadow_entry_reader: called\n");
  
  _nss_dce_sock_read_string(backend, &(spwd->sp_namp), &buffer_start, buffer_length);
  _nss_dce_sock_read_string(backend, &(spwd->sp_pwdp), &buffer_start, buffer_length);
  _nss_dce_sock_read(backend, &(spwd->sp_lstchg), sizeof(spwd->sp_lstchg));
  _nss_dce_sock_read(backend, &(spwd->sp_min), sizeof(spwd->sp_min));
  _nss_dce_sock_read(backend, &(spwd->sp_max), sizeof(spwd->sp_max));
  _nss_dce_sock_read(backend, &(spwd->sp_warn), sizeof(spwd->sp_warn));
  _nss_dce_sock_read(backend, &(spwd->sp_inact), sizeof(spwd->sp_inact));
  _nss_dce_sock_read(backend, &(spwd->sp_expire), sizeof(spwd->sp_expire));
  _nss_dce_sock_read(backend, &(spwd->sp_flag), sizeof(spwd->sp_flag));
	    

  if (*buffer_length >= 0)
     lookup_data->returnval = spwd;
  else
    {
      lookup_data->erange = 1;
      lookup_data->returnval = NULL;
    }

  return NSS_SUCCESS;
}
