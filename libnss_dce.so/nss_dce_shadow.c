/* 
 * DCE Naming Services for Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#include <stdio.h>
#include <errno.h>
#include <nss.h>
#include <shadow.h>
#include <dce/rgynbase.h>
#include "nss_dced_protocol.h"
#include "nss_dce_common.h"
#include "nss_dce_shadow.h"


enum nss_status _nss_dce_getspnam_r(const char *name, struct spwd *spwd, char *buffer, size_t buflen, int *errnop)
{
  nss_XbyY_buf_t lookup_data = {(void *)spwd, buffer, buflen};
  int string_length;
  enum nss_status status;
  
  TRACE("nss_dce_shadow.getspnam: called for username %s\n", name);

  if ((string_length = strlen(name)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_shadow.getspnam: name too long, returning NSS_STATUS_NOTFOUND\n");
      *errnop = errno = ENOENT;
      return NSS_STATUS_NOTFOUND;
    }
  
  if ((status = _nss_dce_request(NSS_DCED_GETSPNAM)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
  
  if ((status =_nss_dce_sock_write_string(name, string_length)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
  
  status =_nss_dce_read_response(&lookup_data, _nss_dce_shadow_entry_reader);
  *errnop = errno;
  return status;
}

enum nss_status _nss_dce_setspent()
{
  enum nss_status status;

  TRACE("nss_dce_shadow.setspent: called\n");

  if ((status = _nss_dce_request(NSS_DCED_SETSPENT)) != NSS_STATUS_SUCCESS)
    return status;

  return _nss_dce_read_response(NULL, _nss_dce_null_entry_reader);
}

enum nss_status _nss_dce_getspent_r(struct spwd *spwd, char *buffer, size_t buflen, int *errnop)
{
  nss_XbyY_buf_t lookup_data = {(void *)spwd, buffer, buflen};
  enum nss_status status;
  
  TRACE("nss_dce_shadow.getspent: called\n");
  
  if ((status = _nss_dce_request(NSS_DCED_GETSPENT)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
  
  status = _nss_dce_read_response(&lookup_data, _nss_dce_shadow_entry_reader);
  *errnop = errno;
  return status;
}

enum nss_status _nss_dce_endspent()
{
  TRACE("nss_dce_shadow.endspent: returning NSS_STATUS_SUCCESS\n");
  
  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_dce_shadow_entry_reader(void *data)
{
  nss_XbyY_buf_t *lookup_data = (nss_XbyY_buf_t *)data;
  struct spwd *spwd = (struct spwd *)lookup_data->result;
  char *buffer_start = lookup_data->buffer;
  int *buffer_length = &(lookup_data->buflen);
  enum nss_status status;

  TRACE("nss_dce_shadow.shadow_entry_reader: called\n");
  
  if ((status = _nss_dce_sock_read_string(&(spwd->sp_namp), &buffer_start, buffer_length)) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read_string(&(spwd->sp_pwdp), &buffer_start, buffer_length)) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(spwd->sp_lstchg), sizeof(spwd->sp_lstchg))) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(spwd->sp_min), sizeof(spwd->sp_min))) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(spwd->sp_max), sizeof(spwd->sp_max))) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(spwd->sp_warn), sizeof(spwd->sp_warn))) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(spwd->sp_inact), sizeof(spwd->sp_inact))) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(spwd->sp_expire), sizeof(spwd->sp_expire))) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(spwd->sp_flag), sizeof(spwd->sp_flag))) != NSS_STATUS_SUCCESS) return status;

  if (*buffer_length < 0)
    {
      errno = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }

  return NSS_STATUS_SUCCESS;
}
