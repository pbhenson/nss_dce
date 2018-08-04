/* 
 * DCE Naming Services for Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#include <stdio.h>
#include <nss.h>
#include <pwd.h>
#include <errno.h>
#include <dce/rgynbase.h>
#include "nss_dced_protocol.h"
#include "nss_dce_common.h"
#include "nss_dce_passwd.h"


enum nss_status _nss_dce_getpwnam_r(const char *name, struct passwd *pwd, char *buffer, size_t buflen, int *errnop)
{
  nss_XbyY_buf_t lookup_data = {(void *)pwd, buffer, buflen};
  int string_length;
  enum nss_status status;
  
  TRACE("nss_dce_passwd.getpwnam: called for username %s\n", name);

  if ((string_length = strlen(name)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_passwd.getpwnam: name too long, returning NSS_STATUS_NOTFOUND\n");
      *errnop = errno = ENOENT;
      return NSS_STATUS_NOTFOUND;
    }
  
  if ((status =_nss_dce_request(NSS_DCED_GETPWNAM)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
    
  if ((status = _nss_dce_sock_write_string(name, string_length)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
  
  status = _nss_dce_read_response(&lookup_data, _nss_dce_pw_entry_reader);
  *errnop = errno;
  return status;
}

enum nss_status _nss_dce_getpwuid_r(uid_t uid, struct passwd *pwd, char *buffer, size_t buflen, int *errnop)
{
  nss_XbyY_buf_t lookup_data = {(void *)pwd, buffer, buflen};
  enum nss_status status;
  
  TRACE("nss_dce_passwd.getpwuid: called for UID %d\n", uid);

  if ((status = _nss_dce_request(NSS_DCED_GETPWUID)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }

  if ((status = _nss_dce_sock_write((void *)&uid, sizeof(uid))) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }

  status = _nss_dce_read_response(&lookup_data, _nss_dce_pw_entry_reader);
  *errnop = errno;
  return status;
}

enum nss_status _nss_dce_setpwent()
{
  enum nss_status status;

  TRACE("nss_dce_passwd.setpwent: called\n");
  
  if ((status = _nss_dce_request(NSS_DCED_SETPWENT)) != NSS_STATUS_SUCCESS)
      return status;

  return _nss_dce_read_response(NULL, _nss_dce_null_entry_reader);
}

enum nss_status _nss_dce_getpwent_r(struct passwd *pwd, char *buffer, size_t buflen, int *errnop)
{
  nss_XbyY_buf_t lookup_data = {(void *)pwd, buffer, buflen};
  enum nss_status status;
  
  TRACE("nss_dce_passwd.getpwent: called\n");
  
  if ((status =_nss_dce_request(NSS_DCED_GETPWENT)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
  
  status = _nss_dce_read_response(&lookup_data, _nss_dce_pw_entry_reader);
  *errnop = errno;
  return status;
}

enum nss_status _nss_dce_endpwent()
{
  TRACE("nss_dce_passwd.endpwent: returning NSS_STATUS_SUCCESS\n");
  
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_dce_pw_entry_reader(void *data)
{
  nss_XbyY_buf_t *lookup_data = (nss_XbyY_buf_t *)data;
  struct passwd *pwd = (struct passwd *)lookup_data->result;
  char *buffer_start = lookup_data->buffer;
  int *buffer_length = &(lookup_data->buflen);
  enum nss_status status;

  TRACE("nss_dce_passwd.pw_entry_reader: called\n");
  
  if ((status = _nss_dce_sock_read_string(&(pwd->pw_name), &buffer_start, buffer_length)) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read_string(&(pwd->pw_passwd), &buffer_start, buffer_length)) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(pwd->pw_uid), sizeof(pwd->pw_uid))) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read(&(pwd->pw_gid), sizeof(pwd->pw_gid))) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read_string(&(pwd->pw_gecos), &buffer_start, buffer_length)) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read_string(&(pwd->pw_dir), &buffer_start, buffer_length)) != NSS_STATUS_SUCCESS) return status;
  if ((status = _nss_dce_sock_read_string(&(pwd->pw_shell), &buffer_start, buffer_length)) != NSS_STATUS_SUCCESS) return status;

  if (*buffer_length < 0)
    {
      errno = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }

  return NSS_STATUS_SUCCESS;
}
