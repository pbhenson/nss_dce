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
#include <grp.h>
#include <dce/rgynbase.h>
#include "nss_dced_protocol.h"
#include "nss_dce_common.h"
#include "nss_dce_group.h"


enum nss_status _nss_dce_getgrnam_r(const char *name, struct group *grp, char *buffer, size_t buflen, int *errnop)
{
  nss_XbyY_buf_t lookup_data = {(void *)grp, buffer, buflen};
  int string_length;
  enum nss_status status;

  TRACE("nss_dce_group.getgrnam: called for groupname %s\n", name);
  
  if ((string_length = strlen(name)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_group.getgrnam: name too long, returning NSS_STATUS_NOTFOUND\n");
      *errnop = errno = ENOENT;
      return NSS_STATUS_NOTFOUND;
    }
  
  if ((status = _nss_dce_request(NSS_DCED_GETGRNAM)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }

  if ((status = _nss_dce_sock_write_string(name, string_length)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }

  status = _nss_dce_read_response(&lookup_data, _nss_dce_gr_entry_reader);
  *errnop = errno;
  return status;
}

enum nss_status _nss_dce_getgrgid_r(gid_t gid, struct group *grp, char *buffer, size_t buflen, int *errnop)
{
  nss_XbyY_buf_t lookup_data = {(void *)grp, buffer, buflen};
  enum nss_status status;

  TRACE("nss_dce_group.getgrgid: called for GID %d\n", gid);

  if ((status = _nss_dce_request(NSS_DCED_GETGRGID)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
  
  if ((status = _nss_dce_sock_write(&gid, sizeof(gid))) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
  
  status = _nss_dce_read_response(&lookup_data, _nss_dce_gr_entry_reader);
  *errnop = errno;
  return status;
}

enum nss_status _nss_dce_setgrent()
{
  enum nss_status status;

  TRACE("nss_dce_group.setgrent: called\n");
  
  if ((status = _nss_dce_request(NSS_DCED_SETGRENT)) != NSS_STATUS_SUCCESS)
    return status;
  
  return _nss_dce_read_response(NULL, _nss_dce_null_entry_reader);
}

enum nss_status _nss_dce_getgrent_r(struct group *grp, char *buffer, size_t buflen, int *errnop)
{
  nss_XbyY_buf_t lookup_data = {(void *)grp, buffer, buflen};
  enum nss_status status;
  
  TRACE("nss_dce_group.getgrent: called\n");
  
  if ((status = _nss_dce_request(NSS_DCED_GETGRENT)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }
  
  status = _nss_dce_read_response(&lookup_data, _nss_dce_gr_entry_reader);
  *errnop = errno;
  return status;
}

enum nss_status _nss_dce_endgrent()
{
  TRACE("nss_dce_group.endgrent: returning NSS_STATUS_SUCCESS\n");

  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_dce_initgroups_dyn(char *user, gid_t group, long int *start, long int *size, gid_t **groups, long int limit, int *errnop)
{
  nss_dce_initgroups_buf_t lookup_data = {group, start, size, groups, limit};
  enum nss_status status;
  int string_length;
  
  if ((string_length = strlen(user)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_group.initgroups_dyn: name too long, returning NSS_STATUS_NOTFOUND\n");
      *errnop = errno = ENOENT;
      return NSS_STATUS_NOTFOUND;
    }

  if ((status = _nss_dce_request(NSS_DCED_GETGROUPSBYMEMBER)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }

  if ((status = _nss_dce_sock_write_string(user, string_length)) != NSS_STATUS_SUCCESS)
    {
      *errnop = errno;
      return status;
    }

  status = _nss_dce_read_response(&lookup_data, _nss_dce_initgroups_entry_reader);
  *errnop = errno;
  return status;
}

static enum nss_status _nss_dce_gr_entry_reader(void *data)
{
  nss_XbyY_buf_t *lookup_data = (nss_XbyY_buf_t *)data;
  struct group *grp = (struct group *)lookup_data->result;
  char *buffer_start = lookup_data->buffer;
  int *buffer_length = &(lookup_data->buflen);
  int align_adjust;
  enum nss_status status;

  TRACE("nss_dce_group.gr_entry_reader: called\n");

  if ((status = _nss_dce_sock_read_string(&(grp->gr_name), &buffer_start, buffer_length)) != NSS_STATUS_SUCCESS) return status;
  grp->gr_passwd = buffer_start - 1;
  if ((status = _nss_dce_sock_read(&(grp->gr_gid), sizeof(grp->gr_gid))) != NSS_STATUS_SUCCESS) return status;

  align_adjust = (int)buffer_start % sizeof(char *);
  if (align_adjust > 0) align_adjust = sizeof(char *) - align_adjust;
  
  grp->gr_mem = (char **)((int)buffer_start + align_adjust);
  
  *buffer_length -= (char *)(grp->gr_mem) - buffer_start;
  buffer_start = (char *)(grp->gr_mem + 1);
  *buffer_length -= sizeof(grp->gr_mem);

  if (*buffer_length < 0)
    {
      errno = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }
  
  grp->gr_mem[0] = NULL;

  return NSS_STATUS_SUCCESS;
}

static enum nss_status _nss_dce_initgroups_entry_reader(void *data)
{
  nss_dce_initgroups_buf_t *lookup_data = (nss_dce_initgroups_buf_t *)data;
  gid_t group = lookup_data->group;
  long int *start = lookup_data->start;
  long int *size = lookup_data->size;
  gid_t **groups = lookup_data->groups;
  long int limit = lookup_data->limit;
  int return_count;
  gid_t gid;
  enum nss_status status;

  TRACE("nss_dce_group.initgroups_entry_reader: called\n");

  if ((status = _nss_dce_sock_read(&return_count, sizeof(return_count))) != NSS_STATUS_SUCCESS) return status;

  TRACE("nss_dce_group.initgroups_entry_reader: return_count=%d\n", return_count);

  while (return_count > 0)
    {
      if ((status = _nss_dce_sock_read(&gid, sizeof(gid))) != NSS_STATUS_SUCCESS) return status;

      return_count--;

      if (gid == group) continue;

      if (*start == *size) {
	gid_t *newgroups;
	long int newsize;

	if (limit > 0 && *size == limit) continue;

	newsize = 2 * *size;
	if (limit > 0 && newsize > limit) newsize = limit;

	TRACE("nss_dce_group.initgroups_entry_reader: attempting realloc to %d\n", newsize);
	
	newgroups = realloc(*groups, newsize * sizeof(**groups));

	if (newgroups == NULL) continue;
	
	*groups = newgroups;
	*size = newsize;
      }

      (*groups)[*start] = gid;
      (*start)++;
    }
  
  return NSS_STATUS_SUCCESS;
}

