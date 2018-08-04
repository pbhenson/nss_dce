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
#include <grp.h>
#include <dce/rgynbase.h>
#include "nss_dced_protocol.h"
#include "nss_dce_common.h"
#include "nss_dce_group.h"


nss_status_t _nss_dce_getgrnam(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  int string_length;

  TRACE("nss_dce_group.getgrnam: called for groupname %s\n", lookup_data->key.name);
  
  if (backend->pid != getpid())
    {
      TRACE("nss_dce_group.getgrnam: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  if ((string_length = strlen(lookup_data->key.name)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_group.getgrnam: name too long, returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }
  
  _nss_dce_request(backend, NSS_DCED_GETGRNAM);
  _nss_dce_sock_write_string(backend, lookup_data->key.name, string_length);

  return _nss_dce_read_response(backend, data, _nss_dce_gr_entry_reader);
}

nss_status_t _nss_dce_getgrgid(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;

  TRACE("nss_dce_group.getgrgid: called for GID %d\n", lookup_data->key.gid);

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_group.getgrgid: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  _nss_dce_request(backend, NSS_DCED_GETGRGID);
  _nss_dce_sock_write(backend, &lookup_data->key.gid, sizeof(lookup_data->key.gid));

  return _nss_dce_read_response(backend, data, _nss_dce_gr_entry_reader);
}

nss_status_t _nss_dce_setgrent(dce_backend_ptr_t backend, void *data)
{
  TRACE("nss_dce_group.setgrent: called\n");

  if (backend->pid != getpid())
    {
      TRACE("nss_dce_group.setgrent: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  _nss_dce_request(backend, NSS_DCED_SETGRENT);

  return _nss_dce_read_response(backend, (nss_XbyY_args_t *)data, _nss_dce_null_entry_reader);
}

nss_status_t _nss_dce_getgrent(dce_backend_ptr_t backend, void *data)
{
  TRACE("nss_dce_group.getgrent: called\n");
    
  if (backend->pid != getpid())
    {
      TRACE("nss_dce_group.getgrent: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  _nss_dce_request(backend, NSS_DCED_GETGRENT);

  return _nss_dce_read_response(backend, data, _nss_dce_gr_entry_reader);
}

nss_status_t _nss_dce_endgrent(dce_backend_ptr_t backend, void *dummy)
{
  TRACE("nss_dce_group.endgrent: returning NSS_SUCCESS\n");

  return NSS_SUCCESS;
}

nss_status_t _nss_dce_getgroupsbymember(dce_backend_ptr_t backend, void *data)
{
  struct nss_groupsbymem *lookup_data = (struct nss_groupsbymem *)data;
  int string_length;
  
  if (backend->pid != getpid())
    {
      TRACE("nss_dce_group.getgroupsbymember: pid change, rebinding\n");
      if (_nss_dce_bind_sock(backend) != NSS_TRYAGAIN)
	return NSS_UNAVAIL;
    }
  
  if ((string_length = strlen(lookup_data->username)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_group.getgroupsbymember: name too long, returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }

  _nss_dce_request(backend, NSS_DCED_GETGROUPSBYMEMBER);
  _nss_dce_sock_write_string(backend, lookup_data->username, string_length);

  return _nss_dce_read_response(backend, data, _nss_dce_grbymem_entry_reader);
}
				     
static dce_backend_op_t group_ops[] = {
  _nss_dce_destr,
  _nss_dce_endgrent,
  _nss_dce_setgrent,
  _nss_dce_getgrent,
  _nss_dce_getgrnam,
  _nss_dce_getgrgid,
  _nss_dce_getgroupsbymember
};

nss_backend_t *_nss_dce_group_constr(const char *db_name, const char *src_name, const char *cfg_args)
{
  dce_backend_ptr_t backend;

  TRACE("nss_dce_group.group_constr: called\n");
  
  if (!(backend = (dce_backend_ptr_t)malloc(sizeof (*backend))))
    return (0);

  backend->ops = group_ops;
  backend->n_ops = (sizeof (group_ops) / sizeof (group_ops[0]));
  backend->sock = 0;

  if (_nss_dce_bind_sock(backend) == NSS_UNAVAIL)
    {
      free(backend);
      return 0;
    }

  TRACE("nss_dce_group.group_constr: returning pointer to backend instance\n");
  return ((nss_backend_t *) backend);
}

nss_status_t _nss_dce_gr_entry_reader(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  struct group *grp = (struct group *)lookup_data->buf.result;
  char *buffer_start = lookup_data->buf.buffer;
  int *buffer_length = &(lookup_data->buf.buflen);

  TRACE("nss_dce_group.gr_entry_reader: called\n");

  _nss_dce_sock_read_string(backend, &(grp->gr_name), &buffer_start, buffer_length);
  grp->gr_passwd = buffer_start - 1;
  _nss_dce_sock_read(backend, &(grp->gr_gid), sizeof(grp->gr_gid));

  grp->gr_mem = (char **)ROUND_UP(buffer_start, sizeof(buffer_start));

  *buffer_length -= (char *)(grp->gr_mem) - buffer_start;
  buffer_start = (char *)(grp->gr_mem + 1);
  *buffer_length -= sizeof(grp->gr_mem);

  if (*buffer_length >= 0)
    {
      grp->gr_mem[0] = NULL;
      lookup_data->returnval = grp;
    }
  else
    {
      lookup_data->erange = 1;
      lookup_data->returnval = NULL;
    }

  return NSS_SUCCESS;
}

nss_status_t _nss_dce_grbymem_entry_reader(dce_backend_ptr_t backend, void *data)
{
  struct nss_groupsbymem *lookup_data = (struct nss_groupsbymem *)data;
  int numgids_orig = lookup_data->numgids;
  int return_count;
  int duplicate_flag;
  int index;
  gid_t gid;
  
  TRACE("nss_dce_group.grbymem_entry_reader: called\n");

  _nss_dce_sock_read(backend, &return_count, sizeof(return_count));

  while (return_count > 0)
    {
      duplicate_flag = 0;

      _nss_dce_sock_read(backend, &gid, sizeof(gid));

      for (index = 0; index < numgids_orig; index++)
        if (gid == lookup_data->gid_array[index])
          duplicate_flag = 1;
        
      if ((!duplicate_flag) && (lookup_data->numgids < lookup_data->maxgids))
        lookup_data->gid_array[lookup_data->numgids++] = gid;
      
      return_count--;
    }

  if (lookup_data->numgids == lookup_data->maxgids)
    return NSS_SUCCESS;
  else
    return NSS_NOTFOUND;
}

