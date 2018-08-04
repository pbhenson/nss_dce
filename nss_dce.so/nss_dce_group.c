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
#include <grp.h>
#include <dce/rgynbase.h>
#include "nss_dced_protocol.h"

#ifdef DEBUG
#define TRACE(X...) fprintf(stderr, X)
#else
#define TRACE(X...)
#endif

#define SOCKIO_OK -1

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
  struct group grp;
};

static int bind_sock(dce_backend_ptr_t backend)
{
  struct sockaddr_un name;

  TRACE("nss_dce_group.bind_sock: entered\n");
  
  if (backend->sock)
    close(backend->sock);
  
  if ((backend->sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)) < 0)
    {
      TRACE("nss_dce_group.bind_sock: socket failed, returning NSS_UNAVAIL\n");
      return NSS_UNAVAIL;
    }
    
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, NSS_DCED_SOCKETPATH);
  
  if (connect(backend->sock, (struct sockaddr *)&name, sizeof(struct sockaddr_un)))
    {
      TRACE("nss_dce_group.bind_sock: connect failed, returning NSS_UNAVAIL\n");
      close(backend->sock);
      return NSS_UNAVAIL;
    }

  TRACE("nss_dce_group.bind_sock: established connection, returning NSS_TRYAGAIN\n");
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

nss_status_t _nss_dce_getgrnam(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *) data;
  int request;
  int response = NSS_DCED_UNAVAIL;
  int string_length;
  gid_t gid;

  TRACE("nss_dce_group.getgrnam: called for groupname %s\n", lookup_data->key.name);
  
  if ((string_length = strlen(lookup_data->key.name)+1) > sec_rgy_name_t_size)
    {
      TRACE("nss_dce_group.getgrnam: name too long, returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }
  
  request = NSS_DCED_GETGRNAM;
  sock_write(backend, &request, sizeof(int));
  
  sock_write(backend, &string_length, sizeof(int));
  sock_write(backend, lookup_data->key.name, string_length);

  sock_read(backend, &response, sizeof(int));

  switch(response)
    {
    case NSS_DCED_UNAVAIL:
      TRACE("nss_dce_group.getgrnam: returning NSS_UNAVAIL\n");
      return NSS_UNAVAIL;
      
    case NSS_DCED_NOTFOUND:
      TRACE("nss_dce_group.getgrnam: returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;

    case NSS_DCED_SUCCESS:
      break;
        
    default:
      TRACE("nss_dce_group.getgrnam: returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }

  sock_read(backend, &string_length, sizeof(int));
  sock_read(backend, backend->grp.gr_name, string_length);

  sock_read(backend, &gid, sizeof(gid_t));
  backend->grp.gr_gid = gid;

  *((struct group *) lookup_data->buf.result) = backend->grp;
  lookup_data->returnval = &(backend->grp);

  TRACE("nss_dce_group.getgrnam: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;
}

nss_status_t _nss_dce_getgrgid(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *)data;
  int request;
  int response = NSS_DCED_UNAVAIL;
  int string_length;
  gid_t gid;

  TRACE("nss_dce_group.getgrgid: called for GID %d\n", lookup_data->key.gid);

  request = NSS_DCED_GETGRGID;
  sock_write(backend, &request, sizeof(int));

  gid = lookup_data->key.gid;
  sock_write(backend, &gid, sizeof(gid_t));

  sock_read(backend, &response, sizeof(int));

  switch(response)
    {
    case NSS_DCED_UNAVAIL:
      TRACE("nss_dce_group.getgrgid: returning NSS_UNAVAIL\n");
      return NSS_UNAVAIL;
      
    case NSS_DCED_NOTFOUND:
      TRACE("nss_dce_group.getgrgid: returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;

    case NSS_DCED_SUCCESS:
      break;
        
    default:
      TRACE("nss_dce_group.getgrgid: returning NSS_NOTFOUND\n");
      return NSS_NOTFOUND;
    }

  sock_read(backend, &string_length, sizeof(int));
  sock_read(backend, backend->grp.gr_name, string_length);

  sock_read(backend, &gid, sizeof(gid_t));
  backend->grp.gr_gid = gid;

  *((struct group *) lookup_data->buf.result) = backend->grp;
  lookup_data->returnval = &(backend->grp);

  TRACE("nss_dce_group.getgrgid: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;  
}

nss_status_t _nss_dce_setgrent(dce_backend_ptr_t backend, void *dummy)
{
  int request;
  int response = NSS_DCED_UNAVAIL;

  TRACE("nss_dce_group.setgrent: called\n");
    
  request = NSS_DCED_SETGRENT;
  sock_write(backend, &request, sizeof(int));

  sock_read(backend, &response, sizeof(int));

  switch(response)
    {
    case NSS_DCED_UNAVAIL:
      TRACE("nss_dce_group.setgrent: returned NSS_UNAVAIL\n");
      return NSS_UNAVAIL;
        
    default:
      TRACE("nss_dce_group.setgrent: returned NSS_SUCCESS\n");
      return NSS_SUCCESS;
    }
}

nss_status_t _nss_dce_getgrent(dce_backend_ptr_t backend, void *data)
{
  nss_XbyY_args_t *lookup_data = (nss_XbyY_args_t *) data;
  int request;
  int response = NSS_DCED_UNAVAIL;
  int string_length;
  gid_t gid;

  TRACE("nss_dce_group.getgrent: called\n");
    
  request = NSS_DCED_GETGRENT;
  sock_write(backend, &request, sizeof(int));

  sock_read(backend, &response, sizeof(int));

  switch(response)
    {
    case NSS_DCED_UNAVAIL:
      TRACE("nss_dce_group.getgrent: returning NSS_UNAVAIL\n");
      *((struct group *) lookup_data->buf.result) = backend->grp;
      lookup_data->returnval = NULL;
      return NSS_UNAVAIL;
      
    case NSS_DCED_SUCCESS:
      break;
        
    default:
      TRACE("nss_dce_group.getgrent: returning NSS_NOTFOUND\n");
      *((struct group *) lookup_data->buf.result) = backend->grp;
      lookup_data->returnval = NULL;
      return NSS_NOTFOUND;
    }

  sock_read(backend, &string_length, sizeof(int));
  sock_read(backend, backend->grp.gr_name, string_length);

  sock_read(backend, &gid, sizeof(gid_t));
  backend->grp.gr_gid = gid;

  *((struct group *) lookup_data->buf.result) = backend->grp;
  lookup_data->returnval = &(backend->grp);

  TRACE("nss_dce_group.getgrent: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;
}


nss_status_t _nss_dce_endgrent(dce_backend_ptr_t backend, void *dummy)
{
  TRACE("nss_dce_group.endgrent: returning NSS_SUCCESS\n");

  return NSS_SUCCESS;
}

nss_status_t _nss_dce_group_destr(dce_backend_ptr_t backend, void *dummy)
{
  TRACE("nss_dce_group.group_destr: called\n");
    
  close(backend->sock);

  free(backend->grp.gr_name);
  free(backend->grp.gr_passwd);
  free(backend->grp.gr_mem);
  free(backend);

  TRACE("nss_dce_group.group_destr: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;
}

static dce_backend_op_t group_ops[] = {
	_nss_dce_group_destr,
	_nss_dce_endgrent,
	_nss_dce_setgrent,
	_nss_dce_getgrent,
	_nss_dce_getgrnam,
	_nss_dce_getgrgid
};

nss_backend_t *_nss_dce_group_constr(const char *dummy1, const char *dummy2,
                                     const char *dummy3)
{
  dce_backend_ptr_t backend;
  struct sockaddr_un name;

  TRACE("nss_dce_group.group_constr: called\n");
  
  if (!(backend = (dce_backend_ptr_t)malloc(sizeof (*backend))))
    return (0);

  backend->ops = group_ops;
  backend->n_ops = (sizeof (group_ops) / sizeof (group_ops[0]));
  backend->sock = 0;

  if (bind_sock(backend) == NSS_UNAVAIL)
    return 0;

  if (!(backend->grp.gr_name = (char *)malloc(sec_rgy_name_t_size)))
    return 0;
  if (!(backend->grp.gr_passwd = (char *)malloc(1)))
    return 0;
  backend->grp.gr_passwd[0] = '\0';
  if (!(backend->grp.gr_mem = (char **)malloc(sizeof(char **))))
    return 0;
  backend->grp.gr_mem[0] = NULL;

  TRACE("nss_dce_group.group_constr: returning pointer to backend instance\n");
  return ((nss_backend_t *) backend);
}


