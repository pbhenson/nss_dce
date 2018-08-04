/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997-2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <nss_dbdefs.h>
#include "nss_dced_protocol.h"
#include "nss_dce_common.h"

int _nss_dce_bind_sock(dce_backend_ptr_t backend)
{
  struct sockaddr_un name;

  TRACE("nss_dce_common.bind_sock: called\n");
  
  if (backend->sock)
    close(backend->sock);
  
  backend->pid = getpid();
  
  if ((backend->sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)) < 0)
    {
      TRACE("nss_dce_common.bind_sock: socket failed (%d), returning NSS_UNAVAIL\n", errno);
      return NSS_UNAVAIL;
    }
    
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, NSS_DCED_SOCKETPATH);
  
  if (connect(backend->sock, (struct sockaddr *)&name, sizeof(struct sockaddr_un)))
    {
      TRACE("nss_dce_common.bind_sock: connect failed (%d), returning NSS_UNAVAIL\n", errno);
      close(backend->sock);
      backend->sock = -1;
      return NSS_UNAVAIL;
    }

  TRACE("nss_dce_common.bind_sock: established connection, returning NSS_TRYAGAIN\n");
  return NSS_TRYAGAIN;
}

int __nss_dce_sock_read(dce_backend_ptr_t backend, const void *buf, size_t nbytes)
{
  if (read(backend->sock, buf, nbytes) != nbytes)
    return _nss_dce_bind_sock(backend);
  else
    return SOCKIO_OK;
}

int __nss_dce_sock_write(dce_backend_ptr_t backend, const void *buf, size_t nbytes)
{
  void *pipe_orig = signal(SIGPIPE, SIG_IGN);
  int wbytes = write(backend->sock, buf, nbytes);
  
  signal(SIGPIPE, pipe_orig);
  return ((wbytes == nbytes) ? SOCKIO_OK : _nss_dce_bind_sock(backend));
}

int __nss_dce_sock_read_string(dce_backend_ptr_t backend, char **buffer, char **buffer_start, int *buffer_length)
{
  int string_length;

  TRACE("nss_dce_common.sock_read_string: called\n");

  _nss_dce_sock_read(backend, &string_length, sizeof(string_length));

  if (string_length <= *buffer_length)
    {
      *buffer = *buffer_start;
      _nss_dce_sock_read(backend, *buffer, string_length);
      *buffer_length -= string_length;
      *buffer_start += string_length;
    }
  else
    {
      char disposal[1024];

      while (string_length > 0)
	{
	  int bytes_to_read = (string_length > 1024) ? 1024 : string_length;
	  _nss_dce_sock_read(backend, disposal, bytes_to_read);
	  string_length -= bytes_to_read;
	}
      
      *buffer_length = -1;
    }

  return SOCKIO_OK;
}

nss_status_t _nss_dce_destr(dce_backend_ptr_t backend, void *dummy)
{
  TRACE("nss_dce_common.destr: called\n");
  
  close(backend->sock);
  free(backend);

  TRACE("nss_dce_common.destr: returning NSS_SUCCESS\n");
  return NSS_SUCCESS;
}

nss_status_t _nss_dce_read_response(dce_backend_ptr_t backend, void *data, nss_dce_entry_reader_t entry_reader)
{
  nss_dced_message_t response;

  TRACE("nss_dce_common.read_response: called\n");
  
  _nss_dce_sock_read(backend, &response, sizeof(response));

  switch(response)
    {
      case NSS_DCED_SUCCESS:
        return entry_reader(backend, data);
        
      case NSS_DCED_UNAVAIL:
        TRACE("nss_dce_common.read_response: returning NSS_UNAVAIL\n");
        return NSS_UNAVAIL;
      
      case NSS_DCED_NOTFOUND:
        TRACE("nss_dce_common.read_response: returning NSS_NOTFOUND\n");
        return NSS_NOTFOUND;

      default:
        TRACE("nss_dce_common.read_response: unknown result code received (%d), returning NSS_NOTFOUND\n", response);
        return NSS_NOTFOUND;
    }
}

nss_status_t _nss_dce_null_entry_reader(dce_backend_ptr_t backend, void *data)
{
  return NSS_SUCCESS;
}
