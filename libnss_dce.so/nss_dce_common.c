/* 
 * DCE Naming Services for Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <nss.h>
#include "nss_dced_protocol.h"
#include "nss_dce_common.h"

static int sock = -1;
static pid_t pid = 0;

static enum nss_status _nss_dce_init_sock()
{
  struct sockaddr_un name;

  TRACE("nss_dce_common.init_sock: called\n");

  if (sock >= 0)
    {
      TRACE("nss_dce_common.init_sock: existing socket\n");
      
      if (pid == getpid())
	{
	  TRACE("nss_dce_common.init_sock: pid not changed, returning NSS_STATUS_TRYAGAIN\n");
	  
	  errno = EAGAIN;
	  return NSS_STATUS_TRYAGAIN;
	}
      else
	{
	  TRACE("nss_dce_common.init_sock: pid changed, closing socket\n");
	  
	  close(sock);
	}
    }
  
  pid = getpid();
  
  if ((sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC)) < 0)
    {
      TRACE("nss_dce_common.init_sock: socket failed (%d), returning NSS_STATUS_UNAVAIL\n", errno);
      errno = ENOENT;
      return NSS_STATUS_UNAVAIL;
    }
    
  name.sun_family = AF_UNIX;
  strcpy(name.sun_path, NSS_DCED_SOCKETPATH);
  
  if (connect(sock, (struct sockaddr *)&name, sizeof(struct sockaddr_un)))
    {
      TRACE("nss_dce_common.init_sock: connect failed (%d), returning NSS_STATUS_UNAVAIL\n", errno);
      close(sock);
      sock = -1;
      errno = ENOENT;
      return NSS_STATUS_UNAVAIL;
    }

  TRACE("nss_dce_common.init_sock: established connection, returning NSS_STATUS_TRYAGAIN\n");
  errno = EAGAIN;
  return NSS_STATUS_TRYAGAIN;
}

enum nss_status _nss_dce_sock_read(const void *buf, size_t nbytes)
{
  int rbytes;
  
  TRACE("nss_dce_common.sock_read: called, nbytes=%d\n", nbytes);
  
  if ((rbytes = read(sock, buf, nbytes)) == nbytes)
      return NSS_STATUS_SUCCESS;

  TRACE("nss_dce_common.sock_read: partial read %d bytes, errno=%d; closing socket\n", rbytes, errno);
  
  close(sock);
  sock = -1;
  return _nss_dce_init_sock();
}

enum nss_status _nss_dce_sock_write(const void *buf, size_t nbytes)
{
  void *pipe_orig = signal(SIGPIPE, SIG_IGN);
  int wbytes = write(sock, buf, nbytes);

  signal(SIGPIPE, pipe_orig);

  if (wbytes == nbytes)
    return NSS_STATUS_SUCCESS;

  TRACE("nss_dce_common.sock_write: partial write %d bytes, errno=%d; closing socket\n", wbytes, errno);

  close(sock);
  sock = -1;
  return _nss_dce_init_sock();
}

enum nss_status _nss_dce_sock_read_string(char **buffer, char **buffer_start, int *buffer_length)
{
  enum nss_status status;
  int string_length;

  TRACE("nss_dce_common.sock_read_string: called\n");

  if ((status = _nss_dce_sock_read(&string_length, sizeof(string_length))) != NSS_STATUS_SUCCESS)
    return status;

  if (string_length <= *buffer_length)
    {
      *buffer = *buffer_start;

      if ((status = _nss_dce_sock_read(*buffer, string_length)) != NSS_STATUS_SUCCESS)
	return status;

      *buffer_length -= string_length;
      *buffer_start += string_length;
    }
  else
    {
      char disposal[1024];

      TRACE("nss_dce_common.sock_read_string: length exceeds buffer size, discarding\n");
      
      while (string_length > 0)
	{
	  int bytes_to_read = (string_length > 1024) ? 1024 : string_length;

	  if ((status = _nss_dce_sock_read(disposal, bytes_to_read)) != NSS_STATUS_SUCCESS)
	    return status;

	  string_length -= bytes_to_read;
	}
      
      *buffer_length = -1;
    }

  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_dce_sock_write_string(const char *buffer, int buffer_length)
{
  enum nss_status status;
  
  TRACE("nss_dce_common.sock_write_string: called, length=%d, string=%s\n", buffer_length, buffer);

  if ((status = _nss_dce_sock_write(&buffer_length, sizeof(buffer_length))) != NSS_STATUS_SUCCESS)
    return status;
  
  return _nss_dce_sock_write(buffer, buffer_length);
}

enum nss_status _nss_dce_request(nss_dced_message_t request)
{
  enum nss_status status;

  TRACE("nss_dce_common._nss_dce_request: called\n");

  if ((status = _nss_dce_init_sock()) != NSS_STATUS_TRYAGAIN)
    return status;
  
  return _nss_dce_sock_write(&request, sizeof(request));
}

enum nss_status _nss_dce_read_response(void *data, nss_dce_entry_reader_t entry_reader)
{
  enum nss_status status;
  nss_dced_message_t response;

  TRACE("nss_dce_common.read_response: called\n");
  
  if ((status = _nss_dce_sock_read(&response, sizeof(response))) != NSS_STATUS_SUCCESS)
    return status;

  switch(response)
    {
      case NSS_DCED_SUCCESS:
        return entry_reader(data);
        
      case NSS_DCED_UNAVAIL:
        TRACE("nss_dce_common.read_response: returning NSS_STATUS_UNAVAIL\n");
	errno = ENOENT;
        return NSS_STATUS_UNAVAIL;
      
      case NSS_DCED_NOTFOUND:
        TRACE("nss_dce_common.read_response: returning NSS_STATUS_NOTFOUND\n");
	errno = ENOENT;
        return NSS_STATUS_NOTFOUND;

      default:
        TRACE("nss_dce_common.read_response: unknown result code received (%d), returning NSS_STATUS_NOTFOUND\n", response);
	errno = ENOENT;
        return NSS_STATUS_NOTFOUND;
    }
}

enum nss_status _nss_dce_null_entry_reader(void *data)
{
  return NSS_STATUS_SUCCESS;
}
