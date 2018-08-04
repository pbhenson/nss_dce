/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997,1998 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCE_COMMON_H
#define NSS_DCE_COMMON_H

#ifdef DEBUG
#define TRACE(X...) { fprintf(stderr, X); fflush(stderr); } 
#else
#define TRACE(X...)
#endif

#define SOCKIO_OK (-1)

#define _nss_dce_sock_read(B, V, L) { int ret_val = __nss_dce_sock_read(B, V, L); \
                                      if (ret_val != SOCKIO_OK) return ret_val; }

#define _nss_dce_sock_write(B, V, L) { int ret_val = __nss_dce_sock_write(B, V, L); \
                                       if (ret_val != SOCKIO_OK) return ret_val; }

#define _nss_dce_sock_read_string(B, V, S, L) { int ret_val = __nss_dce_sock_read_string(B, V, S, L); \
                                      if (ret_val != SOCKIO_OK) return ret_val; }

#define _nss_dce_sock_write_string(B, V, L) { _nss_dce_sock_write(B, &L, sizeof(L)); \
					      _nss_dce_sock_write(B, V, L); }
					   
#define _nss_dce_request(B, R) { nss_dced_message_t request = R; \
                                 _nss_dce_sock_write(B, &request, sizeof(request)); }

					
typedef	struct dce_backend *dce_backend_ptr_t;
typedef	nss_status_t (*dce_backend_op_t)(dce_backend_ptr_t, void *);

struct dce_backend
{
  dce_backend_op_t *ops;
  nss_dbop_t n_ops;

  pid_t pid;
  int sock;
};

typedef nss_status_t (*nss_dce_entry_reader_t)();

int _nss_dce_bind_sock(dce_backend_ptr_t);
int __nss_dce_sock_read(dce_backend_ptr_t, const void *, size_t);
int __nss_dce_sock_write(dce_backend_ptr_t, const void *, size_t);
int __nss_dce_sock_read_string(dce_backend_ptr_t, char **, char **, int *);
nss_status_t _nss_dce_destr(dce_backend_ptr_t, void *);
nss_status_t _nss_dce_read_response(dce_backend_ptr_t, void *, nss_dce_entry_reader_t);
nss_status_t _nss_dce_null_entry_reader(dce_backend_ptr_t, void *);

#endif
