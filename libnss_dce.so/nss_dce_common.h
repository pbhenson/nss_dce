/* 
 * DCE Naming Services for Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCE_COMMON_H
#define NSS_DCE_COMMON_H

#ifdef DEBUG
#define TRACE(X...) { fprintf(stderr, X); fflush(stderr); } 
#else
#define TRACE(X...)
#endif

typedef enum nss_status (*nss_dce_entry_reader_t)();

typedef struct {
  void            *result;
  char            *buffer;
  size_t          buflen;
} nss_XbyY_buf_t;

					
enum nss_status _nss_dce_sock_read(const void *, size_t);
enum nss_status _nss_dce_sock_write(const void *, size_t);
enum nss_status _nss_dce_sock_read_string(char **, char **, int *);
enum nss_status _nss_dce_sock_write_string(const char *, int);
enum nss_status _nss_dce_request(nss_dced_message_t);
enum nss_status _nss_dce_read_response(void *, nss_dce_entry_reader_t);
enum nss_status _nss_dce_null_entry_reader(void *);

#endif


