/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997-2000 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCE_PASSWD_H
#define NSS_DCE_PASSWD_H

nss_status_t _nss_dce_getpwnam(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_getpwuid(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_setpwent(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_getpwent(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_endpwent(dce_backend_ptr_t backend, void *data);
nss_backend_t *_nss_dce_passwd_constr(const char *db_name, const char *src_name, const char *cfg_args);
nss_status_t _nss_dce_pw_entry_reader(dce_backend_ptr_t backend, void *data);

#endif
