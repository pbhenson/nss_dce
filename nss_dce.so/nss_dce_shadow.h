/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997-2000 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCE_SHADOW_H
#define NSS_DCE_SHADOW_H

nss_status_t _nss_dce_getspnam(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_setspent(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_getspent(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_endspent(dce_backend_ptr_t backend, void *data);
nss_backend_t *_nss_dce_shadow_constr(const char *db_name, const char *src_name, const char *cfg_args);
nss_status_t _nss_dce_shadow_entry_reader(dce_backend_ptr_t backend, void *data);

#endif
