/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997-2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCE_GROUP_H
#define NSS_DCE_GROUP_H

nss_status_t _nss_dce_getgrnam(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_getgrgid(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_setgrent(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_getgrent(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_endgrent(dce_backend_ptr_t backend, void *dummy);
nss_status_t _nss_dce_getgroupsbymember(dce_backend_ptr_t backend, void *data);
nss_backend_t *_nss_dce_group_constr(const char *db_name, const char *src_name, const char *cfg_args);
nss_status_t _nss_dce_gr_entry_reader(dce_backend_ptr_t backend, void *data);
nss_status_t _nss_dce_grbymem_entry_reader(dce_backend_ptr_t backend, void *data);

#endif

