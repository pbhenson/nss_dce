/* 
 * DCE Naming Services for Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCE_SHADOW_H
#define NSS_DCE_SHADOW_H

enum nss_status _nss_dce_getspnam_r(const char *, struct spwd *, char *, size_t, int *);
enum nss_status _nss_dce_setspent();
enum nss_status _nss_dce_getspent_r(struct spwd *, char *, size_t, int *);
enum nss_status _nss_dce_endspent();
static enum nss_status _nss_dce_shadow_entry_reader(void *);

#endif
