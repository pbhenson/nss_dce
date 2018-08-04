/* 
 * DCE Naming Services for Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCE_PASSWD_H
#define NSS_DCE_PASSWD_H

enum nss_status _nss_dce_getpwnam_r(const char *, struct passwd *, char *, size_t, int *);
enum nss_status _nss_dce_getpwuid_r(uid_t, struct passwd *, char *, size_t, int *);
enum nss_status _nss_dce_setpwent();
enum nss_status _nss_dce_getpwent_r(struct passwd *, char *, size_t, int *);
enum nss_status _nss_dce_endpwent();
static enum nss_status _nss_dce_pw_entry_reader(void *);

#endif
