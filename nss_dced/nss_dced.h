/* 
 * DCE Naming Services for Solaris/Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997-2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCED_H
#define NSS_DCED_H

/* default lifetime (in seconds) of a password, used only if registry policy lookup fails */
#define NSS_DCED_PASSWD_LIFETIME 0  /* no password expiration */

/* minimum number of days required between password changes */
#define NSS_DCED_SP_MIN -1  /* no minimum number of days */

/* number of days before password expires that the user is warned */
#define NSS_DCED_SP_WARN -1  /* no warning */

/* number of days of inactivity allowed for user */
#define NSS_DCED_SP_INACT -1  /* no inactivity limit */


void nss_dced_main();

pthread_addr_t handle_request(pthread_addr_t arg);

void nss_dced_passwd_lookup(sec_rgy_cursor_t *passwd_cursor, int sock, sec_rgy_name_t pname);

void nss_dced_shadow_lookup(sec_rgy_cursor_t *shadow_cursor, int sock, sec_rgy_name_t pname);

void nss_dced_getpwuid(sec_rgy_cursor_t *passwd_cursor, int sock, uid_t uid);

void nss_dced_getgrnam(int sock, sec_rgy_name_t pname);

void nss_dced_getgrgid(int sock, gid_t gid);

void nss_dced_getgrent(sec_rgy_cursor_t *group_cursor, int sock);

void nss_dced_getgroupsbymember(int sock, sec_rgy_name_t pname);

#endif
