/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCED_H
#define NSS_DCED_H

pthread_addr_t handle_request(pthread_addr_t arg);

void nss_dced_acct_lookup(sec_rgy_cursor_t *account_cursor, int sock, sec_rgy_name_t pname);

void nss_dced_getpwuid(sec_rgy_cursor_t *account_cursor, int sock, uid_t uid);

void nss_dced_getgrnam(int sock, sec_rgy_name_t pname);

void nss_dced_getgrgid(int sock, gid_t gid);

void nss_dced_getgrent(sec_rgy_cursor_t *group_cursor, int sock);

#endif
