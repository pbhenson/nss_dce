/* 
 * DCE Naming Services for Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCE_GROUP_H
#define NSS_DCE_GROUP_H

typedef struct {
  gid_t group;
  long int *start;
  long int *size;
  gid_t **groups;
  long int limit;
} nss_dce_initgroups_buf_t;

enum nss_status _nss_dce_getgrnam_r(const char *, struct group *, char *, size_t, int *);
enum nss_status _nss_dce_getgrgid_r(gid_t, struct group *, char *, size_t, int *);
enum nss_status _nss_dce_setgrent();
enum nss_status _nss_dce_getgrent_r(struct group *, char *, size_t, int *);
enum nss_status _nss_dce_endgrent();
enum nss_status _nss_dce_initgroups_dyn(char *, gid_t, long int *, long int *, gid_t **, long int, int *);
static enum nss_status _nss_dce_gr_entry_reader(void *);
static enum nss_status _nss_dce_initgroups_entry_reader(void *);

#endif

