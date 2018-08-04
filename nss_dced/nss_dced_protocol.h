/* 
 * DCE Naming Services for Solaris
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCED_PROTOCOL_H
#define NSS_DCED_PROTOCOL_H

#define NSS_DCED_SOCKETPATH "/tmp/.nss_dced"

#define NSS_DCED_UNAVAIL   (1)
#define NSS_DCED_NOTFOUND  (2)
#define NSS_DCED_SUCCESS   (3)

#define NSS_DCED_GETPWNAM  (1)
#define NSS_DCED_GETPWUID  (2)
#define NSS_DCED_SETPWENT  (3)
#define NSS_DCED_GETPWENT  (4)
#define NSS_DCED_ENDPWENT  (5)
#define NSS_DCED_GETGRNAM  (6)
#define NSS_DCED_GETGRGID  (7)
#define NSS_DCED_SETGRENT  (8)
#define NSS_DCED_GETGRENT  (9)
#define NSS_DCED_ENDGRENT (10)
#define NSS_DCED_SHUTDOWN (11)

#endif


