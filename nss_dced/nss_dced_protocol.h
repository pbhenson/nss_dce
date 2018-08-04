/* 
 * DCE Naming Services for Solaris/Linux
 *
 * Paul Henson <henson@acm.org>
 *
 * Copyright (c) 1997-2002 Paul Henson -- see COPYRIGHT file for details
 *
 */

#ifndef NSS_DCED_PROTOCOL_H
#define NSS_DCED_PROTOCOL_H

#ifndef NSS_DCED_SOCKETPATH
#define NSS_DCED_SOCKETPATH "/opt/dcelocal/var/security/.nss_dced"
#endif

typedef unsigned char nss_dced_message_t;

#define NSS_DCED_UNAVAIL   (1)
#define NSS_DCED_NOTFOUND  (2)
#define NSS_DCED_SUCCESS   (3)

#define NSS_DCED_GETPWNAM           (1)
#define NSS_DCED_GETPWUID           (2)
#define NSS_DCED_SETPWENT           (3)
#define NSS_DCED_GETPWENT           (4)
#define NSS_DCED_ENDPWENT           (5)
#define NSS_DCED_GETGRNAM           (6)
#define NSS_DCED_GETGRGID           (7)
#define NSS_DCED_SETGRENT           (8)
#define NSS_DCED_GETGRENT           (9)
#define NSS_DCED_ENDGRENT          (10)
#define NSS_DCED_GETGROUPSBYMEMBER (11)
#define NSS_DCED_GETSPNAM          (12)
#define NSS_DCED_SETSPENT          (13)
#define NSS_DCED_GETSPENT          (14)
#define NSS_DCED_ENDSPENT          (15)

#endif


