#include <stdio.h>
#include <pwd.h>

main(int argc, char *argv[])
{
  struct passwd *pwd;

  if (argc != 2)
  {
    fprintf(stderr, "usage: %s username\n", argv[0]);
    exit(-1);
  }
  
  if (pwd = getpwnam(argv[1]))
    print_passwd(pwd);
  else
    printf("Couldn't find username %s\n\n", argv[1]);
}

print_passwd(struct passwd *pwd)
{
  printf("%s %s %d %d %s %s %s %s %s\n\n",
	 pwd->pw_name,
	 pwd->pw_passwd,
	 pwd->pw_uid,
	 pwd->pw_gid,
	 pwd->pw_age,
	 pwd->pw_comment,
	 pwd->pw_gecos,
	 pwd->pw_dir,
	 pwd->pw_shell);
}

