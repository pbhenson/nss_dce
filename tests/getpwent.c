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

  setpwent();

  while ((pwd = getpwent()) != NULL)
  {
    if (!strcmp(pwd->pw_name, argv[1]))
    {
      print_passwd(pwd);
      break;
    }
  }

  if (!pwd)
    printf("Couldn't find username %s\n\n", argv[1]);
  
  endpwent();
}

print_passwd(struct passwd *pwd)
{
  printf("%s %s %d %d"
#ifdef SunOS
         " %s %s"
#endif
         " %s %s %s\n\n",
         pwd->pw_name,
         pwd->pw_passwd,
         pwd->pw_uid,
         pwd->pw_gid,
#ifdef SunOS
         pwd->pw_age,
         pwd->pw_comment,
#endif
         pwd->pw_gecos,
         pwd->pw_dir,
         pwd->pw_shell);
}
