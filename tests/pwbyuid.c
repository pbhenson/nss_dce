#include <stdio.h>
#include <pwd.h>

main(int argc, char *argv[])
{
  struct passwd *pwd;

  if (argc != 2)
  {
    fprintf(stderr, "usage: %s UID\n", argv[0]);
    exit(-1);
  }

  printf("Searching for UID %d with setpwent/getpwent/endpwent.\n\n",
         atoi(argv[1]));

  setpwent();

  while ((pwd = getpwent()) != NULL)
  {
    if (pwd->pw_uid == atoi(argv[1]))
    {
      print_passwd(pwd);
      break;
    }
  }

  if (!pwd)
    printf("Couldn't find UID %d\n\n", atoi(argv[1]));
  
  endpwent();

  printf("Searching for UID %d with getpwuid.\n\n", atoi(argv[1]));

  pwd = getpwuid(atoi(argv[1]));

  if (pwd == NULL)
    printf("Couldn't find UID %d\n\n", atoi(argv[1]));
  else
    print_passwd(pwd);

  exit(0);
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

