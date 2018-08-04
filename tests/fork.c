#include <stdio.h>
#include <pwd.h>

int main()
{
 printf("Process id: %d\n", getpid());

  printf("(%d) Calling getpwnam\n", getpid());
  
  print_passwd(getpwnam("henson"));

  printf("Forking\n");
  fork();
  fork();
  fork();
  
  printf("Process id: %d\n", getpid());

  printf("(%d) Calling getpwnam\n", getpid());
  
  print_passwd(getpwnam("henson"));

  
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
