#include <stdio.h>
#include <grp.h>

main(int argc, char *argv[])
{
  struct group *grp;

  if (argc != 2)
  {
    fprintf(stderr, "usage: %s groupname\n", argv[0]);
    exit(-1);
  }

  printf("Searching for groupname %s with setgrent/getgrent/endgrent.\n\n",
         argv[1]);

  setgrent();

  while ((grp = getgrent()) != NULL)
  {
    if (!strcmp(grp->gr_name, argv[1]))
    {
      print_group(grp);
      break;
    }
  }

  if (!grp)
    printf("Couldn't find groupname %s\n\n", argv[1]);
  
  endgrent();

  printf("Searching for groupname %s with getgrnam.\n\n", argv[1]);

  grp = getgrnam(argv[1]);

  if (grp == NULL)
    printf("Couldn't find groupname %s\n\n", argv[1]);
  else
    print_group(grp);

  exit(0);
}

print_group(struct group *grp)
{
  printf("%s %s %d\n\n",
	 grp->gr_name,
	 grp->gr_passwd,
	 grp->gr_gid);
}

