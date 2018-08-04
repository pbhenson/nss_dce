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

  if (grp = getgrnam(argv[1]))
    print_group(grp);
  else
    printf("Couldn't find groupname %s\n\n", argv[1]);
}

print_group(struct group *grp)
{
  printf("%s %s %d\n\n",
	 grp->gr_name,
	 grp->gr_passwd,
	 grp->gr_gid);
}

