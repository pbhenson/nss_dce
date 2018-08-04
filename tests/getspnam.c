#include <stdio.h>
#include <shadow.h>

main(int argc, char *argv[])
{
  struct spwd *spwd;

  if (argc != 2)
  {
    fprintf(stderr, "usage: %s username\n", argv[0]);
    exit(-1);
  }
  
  if (spwd = getspnam(argv[1]))
    print_shadow(spwd);
  else
    printf("Couldn't find username %s\n\n", argv[1]);
}

print_shadow(struct spwd *spwd)
{
  printf("%s %s %ld %ld %ld %ld %ld %ld %uld\n\n",
	 spwd->sp_namp,
	 spwd->sp_pwdp,
	 spwd->sp_lstchg,
	 spwd->sp_min,
	 spwd->sp_max,
	 spwd->sp_warn,
	 spwd->sp_inact,
	 spwd->sp_expire,
	 spwd->sp_flag);
}

