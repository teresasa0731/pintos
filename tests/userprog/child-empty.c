/* Child process run by exec-multiple, exec-one, wait-simple, and
   wait-twice tests.
   Just prints a single message and terminates. */

#include <stdio.h>
#include "tests/lib.h"

// const char *test_name = "child-empty";

int
main (void)
{
  test_name = "child-empty";
  return 0;
}
