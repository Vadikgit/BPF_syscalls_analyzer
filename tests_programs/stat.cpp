#include <iostream>
#include <sys/stat.h>

int main(int argc, char **argv)
{
  struct stat sb;
  if (stat("/proc/self/ns/pid", &sb) == -1)
  {
    fprintf(stderr, "Failed to acquire namespace information");
    return 1;
  }

  std::cout << "\n STAT: " << sb.st_dev << ' ' << sb.st_ino << '\n';
}
