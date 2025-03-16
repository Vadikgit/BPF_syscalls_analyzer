#include <stdio.h>
#include <stdlib.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
  if(argc == 2){
    if(argv[1][0] == '1'){
      int a;
      
      char line[256];
      printf("\nEnter a: ");
      if(fgets(line,256,stdin) && sscanf(line,"%d", &a)!=1 )
        a = 1;
      
      for (int i = 0; i < a; i++)
        printf("Hello world!\n");
    }
    else if(argv[1][0] == '2'){
      pid_t pid;
      int rv;
      pid = clone();
      switch(pid) {
        case 0:
          printf(" CHILD process pid: %d\n", getpid());
          sleep(10);
          break;

        default:
          printf("PARENT process pid: %d\n", getpid());
          sleep(10);
      }
    }
    else if(argv[1][0] == '3'){
      
    }
  }
  
  return 0;
}
