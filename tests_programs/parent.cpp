#include <iostream> 
#include <unistd.h> 
using namespace std; 

int main() 
{ 
	int pid; 
	pid = fork(); 
	
  if (pid == 0) 
	{ 
		cout << "\nCHILD Process: [ "	<< getppid() << " ] -> [ " << getpid() << " ]" << endl; 
	}
  else	{ 
		cout << "\nPARENT Process: [ "	<< getppid() << " ] -> [ " << getpid() << " ]" << endl; 
  }

  return 0; 
}
