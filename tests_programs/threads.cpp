#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <unistd.h>
#include <chrono>

int main()
{

  std::cout << "\nInit PID: [ " << getpid() << " ]" << std::endl;
  std::vector<std::thread> threadsVec;

  std::chrono::milliseconds timespan(1500); // or whatever
  std::this_thread::sleep_for(timespan);

  for (size_t i = 0; i < 5; i++)
  {
    threadsVec.push_back(std::thread([=]()
                                     {
                                       std::cout << "\nThread " << i << " PID: [ " << getpid() << " ]" << std::endl;
                                       printf("The ID of this of this thread is: %ld\n", (long int)syscall(186));

                                       std::vector<std::thread> threads2Vec;

                                       std::chrono::milliseconds timespan(1500); // or whatever
                                       std::this_thread::sleep_for(timespan);

                                       for (size_t i = 0; i < 5; i++)
                                       {
                                         threads2Vec.push_back(std::thread([=]()
                                                                           {
            std::this_thread::sleep_for(std::chrono::milliseconds(10000));
            std::cout << "\n\nThread " << i <<  " PID: [ "	<< getpid() << " ]" << std::endl; 
             printf("The ID of this of this thread is: %ld\n", (long int)syscall(186)); }));
                                       }
                                       //std::this_thread::sleep_for(std::chrono::milliseconds(10000));
                                       for (size_t i = 0; i < threads2Vec.size(); i++)
                                       {
                                         threads2Vec[i].join();
                                       } }));
  }

  for (size_t i = 0; i < threadsVec.size(); i++)
  {
    threadsVec[i].join();
  }

  return 0;
}
