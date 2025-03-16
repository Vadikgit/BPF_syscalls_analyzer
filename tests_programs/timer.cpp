#include <chrono>
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <thread>
#include <vector>
#include <unistd.h>

void threadProcedure(int level, int maxLevel)
{
  std::cout << "\nThread PID: [ " << getpid() << " ]" << std::endl;
  printf("The ID of this thread is: %ld\n", (long int)syscall(186));

  std::system("bash -c \"ls\"");

  for (int i = 0; i < 100; i++)
  {
    // for(int i = 0; i < 100000; i++) {

    int *ptr = new int[900];
    *ptr = 10;
    for (int j = 0; j < 900; j++)
      ptr[j] = j;
    delete[] ptr;
  }

  std::vector<std::thread> threadsVec;

  if (level < maxLevel)
  {
    for (size_t i = 0; i < 5; i++)
    {
      threadsVec.push_back(std::thread(threadProcedure, level + 1, maxLevel));
    }

    for (size_t i = 0; i < threadsVec.size(); i++)
    {
      threadsVec[i].join();
    }
  }
}

int main()
{
  auto start_time = std::chrono::steady_clock::now();

  for (int i = 0; i < 10000; i++)
  {
    // for(int i = 0; i < 100000; i++) {
    int *ptr = new int[900];
    *ptr = 10;
    for (int j = 0; j < 900; j++)
      ptr[j] = j;
    delete[] ptr;
  }

  for (int i = 0; i < 10000; i++)
  {
    // for(int i = 0; i < 100000; i++) {
    std::ofstream outf("SomeText.txt");
    outf << "See line #1!" << std::endl;
  }

  threadProcedure(0, 2);

  /*for (int i = 0; i < 100; i++)
  {
    // for(int i = 0; i < 100000; i++) {
    int *ptr = new int[900];
    *ptr = 10;
    for (int j = 0; j < 900; j++)
      ptr[j] = j;
    delete[] ptr;
  }

  for (int i = 0; i < 5; i++)
  {
    // for(int i = 0; i < 10000; i++) {
    std::system("python3 -mtimeit -s\"from numpy import zeros; N=10**6\" \"a = zeros(N,dtype='i')\"\\
    \"for i in range(N):\" \"  a[i] = i\"");
  }

  for (int i = 0; i < 100; i++)
  {
    // for(int i = 0; i < 100000; i++) {
    std::ofstream outf("SomeText.txt");
    outf << "See line #1!" << std::endl;
  }*/

  auto end_time = std::chrono::steady_clock::now();
  auto elapsed_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_time - start_time);
  std::cout << elapsed_ns.count() << " ns\n";
}
