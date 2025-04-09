// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

#include "syscalls_names.h"
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fstream>
#include <list>
#include <vector>
#include "structs.h"
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <iomanip>
#include <sstream>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
  int err;
  libbpf_set_print(libbpf_print_fn);

  int BaseTableMap_map_id = -1;

  if (argc < 4)
  {
    std::cout << "\n----------------------------------\n"
              << "\nMap(s) ids not specified\n"
              << "\nExiting\n"
              << "\n----------------------------------\n";
    return 0;
  }

  BaseTableMap_map_id = std::stoll(argv[1]);

  int BaseTableMap_map_fd = bpf_map_get_fd_by_id(BaseTableMap_map_id);

  bool not_found_BaseTableMap = (BaseTableMap_map_fd < 0);
  printf("\n----------------------------------\n");
  printf("\nBaseTableMap_map_fd: %d\n", BaseTableMap_map_fd);
  printf("\n----------------------------------\n");

  if (not_found_BaseTableMap)
  {
    printf("\n----------------------------------\n");
    printf("\nPinned map NOT FOUND\n");
    printf("\nExiting\n");
    printf("\n----------------------------------\n");
    return 0;
  }

  struct bpf_map_info info = {};
  uint32_t info_len = sizeof(struct bpf_map_info);

  bpf_map_get_info_by_fd(BaseTableMap_map_fd, &info, &info_len);

  printf("\nMax entries: %d\n", info.max_entries);

  uint32_t first_key_to_print = 0;
  uint32_t num_of_entries_to_print = info.max_entries;

  if (argc == 4)
  {
    num_of_entries_to_print = atoll(argv[3]);
    printf("\nPrinting first %llu entries\n", num_of_entries_to_print);
  }
  else if (argc == 5)
  {
    first_key_to_print = atoll(argv[3]);
    num_of_entries_to_print = atoll(argv[4]);
    printf("\nPrinting %llu\n entries since %llu", num_of_entries_to_print, first_key_to_print);
  }

  std::string columns = std::string(argv[2]);
  std::stringstream ss(columns);
  int id;
  std::unordered_set<int> columnsIds;
  while (ss >> id)
    columnsIds.emplace(id);

  for (int i = first_key_to_print; i < first_key_to_print + num_of_entries_to_print; i++)
  {
    struct BaseTableEntry MapElem;

    bpf_map_lookup_elem(BaseTableMap_map_fd, &i, &MapElem);

    if (MapElem.is_returned)
    {
      std::chrono::system_clock::time_point enterTime;
      enterTime += std::chrono::microseconds(MapElem.enter_time / 1000);
      std::chrono::system_clock::time_point exitTime;
      exitTime += std::chrono::microseconds(MapElem.exit_time / 1000);

      time_t enterTimeT = std::chrono::system_clock::to_time_t(enterTime);
      time_t exitTimeT = std::chrono::system_clock::to_time_t(exitTime);

      struct tm *pEnterTime = localtime(&enterTimeT);
      struct tm *pExitTime = localtime(&exitTimeT);

      std::cout << "\n";
      std::cout << std::setw(10) << i << " | ";

      if (columnsIds.empty() || columnsIds.find(1) != columnsIds.end())
        std::cout << "glob_id: " << MapElem.global_id << " | ";

      if (columnsIds.empty() || columnsIds.find(2) != columnsIds.end())
        std::cout << "syscall: " << syscalls_names[MapElem.syscall_number] << " | ";

      if (columnsIds.empty() || columnsIds.find(3) != columnsIds.end())
        std::cout << "TGID: " << (MapElem.process_ID >> 32) << " | ";

      if (columnsIds.empty() || columnsIds.find(4) != columnsIds.end())
        std::cout << "PID: " << ((MapElem.process_ID << 32) >> 32) << " | ";

      if (columnsIds.empty() || columnsIds.find(5) != columnsIds.end())
        std::cout << "GID: " << (MapElem.process_owner_user_ID >> 32) << " | ";

      if (columnsIds.empty() || columnsIds.find(6) != columnsIds.end())
        std::cout << "UID: " << ((MapElem.process_owner_user_ID << 32) >> 32) << " | ";

      if (columnsIds.empty() || columnsIds.find(7) != columnsIds.end())
        std::cout << "ret: " << MapElem.returned_value << " | ";

      if (columnsIds.empty() || columnsIds.find(8) != columnsIds.end())
        std::cout << "enter: " << std::put_time(pEnterTime, "%D %T") << "." << std::setw(6) << std::setfill('0') << (MapElem.enter_time / 1000) % 1'000'000 << " | " << std::setfill(' ');

      if (columnsIds.empty() || columnsIds.find(9) != columnsIds.end())
        std::cout << "exit: " << std::put_time(pExitTime, "%D %T") << "." << std::setw(6) << std::setfill('0') << (MapElem.exit_time / 1000) % 1'000'000 << " | " << std::setfill(' ');

      if (columnsIds.empty() || columnsIds.find(10) != columnsIds.end())
        std::cout << "(" << (MapElem.exit_time - MapElem.enter_time) << " ns)";
    }
    else
    {
      std::chrono::system_clock::time_point enterTime;
      enterTime += std::chrono::microseconds(MapElem.enter_time / 1000);

      time_t enterTimeT = std::chrono::system_clock::to_time_t(enterTime);

      std::cout << "\n";
      std::cout << std::setw(10) << i << " | ";

      if (columnsIds.empty() || columnsIds.find(1) != columnsIds.end())
        std::cout << "glob_id: " << MapElem.global_id << " | ";

      if (columnsIds.empty() || columnsIds.find(2) != columnsIds.end())
        std::cout << "syscall: " << syscalls_names[MapElem.syscall_number] << " | ";

      if (columnsIds.empty() || columnsIds.find(8) != columnsIds.end())
        std::cout << "enter: " << ((MapElem.enter_time == 0) ? "0" : ctime(&enterTimeT)) << " | ";

      if (columnsIds.empty() || columnsIds.find(3) != columnsIds.end())
        std::cout << "TGID: " << (MapElem.process_ID >> 32) << " | ";

      if (columnsIds.empty() || columnsIds.find(4) != columnsIds.end())
        std::cout << "PID: " << ((MapElem.process_ID << 32) >> 32) << " | ";

      if (columnsIds.empty() || columnsIds.find(5) != columnsIds.end())
        std::cout << "GID: " << (MapElem.process_owner_user_ID >> 32) << " | ";

      if (columnsIds.empty() || columnsIds.find(6) != columnsIds.end())
        std::cout << "UID: " << ((MapElem.process_owner_user_ID << 32) >> 32) << " | ";

      if (columnsIds.empty() || columnsIds.find(7) != columnsIds.end())
        std::cout << "--NO RETURN-- ";
    }
  }

  printf("\n");
  return 0;
}
