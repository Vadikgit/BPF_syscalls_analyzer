// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <cstdlib>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "analyzer.skel.h"
#include "structs.h"

#include <vector>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <string>

//
#include <sys/stat.h>
//
int err;

int SeqNums_map_fd = -1;
int ContinExtrFlag_map_fd = -1;
int BaseTableMap_map_fd = -1;

std::string ContinExtrFlagPathName = "/sys/fs/bpf/ContinExtrFlag";

std::string EnterHandlerPathName = "/sys/fs/bpf/handle_tp_enter";
std::string ExitHandlerPathName = "/sys/fs/bpf/handle_tp_exit";

std::string EnterHandlerLinkPatternPathName = "/sys/fs/bpf/handler_link_enter_";
std::string ExitHandlerLinkPatternPathName = "/sys/fs/bpf/handler_link_exit_";

const std::string arg_specify_root_process_to_catch_syscalls = "-pid";
const std::string arg_start_analyzer = "-start";
const std::string arg_stop_analyzer = "-stop";

std::unordered_map<std::string, std::vector<std::string>> arguments;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

void create_or_reuse_map(std::string pathName, bpf_map_type mapType, uint32_t keySize, uint32_t valSize,
                         uint64_t maxEntries, struct bpf_map *mapPointerInScel, int &mapFd)
{

  mapFd = bpf_obj_get(pathName.c_str());

  bool notFoundMap = (mapFd < 0);

  std::cout << "\n----------------------------------\n"
            << pathName
            << " file descriptor: " << mapFd << "\n----------------------------------\n";

  if (notFoundMap)
  {
    std::cout << "\n----------------------------------\n\nPinned map " << pathName
              << " NOT FOUND\n\nCreating new ...\n\n----------------------------------\n";

    mapFd = bpf_map_create(mapType, pathName.substr(pathName.rfind('/') + 1).c_str(), keySize, valSize, maxEntries, 0);
  }

  bpf_map__reuse_fd(mapPointerInScel, mapFd);

  if (notFoundMap)
    bpf_map__pin(mapPointerInScel, pathName.c_str());
}

void attach_handlers_to_syscalls_and_pin_links(struct analyzer_bpf *skel)
{
  // Reading data about relevant syscalls from file  --------------
  std::ifstream inf("relevant_syscalls.txt");
  if (!inf)
  {
    std::cerr << "relevant_syscalls.txt could not be opened for reading!\n";
    exit(1);
  }

  std::string currentString;

  while (inf)
  {
    std::getline(inf, currentString);

    if (currentString.length() > 0 && currentString.back() == '-')
    {
      currentString = currentString.substr(0, currentString.find('-'));
      std::cout << "\'" << currentString << "\' will be traced\n";

      struct bpf_link *enter_link = bpf_program__attach_tracepoint(skel->progs.handle_tp_enter, "syscalls", (std::string("sys_enter_") + currentString).c_str());

      struct bpf_link *exit_link = bpf_program__attach_tracepoint(skel->progs.handle_tp_exit, "syscalls", (std::string("sys_exit_") + currentString).c_str());

      if (enter_link)
        bpf_link__pin(enter_link, (EnterHandlerLinkPatternPathName + currentString).c_str());

      if (exit_link)
        bpf_link__pin(exit_link, (ExitHandlerLinkPatternPathName + currentString).c_str());
    }
  }

  bpf_program__pin(skel->progs.handle_tp_enter, EnterHandlerPathName.c_str());
  bpf_program__pin(skel->progs.handle_tp_exit, ExitHandlerPathName.c_str());
}

void delete__handlers_and_links(struct analyzer_bpf *skel)
{
  std::system("rm /sys/fs/bpf/h*");
}

int cleanup(struct analyzer_bpf *skel)
{
  analyzer_bpf__destroy(skel);
  std::cout << "\n----------------------------------\n\nCLEANUP ...\n\n----------------------------------\n";
  return err;
}

void process_arguments(int argc, char **argv, struct analyzer_bpf *skel)
{
  std::string key;
  for (int i = 1; i < argc; i++)
  {
    if (argv[i][0] == '-')
    {
      key = argv[i];
      auto it = arguments.find(key);

      if (it == arguments.end())
        arguments[key] = {};
    }
    else
    {
      arguments[key].push_back(argv[i]);
    }
  }

  if (arguments.find(arg_start_analyzer) != arguments.end())
  { // analyzer started

    // Load & verify BPF programs
    err = analyzer_bpf__load(skel);
    if (err)
    {
      fprintf(stderr, "Failed to load and verify BPF skeleton\n");
      return;
    }

    // Preparing BPF maps
    SeqNums_map_fd = bpf_map__fd(skel->maps.SeqNums);
    BaseTableMap_map_fd = bpf_map__fd(skel->maps.BaseTableMap);
    // ContinExtrFlag_map_fd = bpf_map__fd(skel->maps.ContinExtrFlag);

    ContinExtrFlag_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, ContinExtrFlagPathName.substr(ContinExtrFlagPathName.rfind('/') + 1).c_str(), sizeof(uint32_t), sizeof(uint8_t), 1, 0);
    bpf_obj_pin(ContinExtrFlag_map_fd, ContinExtrFlagPathName.c_str());
    // SeqNums_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "SeqNums");
    // ContinExtrFlag_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ContinExtrFlag");

    printf("\n----------------------------------\n");
    printf("BaseTableMap_map_fd: %d\n", BaseTableMap_map_fd);
    printf("SeqNums_map_fd: %d\n", SeqNums_map_fd);
    printf("ContinExtrFlag_map_fd: %d\n", ContinExtrFlag_map_fd);
    printf("----------------------------------\n");

    struct bpf_map_info mp_info = {};
    uint32_t info_len = sizeof(mp_info);

    int BaseTableMap_map_id = -1;
    int SeqNums_map_id = -1;
    int ContinExtrFlag_map_id = -1;

    bpf_map_get_info_by_fd(BaseTableMap_map_fd, &mp_info, &info_len);
    BaseTableMap_map_id = mp_info.id;

    bpf_map_get_info_by_fd(SeqNums_map_fd, &mp_info, &info_len);
    SeqNums_map_id = mp_info.id;

    bpf_map_get_info_by_fd(ContinExtrFlag_map_fd, &mp_info, &info_len);
    ContinExtrFlag_map_id = mp_info.id;

    printf("\n----------------INFO------------------\n");
    printf("BaseTableMap_map_id: %d\n", BaseTableMap_map_id);
    printf("SeqNums_map_id: %d\n", SeqNums_map_id);
    printf("ContinExtrFlag_map_id: %d\n", ContinExtrFlag_map_id);
    printf("\n----------------------------------\n");

    // create_or_reuse_map(SeqNumsPathName, BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint64_t),
    //                         3, skel->maps.SeqNums, SeqNums_map_fd); // Sequence Number
    // create_or_reuse_map(ContinExtrFlagPathName, BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(uint8_t),
    //                     1, skel->maps.ContinExtrFlag, ContinExtrFlag_map_fd); // Continue work of extractor

    std::cout << "\n----------------------------------\n\nAttached to maps\n\n----------------------------------\n";

    // Start map_extractor
    uint32_t ContinExtr_key = 0;
    uint8_t ContinExtr_val = 1;
    bpf_map_update_elem(ContinExtrFlag_map_fd, &ContinExtr_key, &ContinExtr_val, 0);

    std::string map_extractor_command = std::string("./map_extractor ") + std::to_string(BaseTableMap_map_id) + " " + std::to_string(SeqNums_map_id) + " " + std::to_string(ContinExtrFlag_map_id) + std::string(" > extractorlog.txt 2>&1 &");
    std::system(map_extractor_command.c_str());

    // Fill in max_entries_BaseTableMap_c SeqNums[2]
    uint32_t seqnum2 = 2;
    bpf_map_update_elem(SeqNums_map_fd, &seqnum2, &(skel->rodata->max_entries_BaseTableMap_c), 0);
    seqnum2 = 1;
    uint64_t seqnumsval = 0;
    bpf_map_update_elem(SeqNums_map_fd, &seqnum2, &seqnumsval, 0);

    // Attach tracepoints handler
    err = analyzer_bpf__attach(skel);
    if (err)
    {
      fprintf(stderr, "Failed to attach BPF skeleton\n");
      return;
    }

    attach_handlers_to_syscalls_and_pin_links(skel);
    std::cout << "\n----------------------------------\n\nHandlers attached to tracepoints\n\n----------------------------------\n";

    if (arguments.find(arg_specify_root_process_to_catch_syscalls) != arguments.end() &&
        arguments[arg_specify_root_process_to_catch_syscalls].empty() == false)
    { // process
      try
      {
        uint64_t PD_to_track = std::stoll(arguments[arg_specify_root_process_to_catch_syscalls][0]);

        skel->bss->to_track_value = PD_to_track;

        std::cout << "\n----------------------------------\n\nTracking PID: " << PD_to_track
                  << "\n\n----------------------------------\n";
      }
      catch (std::invalid_argument const &ex)
      {
        std::cout << ex.what() << '\n';
      }
    }

    std::cout << "Analyzer successfully started! Run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.\n";
  }

  if (arguments.find(arg_stop_analyzer) != arguments.end())
  { // analyzer stoped
    // Stop map_extractor
    // ContinExtrFlag_map_fd = bpf_map__fd(skel->maps.ContinExtrFlag);
    // ContinExtrFlag_map_fd = bpf_object__find_map_fd_by_name(skel->obj, "ContinExtrFlag");

    ContinExtrFlag_map_fd = bpf_obj_get(ContinExtrFlagPathName.c_str());

    printf("\n----------------------------------\n");
    printf("\nContinExtrFlag_map_fd: %d\n", ContinExtrFlag_map_fd);
    printf("\n----------------------------------\n");
    uint32_t ContinExtr_key = 0;
    uint8_t ContinExtr_val = 0;
    bpf_map_update_elem(ContinExtrFlag_map_fd, &ContinExtr_key, &ContinExtr_val, 0);

    // std::system((std::string("rm /sys/fs/bpf/") + ContinExtrFlagPathName.substr(ContinExtrFlagPathName.rfind('/') + 1)).c_str());

    // Unpin tracepoints handlers
    delete__handlers_and_links(skel);
    std::cout << "\n----------------------------------\n\nHandlers unpinned from BPF filesystem\n\n----------------------------------\n";
    std::cout << "Analyzer successfully stoped!\n";
  }
}

int main(int argc, char **argv)
{
  struct analyzer_bpf *skel;

  libbpf_set_print(libbpf_print_fn);

  skel = analyzer_bpf__open();

  //
  struct stat sb;
  if (stat("/proc/self/ns/pid", &sb) == -1)
  {
    fprintf(stderr, "Failed to acquire namespace information");
    return 1;
  }

  skel->bss->dev = sb.st_dev;
  skel->bss->ino = sb.st_ino;

  std::cout << "\n STAT: " << sb.st_dev << ' ' << sb.st_ino;
  //

  if (!skel)
  {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  // Processing arguments --------------
  process_arguments(argc, argv, skel);
  if (err)
  {
    return -cleanup(skel);
  }
}
