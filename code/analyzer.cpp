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

#include <iostream>
#include <fstream>
#include <string>


int SyscllStatMap_map_fd = -1;
int BaseTableMap_map_fd  = -1;
int ProgNormalTrace_map_fd = -1;
bool keep_maps_alive_after_exit = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

void read_and_fill_normal_traces_map()
{
  // Reading data about the normal operation of programs from a disk in a ProgNormalTrace map  --------------
  std::ifstream inf("programs_traces.txt");
  if (!inf)
  {
    std::cerr << "programs_traces.txt could not be opened for reading!\n";
    exit(1);
  }
  
  struct ProgNameType key1 = {};
  struct ProgSyscallsListType val1 = {};
  
  while (inf) {
    std::string traceStr, progName, currentSyscallNumber;
    std::getline(inf, traceStr);
  
    int leftSpacePos = traceStr.find(' ');
    int rightSpacePos = leftSpacePos;
    
    progName = traceStr.substr(0, leftSpacePos);
    progName.copy(key1.proc_name, progName.length());
    std::cout << "name: " << progName << '\n' << "calls: " << std::endl;
    
    while (leftSpacePos != std::string::npos) {
      rightSpacePos = traceStr.find(' ', leftSpacePos + 1);
      
      currentSyscallNumber = traceStr.substr(leftSpacePos + 1, rightSpacePos - leftSpacePos - 1);
      std::cout << stoi(currentSyscallNumber) << ' ' << std::endl;
      
      val1.is_syscall_typical[stoi(currentSyscallNumber) / 8] |= (1 << (stoi(currentSyscallNumber) % 8));
      
      leftSpacePos = rightSpacePos;
    }
    
    std::cout << '\n';
    
    bpf_map_update_elem(ProgNormalTrace_map_fd, &key1, &val1, 0);
    
    memset(&key1, 0, sizeof(key1));
    memset(&val1, 0, sizeof(val1));
  }
}


void write_normal_traces_map_in_file()
{
  // Writing data about the normal operation of programs from a ProgNormalTrace map in a disk  --------------
  std::ofstream outf("programs_traces.txt");
  if (!outf)
  {
    std::cerr << "programs_traces.txt could not be opened for writing!\n";
    exit(1);
  }
  
  struct ProgNameType key1 = {};
  struct ProgNameType key2 = {};
  
  int ret = bpf_map_get_next_key(ProgNormalTrace_map_fd, NULL, &key2);
  int new_line_counter = 0;

  while (ret != -ENOENT) {
    struct ProgSyscallsListType val1 = {};
    key1 = key2;
    ret = bpf_map_get_next_key(ProgNormalTrace_map_fd, &key1, &key2);
      
    bpf_map_lookup_elem(ProgNormalTrace_map_fd, &key1, &val1);
    
    std::string traceStr = key1.proc_name;
    
    for (int i = 0; i < (8 * sizeof(val1)); i++)
      if ((val1.is_syscall_typical[i / 8] & (1 << (i % 8))) != 0)
        traceStr += (" " + std::to_string(i));
    
    if (ret != -ENOENT)
      traceStr += "\n";
    
    outf << traceStr;
  }
}

void attach_handlers_to_syscalls(struct analyzer_bpf *skel)
{
  // Reading data about relevant syscalls from file  --------------
  std::ifstream inf("relevant_syscalls.txt");
  if (!inf)
  {
    std::cerr << "relevant_syscalls.txt could not be opened for reading!\n";
    exit(1);
  }
  
  std::string currentString;
  
  while (inf) {
    std::getline(inf, currentString);
    
    if (currentString.length() > 0 && currentString.back() == '-')
    {
      currentString = currentString.substr(0, currentString.find('-'));
      std::cout << "\'" << currentString << "\' will be traced\n";
      
      bpf_program__attach_tracepoint(skel->progs.handle_tp_enter, "syscalls", (std::string("sys_enter_") + currentString).c_str());
      
      bpf_program__attach_tracepoint(skel->progs.handle_tp_exit, "syscalls", (std::string("sys_exit_") + currentString).c_str());
    }
  }
}


void delete_maps(struct analyzer_bpf *skel) 
{
  bpf_map__unpin(skel->maps.BaseTableMap, "/sys/fs/bpf/BaseTableMap");
  bpf_map__unpin(skel->maps.SyscllStatMap, "/sys/fs/bpf/SyscllStatMap");
  bpf_map__unpin(skel->maps.ProgNormalTrace, "/sys/fs/bpf/ProgNormalTrace");
}

int main(int argc, char **argv)
{
	struct analyzer_bpf *skel;
	int err;

        libbpf_set_print(libbpf_print_fn);

	skel = analyzer_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
         
// Base Table --------------
        BaseTableMap_map_fd = bpf_obj_get("/sys/fs/bpf/BaseTableMap");
        
        bool not_found_BaseTableMap = (BaseTableMap_map_fd < 0);
        printf("\n----------------------------------\n");
        printf("\nBaseTableMap_map_fd: %d\n", BaseTableMap_map_fd);
        printf("\n----------------------------------\n");
        
        if (not_found_BaseTableMap) {
          printf("\n----------------------------------\n");
          printf("\nPinned map BaseTableMap NOT FOUND\n");
          printf("\nCreating new ...\n");
          printf("\n----------------------------------\n");
          
          BaseTableMap_map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, 
                                              "BaseTableMap", 
                                               sizeof(uint32_t), 
                                               sizeof(struct BaseTableEntry), 
                                               skel->rodata->max_entries_BaseTableMap_c, 0);
        }
         
        bpf_map__reuse_fd(skel->maps.BaseTableMap, BaseTableMap_map_fd);
      
        if (not_found_BaseTableMap)
          bpf_map__pin(skel->maps.BaseTableMap, "/sys/fs/bpf/BaseTableMap");
          
          
// Syscall Statistic --------------
        SyscllStatMap_map_fd = bpf_obj_get("/sys/fs/bpf/SyscllStatMap");
        
        bool not_found_SyscllStatMap = (SyscllStatMap_map_fd < 0);
        printf("\n----------------------------------\n");
        printf("SyscllStatMap_map_fd: %d\n", SyscllStatMap_map_fd);
        printf("\n----------------------------------\n");
        
        if (not_found_SyscllStatMap) {
          printf("\n----------------------------------\n");
          printf("\nPinned map SyscllStatMap NOT FOUND\n");
          printf("\nCreating new ...\n");
          printf("\n----------------------------------\n");
          
          SyscllStatMap_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, 
                                              "SyscllStatMap", 
                                               sizeof(uint64_t), 
                                               sizeof(uint64_t), 
                                               skel->rodata->max_entries_SyscllStat_c, 0);
        }
         
        bpf_map__reuse_fd(skel->maps.SyscllStatMap, SyscllStatMap_map_fd);
      
        if (not_found_SyscllStatMap)
          bpf_map__pin(skel->maps.SyscllStatMap, "/sys/fs/bpf/SyscllStatMap");
        
              
        
        
// Programs Normal Trace table --------------
        ProgNormalTrace_map_fd = bpf_obj_get("/sys/fs/bpf/ProgNormalTrace");
        
        bool not_found_ProgNormalTrace = (ProgNormalTrace_map_fd < 0);
        printf("\n----------------------------------\n");
        printf("\ProgNormalTrace_map_fd: %d\n", ProgNormalTrace_map_fd);
        printf("\n----------------------------------\n");
        
        if (not_found_ProgNormalTrace) {
          printf("\n----------------------------------\n");
          printf("\nPinned map ProgNormalTrace NOT FOUND\n");
          printf("\nCreating new ...\n");
          printf("\n----------------------------------\n");
          
          ProgNormalTrace_map_fd = bpf_map_create(BPF_MAP_TYPE_HASH, 
                                              "ProgNormalTrace", 
                                               sizeof(struct ProgNameType), 
                                               sizeof(struct ProgSyscallsListType), 
                                               skel->rodata->max_entries_ProgNormalTrace_c, 0);
        }

        bpf_map__reuse_fd(skel->maps.ProgNormalTrace, ProgNormalTrace_map_fd);
      
        if (not_found_ProgNormalTrace)
          bpf_map__pin(skel->maps.ProgNormalTrace, "/sys/fs/bpf/ProgNormalTrace");        
    
    
        
        printf("\n----------------------------------\n");
        printf("\nAttached to pinned maps\n");
        printf("\n----------------------------------\n");
      
      
// Processing arguments --------------
        if (argc % 2 == 0 && argv[argc - 1][0] == 's') { // save maps
          keep_maps_alive_after_exit = true;
          
          printf("\n----------------------------------\n");
          printf("\nMaps will be saved in bpf filesystem after exit\n");
          printf("\n----------------------------------\n");
        }
          
        if (argc >= 3) {
          if (argv[1][0] == 'p') { // process
            uint64_t PD_to_track = atoll(argv[2]);
            
            skel->bss->to_track_value = PD_to_track;
            skel->bss->tracking_type = 2;
            
	    printf("\n----------------------------------\n");
            printf("\nTracking PID: %llu\n", PD_to_track);
            printf("\n----------------------------------\n");
          }
          else if (argv[1][0] == 'u') { // user
            uint64_t UD_to_track = atoll(argv[2]);
            
            skel->bss->to_track_value = UD_to_track;
            skel->bss->tracking_type = 1;
            
            printf("\n----------------------------------\n");
            printf("\nTracking UID: %llu\n", UD_to_track);
            printf("\n----------------------------------\n");
          }
          else if (argv[1][0] == 'l') { // learning
            skel->bss->tracking_type = 3;
            strcpy(skel->bss->tracking_program_n_a_name, argv[2]);
            
            printf("\n----------------------------------\n");
            printf("Tracking of \"%s\" program normal behaviour\n", argv[2]);
            printf("\n----------------------------------\n");
          }
	}
 
// Reading data about the normal operation of programs from a disk in a ProgNormalTrace map  --------------
 
        read_and_fill_normal_traces_map();

// Load & verify BPF programs
	err = analyzer_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

// Attach tracepoints handler 
	err = analyzer_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
	
	attach_handlers_to_syscalls(skel);
        
	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

// Activity
	getchar(); // finishing

        write_normal_traces_map_in_file();
        
        if(!keep_maps_alive_after_exit)
          delete_maps(skel);
cleanup:
	analyzer_bpf__destroy(skel);
	return -err;
}
