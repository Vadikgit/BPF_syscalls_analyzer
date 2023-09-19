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


int BaseTableMap_map_fd  = -1;
int SyscllStatMap_map_fd = -1;
int ProgNormalTrace_map_fd = -1;

std::string BaseTableMapPathName = "/sys/fs/bpf/BaseTableMap";
std::string SyscllStatMapPathName = "/sys/fs/bpf/SyscllStatMap";
std::string ProgNormalTracePathName = "/sys/fs/bpf/ProgNormalTrace";

const std::string arg_save_maps_after_exit = "-s";
const std::string arg_learn_program_behaviour = "-l";
const std::string arg_specify_process_to_catch_syscalls = "-p";
const std::string arg_specify_user_to_catch_syscalls = "-u";

std::unordered_map<std::string, std::vector<std::string>> arguments;

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

void create_or_reuse_map(std::string pathName, bpf_map_type mapType, uint32_t keySize, uint32_t valSize,
						 uint64_t maxEntries, struct bpf_map * mapPointerInScel, int & mapFd){

	mapFd = bpf_obj_get(pathName.c_str());

	bool notFoundMap = (mapFd < 0);

	std::cout << "\n----------------------------------\n" << pathName
			  << " file descriptor: " << mapFd << "\n----------------------------------\n";

	if (notFoundMap) {
		std::cout << "\n----------------------------------\n\nPinned map " << pathName
				  << " NOT FOUND\n\nCreating new ...\n\n----------------------------------\n";

		mapFd = bpf_map_create(mapType, pathName.substr(pathName.rfind('/') + 1).c_str(), keySize, valSize, maxEntries, 0);
	}

	bpf_map__reuse_fd(mapPointerInScel, mapFd);

	if (notFoundMap)
	     bpf_map__pin(mapPointerInScel, pathName.c_str());
}

void delete_maps(struct analyzer_bpf *skel) 
{
  bpf_map__unpin(skel->maps.BaseTableMap, BaseTableMapPathName.c_str());
  bpf_map__unpin(skel->maps.SyscllStatMap, SyscllStatMapPathName.c_str());
  bpf_map__unpin(skel->maps.ProgNormalTrace, ProgNormalTracePathName.c_str());
}

void process_arguments(int argc, char **argv, struct analyzer_bpf *skel)
{
	std::string key;
    for(int i = 1; i < argc; i++){
    	if(argv[i][0] == '-'){
    		key = argv[i];
    		auto it = arguments.find(key);

    		if (it == arguments.end())
    			arguments[key] = {};
    	}
    	else {
    		arguments[key].push_back(argv[i]);
    	}
    }

    if (arguments.find(arg_save_maps_after_exit) != arguments.end()) { // save maps
    	keep_maps_alive_after_exit = true;
        std::cout << "\n----------------------------------\n\nMaps will be saved in bpf filesystem after exit\n\n----------------------------------\n";
    }

    if (arguments.find(arg_specify_process_to_catch_syscalls) != arguments.end() &&
    	arguments[arg_specify_process_to_catch_syscalls].empty() == false) { // process
    	try
    	{
    		uint64_t PD_to_track = std::stoll(arguments[arg_specify_process_to_catch_syscalls][0]);

    		skel->bss->to_track_value = PD_to_track;
    		skel->bss->tracking_type = 2;

    		std::cout << "\n----------------------------------\n\nTracking PID: " << PD_to_track
    		          << "\n\n----------------------------------\n";
    	}
    	catch (std::invalid_argument const& ex)
    	{
    	    std::cout << ex.what() << '\n';
    	}
    }

    if (arguments.find(arg_specify_user_to_catch_syscalls) != arguments.end() &&
    	arguments[arg_specify_user_to_catch_syscalls].empty() == false) { // user
       	try
       	{
       		uint64_t UD_to_track = std::stoll(arguments[arg_specify_user_to_catch_syscalls][0]);

       		skel->bss->to_track_value = UD_to_track;
       		skel->bss->tracking_type = 1;

        	std::cout << "\n----------------------------------\n\nTracking UID: " << UD_to_track
        			  << "\n\n----------------------------------\n";
        	}
        	catch (std::invalid_argument const& ex)
        	{
        	    std::cout << ex.what() << '\n';
        	}
    }

    if (arguments.find(arg_learn_program_behaviour) != arguments.end() &&
        arguments[arg_learn_program_behaviour].empty() == false) { // learning

    	skel->bss->tracking_type = 3;
    	std::string progName = arguments[arg_learn_program_behaviour][0];
    	progName.copy(skel->bss->tracking_program_n_a_name, progName.length());

    	std::cout << "\n----------------------------------\n\nTracking of " << arguments[arg_learn_program_behaviour][0]
    	          << " program normal behaviour\n\n----------------------------------\n";
    }
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
         
// Preparing BPF maps --------------
	create_or_reuse_map(BaseTableMapPathName, BPF_MAP_TYPE_ARRAY, sizeof(uint32_t), sizeof(struct BaseTableEntry),
						skel->rodata->max_entries_BaseTableMap_c, skel->maps.BaseTableMap, BaseTableMap_map_fd); // Base Table
	create_or_reuse_map(SyscllStatMapPathName, BPF_MAP_TYPE_HASH, sizeof(uint64_t), sizeof(uint64_t),
						skel->rodata->max_entries_SyscllStat_c, skel->maps.SyscllStatMap, SyscllStatMap_map_fd); // Syscall Statistic
	create_or_reuse_map(ProgNormalTracePathName, BPF_MAP_TYPE_HASH, sizeof(struct ProgNameType), sizeof(struct ProgSyscallsListType),
						skel->rodata->max_entries_ProgNormalTrace_c, skel->maps.ProgNormalTrace, ProgNormalTrace_map_fd); // Programs Normal Traces
        
    std::cout << "\n----------------------------------\n\nAttached to pinned maps\n\n----------------------------------\n";
      
      
// Processing arguments --------------
    process_arguments(argc, argv, skel);
 
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
