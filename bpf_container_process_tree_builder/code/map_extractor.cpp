// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fstream>
#include <vector>
#include "structs.h"
#include <iomanip>


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

void printTimestamp(){
	std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
	std::time_t now_c = std::chrono::system_clock::to_time_t(now);
	std::cout << std::put_time(std::localtime(&now_c), "%Y-%m-%d %X");
}

int main(int argc, char **argv)
{
	int err;

		int BaseTableMap_map_fd = bpf_obj_get("/sys/fs/bpf/BaseTableMap");
        int SeqNums_map_fd = bpf_obj_get("/sys/fs/bpf/SeqNums");
        int ContinExtrFlag_map_fd = bpf_obj_get("/sys/fs/bpf/ContinExtrFlag");

        bool not_found_map = ((BaseTableMap_map_fd < 0) || (SeqNums_map_fd < 0) || (ContinExtrFlag_map_fd < 0));
        std::cout << "\n----------------------------------\n" << "BaseTableMap_map_fd: " << BaseTableMap_map_fd;
        std::cout << "\nSeqNums_map_fd: " << SeqNums_map_fd;
        std::cout << "\nContinExtrFlag_map_fd: " << ContinExtrFlag_map_fd << "\n---------------------------------- | ";

        printTimestamp();
        std::cout << '\n';

        if (not_found_map) {
          std::cout << "\n----------------------------------\n" << "\nPinned map NOT FOUND\n" << "\nExiting\n" << "\n----------------------------------\n";
          return 0;
        }

        uint64_t extract_offset = 250000;

        int fileCtr = 0, iterctr = 0;

        bool repeat_condition = true;
        uint32_t extrcontkey = 0;

        while(repeat_condition)
        {
        	uint32_t seqnumkey = 0;
        	uint64_t glob_num;
        	uint64_t next_saving_num;
        	uint64_t base_table_entries;

        	bpf_map_lookup_elem(SeqNums_map_fd, &seqnumkey, &glob_num);

        	seqnumkey = 1;
        	bpf_map_lookup_elem(SeqNums_map_fd, &seqnumkey, &next_saving_num);
        	seqnumkey = 2;
        	bpf_map_lookup_elem(SeqNums_map_fd, &seqnumkey, &base_table_entries);

        	std::cout << "\nEntry global number: " << glob_num << ";";
        	std::cout << "\tNext saving global number: " << next_saving_num << ";";
        	std::cout << "\tExtractor iteration Counter: " << iterctr << " ---------------------------------- | ";
        	printTimestamp();
        	std::cout << '\n';


        	if((glob_num - next_saving_num) >= extract_offset){
        		std::string filename = std::string("binfiles/file") + std::to_string(fileCtr) + std::string(".bin");
        		fileCtr++;

        		std::ofstream outf(filename, std::ios::binary);

        		std::chrono::time_point<std::chrono::system_clock> t1, t2;

        		std::cout << "\nStart of extracting in " << filename << " ---------------------------------- | ";
        		printTimestamp();
        		std::cout << '\n';

        		t1 = std::chrono::system_clock::now();

        		std::vector<BaseTableEntry> arr;
        		arr.resize(extract_offset);

        		for (uint32_t i = next_saving_num; i < (extract_offset + next_saving_num); i++){
        			uint32_t arr_key = (i % base_table_entries);
        			bpf_map_lookup_elem(BaseTableMap_map_fd, &arr_key, &arr[i - next_saving_num]);
        		}

        		outf.write((char*)&arr[0], sizeof(arr[0]) * extract_offset);

        		seqnumkey = 1;
        		next_saving_num += extract_offset;
        		bpf_map_update_elem(SeqNums_map_fd, &seqnumkey, &next_saving_num, 0);

        		t2 = std::chrono::system_clock::now();

        		std::cout << "\nEnd of extracting in " << filename << "\t" << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << " ms, "
        		          << sizeof(BaseTableEntry) * extract_offset << " bytes, "
        		          << double(std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count()) / (sizeof(BaseTableEntry) * extract_offset) << " ms/byte ---------------------------------- | ";
        		printTimestamp();
        		std::cout << '\n';
        	}

        	std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        	bpf_map_lookup_elem(ContinExtrFlag_map_fd, &extrcontkey, &repeat_condition);

        	iterctr++;
        }

        return 0;
}
