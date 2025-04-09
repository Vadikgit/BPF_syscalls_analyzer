// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <chrono>
#include <thread>
#include <sys/resource.h>
#include <../bpf_process_tree_builder_saving/code/bpf/libbpf.h>
#include <../bpf_process_tree_builder_saving/code/bpf/bpf.h>
#include <fstream>
#include <vector>
#include <iomanip>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int TestMap1_fd = -1;
int TestMap2_fd = -1;
int TestMap3_fd = -1;
int TestMap4_fd = -1;
int TestMap5_fd = -1;
int TestMap6_fd = -1;
uint32_t NumberOfValues = 1'000'000;

std::string TestMap1Name = "TestMap1";
std::string TestMap2Name = "TestMap2";
std::string TestMap3Name = "TestMap3";
std::string TestMap4Name = "TestMap4";
std::string TestMap5Name = "TestMap5";
std::string TestMap6Name = "TestMap6";

int main(int argc, char **argv)
{
	std::chrono::time_point<std::chrono::system_clock> t1, t2;

	TestMap1_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, TestMap1Name.c_str(), sizeof(uint32_t), sizeof(uint32_t), NumberOfValues, 0);
	TestMap2_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, TestMap2Name.c_str(), sizeof(uint32_t), sizeof(uint32_t), NumberOfValues, 0);
	TestMap3_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, TestMap3Name.c_str(), sizeof(uint32_t), sizeof(uint32_t) * NumberOfValues, 1, 0);

	std::cout << "\n----------------------------------\n"
			  << TestMap1Name
			  << " file descriptor: " << TestMap1_fd << "\n----------------------------------\n"
			  << TestMap2Name
			  << " file descriptor: " << TestMap2_fd << "\n----------------------------------\n"
			  << TestMap3Name
			  << " file descriptor: " << TestMap3_fd << "\n----------------------------------\n";

	t1 = std::chrono::system_clock::now();

	for (uint32_t i = 0; i < NumberOfValues; i++)
	{
		bpf_map_update_elem(TestMap1_fd, &i, &i, 0);
		//		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		// bpf_map_lookup_elem(ContinExtrFlag_map_fd, &extrcontkey, &repeat_condition);
	}

	t2 = std::chrono::system_clock::now();

	std::cout << "\nTime of single insertions into array: \t" << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() << " mcs, "
			  << sizeof(uint32_t) * NumberOfValues << " bytes, "
			  << double(sizeof(uint32_t) * NumberOfValues) / (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()) << " bytes/mcs ---------------------------------- | " << std::endl;

	///////////////////////////////////////////////////////////////////////////

	std::vector<uint32_t> keys_a(NumberOfValues, 0);
	std::vector<uint32_t> vals_a(NumberOfValues, 0);
	for (uint32_t i = 0; i < NumberOfValues; i++)
	{
		keys_a[i] = i;
		vals_a[i] = i;
	}

	t1 = std::chrono::system_clock::now();

	bpf_map_update_batch(TestMap2_fd, &(keys_a[0]), &(vals_a[0]), &NumberOfValues, 0);

	t2 = std::chrono::system_clock::now();

	std::cout << "\nTime of batch insertion into array: \t" << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() << " mcs, "
			  << sizeof(uint32_t) * NumberOfValues << " bytes, "
			  << double(sizeof(uint32_t) * NumberOfValues) / (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()) << " bytes/mcs ---------------------------------- | " << std::endl;

	///////////////////////////////////////////////////////////////////////////
	uint32_t key_a = 0;
	std::vector<uint32_t> vals_a2(NumberOfValues, 0);

	t1 = std::chrono::system_clock::now();

	for (uint32_t i = 0; i < NumberOfValues; i++)
	{
		vals_a2[i] = i;
	}

	bpf_map_update_elem(TestMap3_fd, &key_a, &(vals_a2[0]), 0);

	t2 = std::chrono::system_clock::now();

	std::cout << "\nTime of single insertion of block into array: \t" << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() << " mcs, "
			  << sizeof(uint32_t) * NumberOfValues << " bytes, "
			  << double(sizeof(uint32_t) * NumberOfValues) / (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()) << " bytes/mcs ---------------------------------- | " << std::endl;

	// std::this_thread::sleep_for(std::chrono::milliseconds(10000));

	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////
	///////////////////////////////////////////////////////////////////////////

	TestMap4_fd = bpf_map_create(BPF_MAP_TYPE_HASH, TestMap4Name.c_str(), sizeof(uint32_t), sizeof(uint32_t), NumberOfValues, 0);
	TestMap5_fd = bpf_map_create(BPF_MAP_TYPE_HASH, TestMap5Name.c_str(), sizeof(uint32_t), sizeof(uint32_t), NumberOfValues, 0);
	TestMap6_fd = bpf_map_create(BPF_MAP_TYPE_HASH, TestMap6Name.c_str(), sizeof(uint32_t), sizeof(uint32_t) * NumberOfValues, 1, 0);

	std::cout << "\n----------------------------------\n"
			  << TestMap4Name
			  << " file descriptor: " << TestMap4_fd << "\n----------------------------------\n"
			  << TestMap5Name
			  << " file descriptor: " << TestMap5_fd << "\n----------------------------------\n"
			  << TestMap6Name
			  << " file descriptor: " << TestMap6_fd << "\n----------------------------------\n";

	t1 = std::chrono::system_clock::now();

	for (uint32_t i = 0; i < NumberOfValues; i++)
	{
		bpf_map_update_elem(TestMap4_fd, &i, &i, 0);
		//		std::this_thread::sleep_for(std::chrono::milliseconds(500));
		// bpf_map_lookup_elem(ContinExtrFlag_map_fd, &extrcontkey, &repeat_condition);
	}

	t2 = std::chrono::system_clock::now();

	std::cout << "\nTime of single insertions into hashtable: \t" << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() << " mcs, "
			  << sizeof(uint32_t) * NumberOfValues << " bytes, "
			  << double(sizeof(uint32_t) * NumberOfValues) / (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()) << " bytes/mcs ---------------------------------- | " << std::endl;

	///////////////////////////////////////////////////////////////////////////

	std::vector<uint32_t> keys_h(NumberOfValues, 0);
	std::vector<uint32_t> vals_h(NumberOfValues, 0);
	for (uint32_t i = 0; i < NumberOfValues; i++)
	{
		keys_h[i] = i;
		vals_h[i] = i;
	}

	t1 = std::chrono::system_clock::now();

	bpf_map_update_batch(TestMap5_fd, &(keys_h[0]), &(vals_h[0]), &NumberOfValues, 0);

	t2 = std::chrono::system_clock::now();

	std::cout << "\nTime of batch insertion into hashtable: \t" << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() << " mcs, "
			  << sizeof(uint32_t) * NumberOfValues << " bytes, "
			  << double(sizeof(uint32_t) * NumberOfValues) / (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()) << " bytes/mcs ---------------------------------- | " << std::endl;

	///////////////////////////////////////////////////////////////////////////
	uint32_t key_h = 0;
	std::vector<uint32_t> vals_h2(NumberOfValues, 0);

	t1 = std::chrono::system_clock::now();

	for (uint32_t i = 0; i < NumberOfValues; i++)
	{
		vals_h2[i] = i;
	}

	bpf_map_update_elem(TestMap6_fd, &key_h, &(vals_h2[0]), 0);

	t2 = std::chrono::system_clock::now();

	std::cout << "\nTime of single insertion of block into hashtable: \t" << std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count() << " mcs, "
			  << sizeof(uint32_t) * NumberOfValues << " bytes, "
			  << double(sizeof(uint32_t) * NumberOfValues) / (std::chrono::duration_cast<std::chrono::microseconds>(t2 - t1).count()) << " bytes/mcs ---------------------------------- | " << std::endl;

	// std::this_thread::sleep_for(std::chrono::milliseconds(10000));

	return 0;
}
