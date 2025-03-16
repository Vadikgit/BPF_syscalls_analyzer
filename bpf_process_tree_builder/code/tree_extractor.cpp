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
#include <list>
#include <vector>
#include "structs.h"
#include <iomanip>
#include <unordered_map>
#include <algorithm>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

struct TreeNode
{
	pid_t pid;
	std::string commName;

	TreeNode *parent;
	TreeNode *leftSon;
	TreeNode *rightBro;
};

void recPrintTree(TreeNode *root, std::string &printString, std::string &broString, int max_info_string_len)
{
	if (root != nullptr)
	{
		std::string infoString = std::to_string(root->pid) + " [" + root->commName + "]";
		infoString = infoString + std::string(max_info_string_len - infoString.length(), ' ');

		if (root->leftSon == nullptr)
		{
			// std::cout << printString << "OOOOOOO\n";
			//  std::cout << printString << "O\n";
			std::cout << printString << infoString << "\n";

			if (broString.find('|') != std::string::npos)
				std::cout << broString << "\n";

			return;
		}

		std::string tempPrintString = printString;

		TreeNode *son = root->leftSon;
		// printString.append("OOOOOOO ------> ");
		// broString.append("                ");
		//  printString.append("O ------> ");
		//  broString.append("          ");
		printString.append(infoString).append(" ------> ");
		broString.append(std::string(infoString.length(), ' ')).append("         ");

		if (root->leftSon->rightBro != nullptr)
			broString.back() = '|';

		while (son != nullptr)
		{
			if (son->rightBro == nullptr)
				broString.back() = ' ';

			recPrintTree(son, printString, broString, max_info_string_len);
			printString = broString.substr(0, printString.length());

			son = son->rightBro;
		}

		// broString = broString.substr(0, broString.length() - std::string("          ").length());
		// broString = broString.substr(0, broString.length() - std::string("                ").length());
		broString = broString.substr(0, broString.length() - std::string("         ").length() - infoString.length());

		printString = tempPrintString;
	}
}

void printTree(TreeNode *root, int max_info_string_len)
{
	std::string printString = "";
	std::string broString = " ";
	std::cout << "\n";
	recPrintTree(root, printString, broString, max_info_string_len);
}

void treeGen(std::vector<TreeNode> &Tree, std::unordered_map<pid_t, uint64_t> &pidParents, std::unordered_map<pid_t, std::string> &pidName)
{
	std::unordered_map<pid_t, size_t> pidNodeId;

	std::vector<pid_t> pids;

	for (auto &pidParent : pidParents)
		pids.push_back(pidParent.first);

	std::sort(pids.begin(), pids.end());
	for (size_t i = 0; i < pids.size(); i++)
	{
		std::cout << pids[i] << " [" << pidName[pids[i]] << "]\n";
	}

	Tree.assign(pids.size(), {0, std::string(""), nullptr, nullptr, nullptr});

	for (size_t i = 0; i < pids.size(); i++)
	{
		Tree[i].pid = pids[i];
		Tree[i].commName = pidName[pids[i]];

		pidNodeId.emplace(pids[i], i);

		if (i > 0)
		{
			TreeNode &parentNode = Tree[pidNodeId[pidParents[pids[i]]]];
			TreeNode *parentLeftSon = parentNode.leftSon;

			Tree[pidNodeId[pidParents[pids[i]]]].leftSon = &(Tree[i]);
			Tree[i].rightBro = parentLeftSon;
		}
	}
}

int main(int argc, char **argv)
{
	int TGID_parent_map_id = -1;
	int TGID_comm_map_id = -1;

	if (argc < 3)
	{
		std::cout << "\n----------------------------------\n"
				  << "\nMap(s) ids not specified\n"
				  << "\nExiting\n"
				  << "\n----------------------------------\n";
		return 0;
	}

	TGID_parent_map_id = std::stoll(argv[1]);
	TGID_comm_map_id = std::stoll(argv[2]);

	int TGID_parent_map_fd = bpf_map_get_fd_by_id(TGID_parent_map_id);
	int TGID_comm_map_fd = bpf_map_get_fd_by_id(TGID_comm_map_id);

	bool not_found_map = ((TGID_parent_map_fd < 0) || (TGID_comm_map_fd < 0));
	std::cout << "\n----------------------------------\n"
			  << "TGID_parent_map_fd: " << TGID_parent_map_fd;
	std::cout << "\nTGID_comm_map_fd: " << TGID_comm_map_fd << "\n---------------------------------- | ";

	std::cout << '\n';

	if (not_found_map)
	{
		std::cout << "\n----------------------------------\n"
				  << "\nMap(s) NOT FOUND\n"
				  << "\nExiting\n"
				  << "\n----------------------------------\n";
		return 0;
	}

	pid_t *current_key = nullptr;
	pid_t parent_pid_key = 0;
	uint64_t parent_pid_value = 0;

	struct ProgNameType pid_comm_val = {};

	std::unordered_map<pid_t, uint64_t> pidParents;
	std::unordered_map<pid_t, std::string> pidName;

	while (bpf_map_get_next_key(TGID_parent_map_fd, current_key, &parent_pid_key) == 0)
	{
		bpf_map_lookup_elem(TGID_parent_map_fd, &parent_pid_key, &parent_pid_value);
		bpf_map_lookup_elem(TGID_comm_map_fd, &parent_pid_key, &pid_comm_val);

		pidParents.emplace(parent_pid_key, parent_pid_value);
		pidName.emplace(parent_pid_key, std::string(pid_comm_val.proc_name));

		current_key = &parent_pid_key;
	}

	/*pidParents.emplace(1, 0);
	pidParents.emplace(2, 1);
	pidParents.emplace(3, 2);

	pidName.emplace(1, "pr1");
	pidName.emplace(2, "pr2");
	pidName.emplace(3, "pr3");*/

	for (auto pid : pidParents)
	{
		std::cout << ((pid.second << 32) >> 32) << " -> " << pid.first << " [" << pidName[pid.first] << "]\n";
	}

	std::vector<TreeNode> treeNodes;

	treeGen(treeNodes, pidParents, pidName);

	int max_info_string_len = 0;

	for (auto &pidObj : pidName)
	{
		std::string currentString = std::to_string(pidObj.first) + " [" + pidObj.second + "]";
		if (currentString.length() > max_info_string_len)
			max_info_string_len = currentString.length();
	}

	printTree(&(treeNodes[0]), max_info_string_len);

	/*while(repeat_condition)
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
	}*/

	return 0;
}
