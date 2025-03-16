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

void treeGen(std::vector<TreeNode> &Tree, std::unordered_map<pid_t, pid_t> &pidParents, std::unordered_map<pid_t, std::string> &pidName)
{
	std::unordered_map<pid_t, size_t> pidNodeId;

	std::vector<pid_t> pids;

	for (auto &pidParent : pidParents)
		pids.push_back(pidParent.first);

	std::sort(pids.begin(), pids.end());
	for (size_t i = 0; i < pids.size(); i++)
	{
		// std::cout << pids[i] << " [" << pidName[pids[i]] << "]\n";
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
	int TGID_root_map_id = -1;

	if (argc < 4)
	{
		std::cout << "\n----------------------------------\n"
				  << "\nMap(s) ids not specified\n"
				  << "\nExiting\n"
				  << "\n----------------------------------\n";
		return 0;
	}

	TGID_parent_map_id = std::stoll(argv[1]);
	TGID_root_map_id = std::stoll(argv[2]);
	TGID_comm_map_id = std::stoll(argv[3]);

	int TGID_parent_map_fd = bpf_map_get_fd_by_id(TGID_parent_map_id);
	int TGID_root_map_fd = bpf_map_get_fd_by_id(TGID_root_map_id);
	int TGID_comm_map_fd = bpf_map_get_fd_by_id(TGID_comm_map_id);

	bool not_found_map = ((TGID_parent_map_fd < 0) || (TGID_comm_map_fd < 0) || (TGID_root_map_fd < 0));
	std::cout << "\n----------------------------------\n"
			  << "TGID_parent_map_fd: " << TGID_parent_map_fd << "\nTGID_root_map_fd: " << TGID_root_map_fd;
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
	pid_t parent_pid_value = 0;
	pid_t root_pid_value = 0;

	struct ProgNameType pid_comm_val = {};

	std::unordered_map<pid_t, pid_t> pidParents;
	std::unordered_map<pid_t, pid_t> pidRoot;
	std::unordered_map<pid_t, std::string> pidName;

	while (bpf_map_get_next_key(TGID_parent_map_fd, current_key, &parent_pid_key) == 0)
	{
		bpf_map_lookup_elem(TGID_parent_map_fd, &parent_pid_key, &parent_pid_value);
		bpf_map_lookup_elem(TGID_root_map_fd, &parent_pid_key, &root_pid_value);
		bpf_map_lookup_elem(TGID_comm_map_fd, &parent_pid_key, &pid_comm_val);

		pidParents.emplace(parent_pid_key, parent_pid_value);
		pidRoot.emplace(parent_pid_key, root_pid_value);
		pidName.emplace(parent_pid_key, std::string(pid_comm_val.proc_name));

		current_key = &parent_pid_key;
	}

	for (auto pid : pidParents)
	{
		std::cout << pid.second << " -> " << pid.first << " [" << pidName[pid.first] << "], root pid: " << pidRoot[pid.first] << "\n";
	}

	std::unordered_map<pid_t, std::pair<std::unordered_map<pid_t, pid_t>, std::unordered_map<pid_t, std::string>>> parentsAndNamesGroubedByRootPid;

	for (auto pid : pidParents)
	{
		if (parentsAndNamesGroubedByRootPid.find(pidRoot[pid.first]) == parentsAndNamesGroubedByRootPid.end())
		{
			parentsAndNamesGroubedByRootPid.emplace(pidRoot[pid.first], std::make_pair(std::unordered_map<pid_t, pid_t>{}, std::unordered_map<pid_t, std::string>{}));
		}

		parentsAndNamesGroubedByRootPid[pidRoot[pid.first]].first.emplace(pid);
		parentsAndNamesGroubedByRootPid[pidRoot[pid.first]].second.emplace(pid.first, pidName[pid.first]);
	}

	std::cout << "\n=======================================================================\n=======================================================================\n";

	for (auto &parentsAndNames : parentsAndNamesGroubedByRootPid)
	{
		std::vector<TreeNode> treeNodes;

		treeGen(treeNodes, parentsAndNames.second.first, parentsAndNames.second.second);

		int max_info_string_len = 0;

		for (auto &pidObj : parentsAndNames.second.second)
		{
			std::string currentString = std::to_string(pidObj.first) + " [" + pidObj.second + "]";
			if (currentString.length() > max_info_string_len)
				max_info_string_len = currentString.length();
		}

		printTree(&(treeNodes[0]), max_info_string_len);
		std::cout << "\n=======================================================================\n=======================================================================\n";
	}

	return 0;
}
