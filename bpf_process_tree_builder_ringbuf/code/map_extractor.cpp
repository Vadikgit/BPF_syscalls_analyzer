// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <ev.h>
#include <amqpcpp.h>
#include <amqpcpp/libev.h>
#include <amqpcpp/linux_tcp.h>
#include <stdlib.h>

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
#include <string>
#include "structs.h"
#include <iomanip>

#define PERF_TEST_MODE
// #define LOGGING
#define PUSHING_TO_RABBITMQ

uint64_t idsCounter = 0;
uint64_t lastGotId = 0;
uint64_t pollIterationsCounter = 0;

std::string ContinExtrFlagPathName = "/sys/fs/bpf/ContinExtrFlag";

#ifdef PUSHING_TO_RABBITMQ
AMQP::TcpChannel *channel;
std::string nodeNameDetermineCommandResult;
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void printTimestamp()
{
	std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
	std::time_t now_c = std::chrono::system_clock::to_time_t(now);
	std::cout << std::put_time(std::localtime(&now_c), "%Y-%m-%d %X");
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
#ifdef LOGGING
	std::cout << "global_id: " << ((BaseTableEntry *)data)->global_id << ", data size: " << data_sz << std::endl;
#endif

#ifdef PERF_TEST_MODE
	idsCounter += ((BaseTableEntry *)data)->global_id;
	lastGotId = ((BaseTableEntry *)data)->global_id;
#endif

#ifdef PERF_TEST_MODE
	channel->startTransaction();

	channel->publish("my-exchange", nodeNameDetermineCommandResult.c_str(), (char *)data, data_sz, 0);

	channel->commitTransaction().onSuccess([]() {}).onError([](const char *message) {});
#endif
	return 0;
}

uint32_t extrcontkey = 0;
bool continue_flag = true;

int main(int argc, char **argv)
{
	int err;
	int BaseTableBuf_map_id = -1;
	int ContinExtrFlag_map_id = -1;

	if (argc < 3)
	{
		std::cout << "\n----------------------------------\n"
				  << "\nMap(s) ids not specified\n"
				  << "\nExiting\n"
				  << "\n----------------------------------\n";
		return 0;
	}

	BaseTableBuf_map_id = std::stoll(argv[1]);
	ContinExtrFlag_map_id = std::stoll(argv[2]);

	int BaseTableBuf_map_fd = bpf_map_get_fd_by_id(BaseTableBuf_map_id);
	int ContinExtrFlag_map_fd = bpf_map_get_fd_by_id(ContinExtrFlag_map_id);

	bool not_found_map = (BaseTableBuf_map_fd < 0 || ContinExtrFlag_map_fd < 0);
	std::cout << "\n----------------------------------\n"
			  << "BaseTableBuf_map_fd: " << BaseTableBuf_map_fd
			  << "\nContinExtrFlag_map_fd: " << ContinExtrFlag_map_fd;
	std::cout << "\n---------------------------------- | ";

	printTimestamp();
	std::cout << '\n';

	if (not_found_map)
	{
		std::cout << "\n----------------------------------\n"
				  << "\nMap(s) NOT FOUND\n"
				  << "\nExiting\n"
				  << "\n----------------------------------\n";
		return 0;
	}

	struct ring_buffer *rb = NULL;

	rb = ring_buffer__new(BaseTableBuf_map_fd, handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
	}

#ifdef PUSHING_TO_RABBITMQ
	// get RabbitMQ server address
	std::string rabbitmqServerAddress;
	const char *rabbitmqServerAddressValue = std::getenv("RABBITMQ_SERVER_ADDRESS");

	if (rabbitmqServerAddressValue != nullptr)
	{
		std::cout << "\n<<<<<<\nDetermined RabbitMQ server address:\n\t" << rabbitmqServerAddressValue << "\n>>>>>>\n\n"
				  << std::endl;
		rabbitmqServerAddress = std::string(rabbitmqServerAddressValue);
	}
	else
	{
		std::cout << "RABBITMQ_SERVER_ADDRESS environment variable is not set. Exiting" << std::endl;
		//		return 0;
		rabbitmqServerAddress = "51.250.11.63";
	}

	// get hostname
	char *nodeNameDetermineCommand = "hostname";

	char buf[BUFSIZ];
	FILE *ptr;

	if ((ptr = popen(nodeNameDetermineCommand, "r")) != NULL)
		while (fgets(buf, BUFSIZ, ptr) != NULL)
			nodeNameDetermineCommandResult = nodeNameDetermineCommandResult + std::string(buf);

	pclose(ptr);

	std::cout << "\n<<<<<<\nDetermined node name:\n\t" << nodeNameDetermineCommandResult << "\n>>>>>>\n"
			  << std::endl;

	// access to the event loop
	std::string rabbitmqConnString = std::string("amqp://guest:guest@") + rabbitmqServerAddress + std::string(":5672/");
	auto *loop = EV_DEFAULT;

	AMQP::LibEvHandler handler(loop);
	AMQP::TcpConnection connection(&handler, AMQP::Address(rabbitmqConnString.c_str()));
	channel = new AMQP::TcpChannel(&connection);

	std::thread t1([=]()
				   { ev_run(loop, 0); });

	channel->declareExchange("my-exchange", AMQP::fanout);
	channel->declareQueue("my-queue");
	channel->bindQueue("my-exchange", "my-queue", "my-routing-key");

#endif

	try
	{
		while (continue_flag == true)
		{
// std::cout << "\tExtractor iteration Counter: " << iterctr << " ---------------------------------- | ";
// printTimestamp();
// std::cout << '\n'
#ifdef LOGGING
			std::cout << "iteration " << iterctr << " ["
					  << std::endl;
#endif
			err = ring_buffer__poll(rb, 100);

			if (err < 0)
			{
				printf("Error polling ring buffer: %d\n", err);
				break;
			}
			// std::this_thread::sleep_for(std::chrono::milliseconds(1000));
			bpf_map_lookup_elem(ContinExtrFlag_map_fd, &extrcontkey, &continue_flag);
			pollIterationsCounter++;

#ifdef LOGGING
			std::cout << "\n]"
					  << std::endl;
#endif
		}

		ring_buffer__free(rb);
	}

	catch (const std::exception &e)
	{
		std::cerr << e.what() << '\n';
	}

#ifdef PERF_TEST_MODE
	std::cout << "\n\nIDs counter: " << idsCounter << std::endl;
	std::cout << "Last got ID: " << lastGotId << std::endl;
	std::cout << "(lastGotId * (lastGotId + 1) / 2 = " << (lastGotId * (lastGotId + 1)) / 2 << std::endl;
	std::cout << "Poll iterations counter: " << pollIterationsCounter << "; syscalls per iteration: " << double(lastGotId) / pollIterationsCounter << std::endl;
#endif

	// std::system(std::string("rm extractorlog.txt").c_str());
	std::system((std::string("rm /sys/fs/bpf/") + ContinExtrFlagPathName.substr(ContinExtrFlagPathName.rfind('/') + 1)).c_str());

#ifdef PUSHING_TO_RABBITMQ
	t1.detach();
	delete channel;
#endif

	return 0;
}