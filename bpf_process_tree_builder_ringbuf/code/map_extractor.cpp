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
#include <algorithm>

#define PERF_TEST_MODE
// #define LOGGING
// #define PUSHING_TO_RABBITMQ
#define RABBITMQ_BUFFER_SIZE 2 * 67'108'864

uint64_t idsCounter = 0;
uint64_t lastGotId = 0;
uint64_t pollIterationsCounter = 0;
uint64_t successfullPollIterationsCounter = 0;
bool pollSuccessFlag = false;

std::string ContinExtrFlagPathName = "/sys/fs/bpf/ContinExtrFlag";

#ifdef PUSHING_TO_RABBITMQ
std::string nodeNameDetermineCommandResult;
uint8_t rabbitMqBuffer[RABBITMQ_BUFFER_SIZE];
size_t rabbitMqBufferFilledPartSize = 0;
size_t numberOfEntries = 0;

uint8_t hostnameBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t per_node_per_analyzer_run_idBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t syscall_numberBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t PIDBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t TGIDBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t UIDBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t GIDBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t core_idBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t returned_valueBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t enter_date_time_nsBuffer[RABBITMQ_BUFFER_SIZE / 8];
uint8_t exit_date_time_nsBuffer[RABBITMQ_BUFFER_SIZE / 8];

size_t hostnameBufferSize = 0;
size_t per_node_per_analyzer_run_idBufferSize = 0;
size_t syscall_numberBufferSize = 0;
size_t PIDBufferSize = 0;
size_t TGIDBufferSize = 0;
size_t UIDBufferSize = 0;
size_t GIDBufferSize = 0;
size_t core_idBufferSize = 0;
size_t returned_valueBufferSize = 0;
size_t enter_date_time_nsBufferSize = 0;
size_t exit_date_time_nsBufferSize = 0;

uint64_t encodeVarInt(uint32_t val, size_t &numOfBytes)
{
	uint64_t res = 0;
	uint64_t temp = val;
	uint64_t ctr256 = 1;
	numOfBytes = 0;

	do
	{
		res |= ((temp % 128) * ctr256);
		res |= (128 * ctr256);
		ctr256 *= 256;
		temp /= 128;
		numOfBytes++;
	} while (temp != 0);

	res &= (ctr256 / 2 - 1);

	return res;
}

void prepareClickhouseNativeBlock(size_t numberOfEntries,
								  const uint8_t *hostnameBuffer, const size_t &hostnameBufferSize,
								  const uint8_t *per_node_per_analyzer_run_idBuffer, const size_t &per_node_per_analyzer_run_idBufferSize,
								  const uint8_t *syscall_numberBuffer, const size_t &syscall_numberBufferSize,
								  const uint8_t *PIDBuffer, const size_t &PIDBufferSize,
								  const uint8_t *TGIDBuffer, const size_t &TGIDBufferSize,
								  const uint8_t *UIDBuffer, const size_t &UIDBufferSize,
								  const uint8_t *GIDBuffer, const size_t &GIDBufferSize,
								  const uint8_t *core_idBuffer, const size_t &core_idBufferSize,
								  const uint8_t *returned_valueBuffer, const size_t &returned_valueBufferSize,
								  const uint8_t *enter_date_time_nsBuffer, const size_t &enter_date_time_nsBufferSize,
								  const uint8_t *exit_date_time_nsBuffer, const size_t &exit_date_time_nsBufferSize,
								  uint8_t *resBuffer, size_t &resBufferPos)
{
	resBufferPos = 0;
	size_t bytesForSmth = 0;

	// columns
	auto encodedSmth = encodeVarInt(11, bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	// entries
	encodedSmth = encodeVarInt(numberOfEntries, bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	// hostname column
	std::string columnName = "c1";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	std::string columnType = "String";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(hostnameBuffer[0]), hostnameBufferSize);
	resBufferPos += hostnameBufferSize;

	// per_node_per_analyzer_run_id column
	columnName = "c2";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt64";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(per_node_per_analyzer_run_idBuffer[0]), per_node_per_analyzer_run_idBufferSize);
	resBufferPos += per_node_per_analyzer_run_idBufferSize;

	// syscall_number column
	columnName = "c3";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt16";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(syscall_numberBuffer[0]), syscall_numberBufferSize);
	resBufferPos += syscall_numberBufferSize;

	// PID column
	columnName = "c4";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt32";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(PIDBuffer[0]), PIDBufferSize);
	resBufferPos += PIDBufferSize;

	// TGID column
	columnName = "c5";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt32";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(TGIDBuffer[0]), TGIDBufferSize);
	resBufferPos += TGIDBufferSize;

	// UID column
	columnName = "c6";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt32";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(UIDBuffer[0]), UIDBufferSize);
	resBufferPos += UIDBufferSize;

	// GID column
	columnName = "c7";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt32";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(GIDBuffer[0]), GIDBufferSize);
	resBufferPos += GIDBufferSize;

	// core_id column
	columnName = "c8";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt16";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(core_idBuffer[0]), core_idBufferSize);
	resBufferPos += core_idBufferSize;

	// returned_value column
	columnName = "c9";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt64";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(returned_valueBuffer[0]), returned_valueBufferSize);
	resBufferPos += returned_valueBufferSize;

	// enter_date_time_ns column
	columnName = "c10";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt64";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(enter_date_time_nsBuffer[0]), enter_date_time_nsBufferSize);
	resBufferPos += enter_date_time_nsBufferSize;

	// exit_date_time_ns column
	columnName = "c11";
	encodedSmth = encodeVarInt(columnName.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnName[0]), columnName.length());
	resBufferPos += columnName.length();

	columnType = "UInt64";
	encodedSmth = encodeVarInt(columnType.length(), bytesForSmth);
	*((uint64_t *)&(resBuffer[resBufferPos])) = encodedSmth;
	resBufferPos += bytesForSmth;

	memcpy(&(resBuffer[resBufferPos]), &(columnType[0]), columnType.length());
	resBufferPos += columnType.length();

	memcpy(&(resBuffer[resBufferPos]), &(exit_date_time_nsBuffer[0]), exit_date_time_nsBufferSize);
	resBufferPos += exit_date_time_nsBufferSize;
}

void appendEntryToBuffers(const struct BaseTableEntry *entry, const std::string &nodeNameDetermineCommandResult,
						  uint8_t *hostnameBuffer, size_t &hostnameBufferPos,
						  uint8_t *per_node_per_analyzer_run_idBuffer, size_t &per_node_per_analyzer_run_idBufferPos,
						  uint8_t *syscall_numberBuffer, size_t &syscall_numberBufferPos,
						  uint8_t *PIDBuffer, size_t &PIDBufferPos,
						  uint8_t *TGIDBuffer, size_t &TGIDBufferPos,
						  uint8_t *UIDBuffer, size_t &UIDBufferPos,
						  uint8_t *GIDBuffer, size_t &GIDBufferPos,
						  uint8_t *core_idBuffer, size_t &core_idBufferPos,
						  uint8_t *returned_valueBuffer, size_t &returned_valueBufferPos,
						  uint8_t *enter_date_time_nsBuffer, size_t &enter_date_time_nsBufferPos,
						  uint8_t *exit_date_time_nsBuffer, size_t &exit_date_time_nsBufferPos)
{
	// hostname
	size_t bytesForStringLength = 0;
	auto encodedStringLength = encodeVarInt(nodeNameDetermineCommandResult.length(), bytesForStringLength);
	*((uint64_t *)&(hostnameBuffer[hostnameBufferPos])) = encodedStringLength;
	hostnameBufferPos += bytesForStringLength;

	memcpy(&(hostnameBuffer[hostnameBufferPos]), &(nodeNameDetermineCommandResult[0]), nodeNameDetermineCommandResult.length());
	hostnameBufferPos += nodeNameDetermineCommandResult.length();

	// per_node_per_analyzer_run_id
	*((uint64_t *)&(per_node_per_analyzer_run_idBuffer[per_node_per_analyzer_run_idBufferPos])) = entry->global_id;
	per_node_per_analyzer_run_idBufferPos += 8;

	// syscall_number
	*((uint16_t *)&(syscall_numberBuffer[syscall_numberBufferPos])) = uint16_t(entry->syscall_number);
	syscall_numberBufferPos += 2;

	// PID
	*((uint32_t *)&(PIDBuffer[PIDBufferPos])) = uint32_t(entry->process_ID % (1ULL << 31));
	PIDBufferPos += 4;

	// TGID
	*((uint32_t *)&(TGIDBuffer[TGIDBufferPos])) = uint32_t(entry->process_ID / (1ULL << 31));
	TGIDBufferPos += 4;

	// UID
	*((uint32_t *)&(UIDBuffer[UIDBufferPos])) = uint32_t(entry->process_owner_user_ID % (1ULL << 31));
	UIDBufferPos += 4;

	// GID
	*((uint32_t *)&(GIDBuffer[GIDBufferPos])) = uint32_t(entry->process_owner_user_ID / (1ULL << 31));
	GIDBufferPos += 4;

	// core_id
	*((uint16_t *)&(core_idBuffer[core_idBufferPos])) = uint16_t(entry->core_id);
	core_idBufferPos += 2;

	// returned_value
	*((uint64_t *)&(returned_valueBuffer[returned_valueBufferPos])) = entry->returned_value;
	returned_valueBufferPos += 8;

	// enter_date_time_ns
	*((uint64_t *)&(enter_date_time_nsBuffer[enter_date_time_nsBufferPos])) = entry->enter_time;
	enter_date_time_nsBufferPos += 8;

	// exit_date_time_ns
	*((uint64_t *)&(exit_date_time_nsBuffer[exit_date_time_nsBufferPos])) = entry->exit_time;
	exit_date_time_nsBufferPos += 8;
}
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

	if (pollSuccessFlag == false)
	{
		successfullPollIterationsCounter++;
		pollSuccessFlag = true;
	}

#endif

#ifdef PUSHING_TO_RABBITMQ
	// memcpy(&(rabbitMqBuffer[rabbitMqBufferFilledPartSize]), data, data_sz);
	// rabbitMqBufferFilledPartSize += data_sz;
	appendEntryToBuffers((BaseTableEntry *)data, nodeNameDetermineCommandResult,
						 hostnameBuffer, hostnameBufferSize,
						 per_node_per_analyzer_run_idBuffer, per_node_per_analyzer_run_idBufferSize,
						 syscall_numberBuffer, syscall_numberBufferSize,
						 PIDBuffer, PIDBufferSize,
						 TGIDBuffer, TGIDBufferSize,
						 UIDBuffer, UIDBufferSize,
						 GIDBuffer, GIDBufferSize,
						 core_idBuffer, core_idBufferSize,
						 returned_valueBuffer, returned_valueBufferSize,
						 enter_date_time_nsBuffer, enter_date_time_nsBufferSize,
						 exit_date_time_nsBuffer, exit_date_time_nsBufferSize);
	numberOfEntries++;
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
		return 0;
	}

	// get hostname
	char *nodeNameDetermineCommand = "hostname";

	char buf[BUFSIZ];
	FILE *ptr;

	if ((ptr = popen(nodeNameDetermineCommand, "r")) != NULL)
		while (fgets(buf, BUFSIZ, ptr) != NULL)
			nodeNameDetermineCommandResult = nodeNameDetermineCommandResult + std::string(buf);

	pclose(ptr);

	nodeNameDetermineCommandResult.erase(std::remove(nodeNameDetermineCommandResult.begin(), nodeNameDetermineCommandResult.end(), '\n'), nodeNameDetermineCommandResult.end());

	std::cout << "\n<<<<<<\nDetermined node name:\n\t" << nodeNameDetermineCommandResult << "\n>>>>>>\n"
			  << std::endl;

	// access to the event loop
	std::string rabbitmqConnString = std::string("amqp://guest:guest@") + rabbitmqServerAddress + std::string(":5672/");
	auto *loop = EV_DEFAULT;

	AMQP::LibEvHandler handler(loop);
	AMQP::TcpConnection connection(&handler, AMQP::Address(rabbitmqConnString.c_str()));
	AMQP::TcpChannel channel(&connection);

	std::thread t1([=]()
				   { ev_run(loop, 0); });

	// channel.declareExchange("exchange1", AMQP::fanout);
	// channel.declareQueue("queue1");
	// channel.bindQueue("exchange1", "queue1", "routing-key1");

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

			pollSuccessFlag = false;

#ifdef PUSHING_TO_RABBITMQ

			rabbitMqBufferFilledPartSize = 0;
			numberOfEntries = 0;

			hostnameBufferSize = 0;
			per_node_per_analyzer_run_idBufferSize = 0;
			syscall_numberBufferSize = 0;
			PIDBufferSize = 0;
			TGIDBufferSize = 0;
			UIDBufferSize = 0;
			GIDBufferSize = 0;
			core_idBufferSize = 0;
			returned_valueBufferSize = 0;
			enter_date_time_nsBufferSize = 0;
			exit_date_time_nsBufferSize = 0;
#endif

			err = ring_buffer__poll(rb, 100);

			if (err < 0)
			{
				printf("Error polling ring buffer: %d\n", err);
				break;
			}

#ifdef PUSHING_TO_RABBITMQ
			// channel.startTransaction();
			if (numberOfEntries != 0)
			{
				prepareClickhouseNativeBlock(numberOfEntries,
											 hostnameBuffer, hostnameBufferSize,
											 per_node_per_analyzer_run_idBuffer, per_node_per_analyzer_run_idBufferSize,
											 syscall_numberBuffer, syscall_numberBufferSize,
											 PIDBuffer, PIDBufferSize,
											 TGIDBuffer, TGIDBufferSize,
											 UIDBuffer, UIDBufferSize,
											 GIDBuffer, GIDBufferSize,
											 core_idBuffer, core_idBufferSize,
											 returned_valueBuffer, returned_valueBufferSize,
											 enter_date_time_nsBuffer, enter_date_time_nsBufferSize,
											 exit_date_time_nsBuffer, exit_date_time_nsBufferSize,
											 rabbitMqBuffer, rabbitMqBufferFilledPartSize);
				//	channel.publish("exchange1", nodeNameDetermineCommandResult.c_str(), (char *)rabbitMqBuffer, rabbitMqBufferFilledPartSize, 0);
				// #ifdef LOGGING
				/*std::cout << "Block: " << std::endl;

				for (size_t i = 0; i < rabbitMqBufferFilledPartSize; i++)
				{
					if (i % 16 == 0)
					{
						std::cout << std::endl;
					}
					std::cout << std::hex << int(rabbitMqBuffer[i]) << " ";
				}
				std::cout << std::endl;*/
				// #endif

				//				channel.startTransaction();
				channel.publish("clickhouse-exchange_my_database_syscalls_from_rabbitmq_bridge", "vadim", (char *)rabbitMqBuffer, rabbitMqBufferFilledPartSize, 0);
				//	channel.commitTransaction().onSuccess([]() {}).onError([](const char *message){	std::cout << "\nERROR. MESSAGE: " << message << std::endl;});
			}
// channel.commitTransaction().onSuccess([]() {}).onError([](const char *message) {});
#endif

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
	std::cout << "Successfull poll iterations counter: " << successfullPollIterationsCounter << "; syscalls per iteration: " << double(lastGotId) / successfullPollIterationsCounter << std::endl;
#endif

	// std::system(std::string("rm extractorlog.txt").c_str());
	std::system((std::string("rm /sys/fs/bpf/") + ContinExtrFlagPathName.substr(ContinExtrFlagPathName.rfind('/') + 1)).c_str());

#ifdef PUSHING_TO_RABBITMQ
	t1.detach();
#endif

	return 0;
}