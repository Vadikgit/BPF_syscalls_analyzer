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

#include <glib.h>
#include <librdkafka/rdkafka.h>

#include "kafka_common.cpp"

#define ARR_SIZE(arr) (sizeof((arr)) / sizeof((arr[0])))

/* Optional per-message delivery callback (triggered by poll() or flush())
 * when a message has been successfully delivered or permanently
 * failed delivery (after retries).
 */
static void dr_msg_cb(rd_kafka_t *kafka_handle,
					  const rd_kafka_message_t *rkmessage,
					  void *opaque)
{
	if (rkmessage->err)
	{
		g_error("Message delivery failed: %s", rd_kafka_err2str(rkmessage->err));
	}
}

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

int main(int argc, char **argv)
{
	int err;
	int BaseTableMap_map_id = -1;
	int SeqNums_map_id = -1;
	int ContinExtrFlag_map_id = -1;

	if (argc < 4)
	{
		std::cout << "\n----------------------------------\n"
				  << "\nMap(s) ids not specified\n"
				  << "\nExiting\n"
				  << "\n----------------------------------\n";
		return 0;
	}

	BaseTableMap_map_id = std::stoll(argv[1]);
	SeqNums_map_id = std::stoll(argv[2]);
	ContinExtrFlag_map_id = std::stoll(argv[3]);

	int BaseTableMap_map_fd = bpf_map_get_fd_by_id(BaseTableMap_map_id);
	int SeqNums_map_fd = bpf_map_get_fd_by_id(SeqNums_map_id);
	int ContinExtrFlag_map_fd = bpf_map_get_fd_by_id(ContinExtrFlag_map_id);

	bool not_found_map = ((BaseTableMap_map_fd < 0) || (SeqNums_map_fd < 0) || (ContinExtrFlag_map_fd < 0));
	std::cout << "\n----------------------------------\n"
			  << "BaseTableMap_map_fd: " << BaseTableMap_map_fd;
	std::cout << "\nSeqNums_map_fd: " << SeqNums_map_fd;
	std::cout << "\nContinExtrFlag_map_fd: " << ContinExtrFlag_map_fd << "\n---------------------------------- | ";

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

	uint64_t extract_offset = 200;

	int fileCtr = 0, iterctr = 0;

	bool repeat_condition = true;
	uint32_t extrcontkey = 0;

	// Kafka producer
	rd_kafka_t *producer;
	rd_kafka_conf_t *conf;
	char errstr[512];

	// Create client configuration
	conf = rd_kafka_conf_new();

	// User-specific properties that you must set
	set_config(conf, "bootstrap.servers", "127.0.0.1:9092");
	set_config(conf, "sasl.username", "<CLUSTER API KEY>");
	set_config(conf, "sasl.password", "<CLUSTER API SECRET>");

	// Fixed properties
	// set_config(conf, "security.protocol", "SASL_SSL");
	set_config(conf, "sasl.mechanisms", "PLAIN");
	set_config(conf, "acks", "all");

	// Install a delivery-error callback.
	rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);

	// Create the Producer instance.
	producer = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!producer)
	{
		g_error("Failed to create new producer: %s", errstr);
		return 1;
	}

	// Configuration object is now owned, and freed, by the rd_kafka_t instance.
	conf = NULL;

	// Produce data by selecting random values from these lists.
	const char *topic = "test";
	const char *products[5] = {"book", "alarm clock", "t-shirts", "gift card", "batteries"};

	uint32_t key = 0;

	while (repeat_condition)
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

		if ((glob_num - next_saving_num) >= extract_offset)
		{
			std::chrono::time_point<std::chrono::system_clock> t1, t2;

			std::cout << "\nStart of extracting in topic ---------------------------------- | ";
			printTimestamp();
			std::cout << '\n';

			t1 = std::chrono::system_clock::now();

			std::vector<BaseTableEntry> arr;
			arr.resize(extract_offset);

			for (uint32_t i = next_saving_num; i < (extract_offset + next_saving_num); i++)
			{
				uint32_t arr_key = (i % base_table_entries);
				bpf_map_lookup_elem(BaseTableMap_map_fd, &arr_key, &arr[i - next_saving_num]);
			}

			key = fileCtr;
			fileCtr++;

			rd_kafka_resp_err_t err;

			err = rd_kafka_producev(producer,
									RD_KAFKA_V_TOPIC(topic),
									RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
									RD_KAFKA_V_KEY((void *)&key, sizeof(key)),
									RD_KAFKA_V_VALUE((void *)&arr[0], sizeof(arr[0]) * extract_offset),
									RD_KAFKA_V_OPAQUE(NULL),
									RD_KAFKA_V_END);

			if (err)
			{
				g_error("Failed to produce to topic %s: %s", topic, rd_kafka_err2str(err));
				return 1;
			}
			else
			{
				g_message("Produced event to topic %s: key = %12d", topic, key);
			}

			rd_kafka_poll(producer, 0);

			// Block until the messages are all sent.
			g_message("Flushing final messages..");
			rd_kafka_flush(producer, 10 * 1000);

			if (rd_kafka_outq_len(producer) > 0)
			{
				g_error("%d message(s) were not delivered", rd_kafka_outq_len(producer));
			}

			seqnumkey = 1;
			next_saving_num += extract_offset;
			bpf_map_update_elem(SeqNums_map_fd, &seqnumkey, &next_saving_num, 0);

			t2 = std::chrono::system_clock::now();

			std::cout << "\nEnd of extracting in topic \t" << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count() << " ms, "
					  << sizeof(BaseTableEntry) * extract_offset << " bytes, "
					  << double(std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count()) / (sizeof(BaseTableEntry) * extract_offset) << " ms/byte ---------------------------------- | ";
			printTimestamp();
			std::cout << '\n';
		}

		//
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));

		bpf_map_lookup_elem(ContinExtrFlag_map_fd, &extrcontkey, &repeat_condition);

		iterctr++;
	}

	rd_kafka_destroy(producer);

	return 0;
}
