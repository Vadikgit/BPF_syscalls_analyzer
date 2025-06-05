CREATE DATABASE my_database;

CREATE TABLE IF NOT EXISTS my_database.syscalls (
    hostname String,
    per_node_per_analyzer_run_id UInt64,
    syscall_number UInt16,
    PID UInt32,
    TGID UInt32,
    UID UInt32,
    GID UInt32,
    core_id UInt16,
    returned_value UInt64,
    enter_date_time DateTime64(9, 'Europe/Moscow'),
    exit_date_time DateTime64(9, 'Europe/Moscow'),
) ENGINE = MergeTree
ORDER BY enter_date_time;

CREATE TABLE my_database.syscalls_from_rabbitmq (
    c1 String,
    c2 UInt64,
    c3 UInt16,
    c4 UInt32,
    c5 UInt32,
    c6 UInt32,
    c7 UInt32,
    c8 UInt16,
    c9 UInt64,
    c10 UInt64,
    c11 UInt64,
) ENGINE = RabbitMQ SETTINGS rabbitmq_host_port = '...:5672',
                            rabbitmq_exchange_name = 'clickhouse-exchange',
                            rabbitmq_routing_key_list = 'myqueue',
                            rabbitmq_format = 'Native',
                            rabbitmq_exchange_type = 'fanout',
                            rabbitmq_num_consumers = 1,
                            rabbitmq_username = 'guest',
                            rabbitmq_password = 'guest',
                            date_time_input_format = 'best_effort';

CREATE MATERIALIZED VIEW IF NOT EXISTS my_database.event_view
TO my_database.syscalls AS
SELECT
    c1 AS hostname,
    c2 AS per_node_per_analyzer_run_id,
    c3 AS syscall_number,
    c4 AS PID,
    c5 AS TGID,
    c6 AS UID,
    c7 AS GID,
    c8 AS core_id,
    c9 AS returned_value,
    addNanoseconds(toDateTime64(0, 9, 'Europe/Moscow'), c10) AS enter_date_time,
    addNanoseconds(toDateTime64(0, 9, 'Europe/Moscow'), c11) AS exit_date_time
FROM my_database.syscalls_from_rabbitmq;

