// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
// #define BPF_NO_GLOBAL_DATA

// #include <sys/types.h>

// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include <linux/sched.h>

// #include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// #include <stdint.h>
// #include <stdlib.h>
// #include <stdbool.h>
// #include <unistd.h>
#include "structs.h"
#include "syscalls_names.h"
// #include <linux/sched.h>

char LICENSE[] SEC("license") = "GPL";

struct sys_enter_args
{
  uint16_t common_type;         // offset:0;	size:2;	signed:0;
  uint8_t common_flags;         // offset:2;	size:1;	signed:0;
  uint8_t common_preempt_count; // offset:3;	size:1;	signed:0;
  uint32_t common_pid;          // offset:4;	size:4;	signed:1;

  uint32_t __syscall_nr; // offset:8;	size:4;	signed:1;
  uint64_t fd;           // offset:16;	size:8;	signed:0;
  uint64_t buf;          // offset:24;	size:8;	signed:0;
  uint64_t count;        // offset:32;	size:8;	signed:0;

  uint32_t pad;
};

struct sys_exit_args
{
  uint16_t common_type;         // offset:0;	size:2;	signed:0;
  uint8_t common_flags;         // offset:2;	size:1;	signed:0;
  uint8_t common_preempt_count; // offset:3;	size:1;	signed:0;
  uint32_t common_pid;          // offset:4;	size:4;	signed:1;

  uint32_t __syscall_nr; // offset:8;	size:4;	signed:1;
  uint64_t ret;          // offset:16;	size:8;	signed:1;

  uint32_t pad;
};

uint64_t val = 0;
uint64_t global_number = 0;
// uint64_t base_table_local_number = 0;
// uint32_t key = 0;
uint64_t nanosecs = 0;

uint64_t to_track_value = 0;

// bool enable_printk = true;

const uint64_t ringbuffer_size_in_bytes = (1UL << 26);
const uint64_t max_entries_BaseTableMap_c = ringbuffer_size_in_bytes / sizeof(struct BaseTableEntry);
const uint64_t max_entries_PIDActGlbSclN_c = 10000;

bool shit = false;

/*struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, max_entries_BaseTableMap_c);
  __type(key, uint32_t);
  __type(value, struct BaseTableEntry);
} BaseTableMap SEC(".maps");*/

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, max_entries_PIDActGlbSclN_c);
  __type(key, uint64_t);
  __type(value, struct BaseTableEntry);
} PIDActScl SEC(".maps");

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, pid_t);
  __type(value, pid_t);
} PID_parent SEC(".maps");

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, pid_t);
  __type(value, struct ProgNameType);
} PID_comm SEC(".maps");

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, ringbuffer_size_in_bytes);
} BaseTableBuf SEC(".maps");

bool is_relevant_enter()
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  pid_t cur_pid = ((cur_pid_tgid << 32) >> 32);

  if (((cur_pid_tgid << 32) >> 32) == to_track_value)
  {
    pid_t *pid_p = bpf_map_lookup_elem(&PID_parent, &cur_pid);

    if (pid_p)
    {
      return true;
    }
    else
    {
      pid_t zeropid = 0;
      bpf_map_update_elem(&PID_parent, &cur_pid, &zeropid, BPF_ANY);
    }

    return true;
  }

  pid_t *pid_p = bpf_map_lookup_elem(&PID_parent, &cur_pid);

  if (pid_p)
  {
    return true;
  }

  struct task_struct *task = (void *)bpf_get_current_task();
  pid_t rppid = BPF_CORE_READ(task, real_parent, tgid);

  pid_t *rppid_p = bpf_map_lookup_elem(&PID_parent, &rppid);

  if (rppid_p)
  {
    bpf_map_update_elem(&PID_parent, &cur_pid, &rppid, BPF_ANY);
    return true;
  }

  return false;
}

bool is_relevant_exit()
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  pid_t cur_pid = ((cur_pid_tgid << 32) >> 32);

  if (((cur_pid_tgid << 32) >> 32) == to_track_value)
  {
    return true;
  }

  pid_t *pid_p = bpf_map_lookup_elem(&PID_parent, &cur_pid);

  if (pid_p)
  {
    return true;
  }

  return false;
}

int common_handle_enter(struct sys_enter_args *ctx)
{
  uint64_t cur_uid_gid = bpf_get_current_uid_gid();
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();

  struct BaseTableEntry handled = {};
  handled.global_id = global_number;
  handled.syscall_number = (uint64_t)(ctx->__syscall_nr);
  handled.enter_time = bpf_ktime_get_tai_ns();
  handled.process_ID = cur_pid_tgid;
  handled.process_owner_user_ID = cur_uid_gid;
  handled.exit_time = 0;
  handled.returned_value = 0;
  handled.is_returned = 0;

  bpf_map_update_elem(&PIDActScl, &(handled.process_ID), &(handled), BPF_ANY);

  global_number++;
  // base_table_local_number = global_number % max_entries_BaseTableMap_c;

  // uint32_t seq_num_key = 0;
  // bpf_map_update_elem(&SeqNums, &seq_num_key, &global_number, BPF_ANY);

  // key = base_table_local_number;

  /*char buf[] = "=========================SYSCALL_INFO=========================\0";

  if (global_number % 50 == 0)
    bpf_ringbuf_output(&BaseTableBuf, &global_number, sizeof(global_number), BPF_RB_FORCE_WAKEUP);
  else
    bpf_ringbuf_output(&BaseTableBuf, &global_number, sizeof(global_number), BPF_RB_NO_WAKEUP);

  global_number++;
  */

  return 0;
}

int common_handle_exit(struct sys_exit_args *ctx)
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();

  pid_t cur_pid = ((cur_pid_tgid << 32) >> 32);

  struct ProgNameType prog_val = {};
  bpf_get_current_comm((prog_val.proc_name), 30);
  bpf_map_update_elem(&PID_comm, &cur_pid, &prog_val, BPF_ANY);

  struct BaseTableEntry *handled = bpf_map_lookup_elem(&PIDActScl, &cur_pid_tgid);

  long bpf_ringbuf_output_res = 0;

  if (handled != NULL)
  {
    if (handled->syscall_number == ctx->__syscall_nr)
    {
      handled->exit_time = bpf_ktime_get_tai_ns();
      handled->returned_value = ctx->ret;
      handled->is_returned = 1;
      // bpf_ringbuf_output_res = bpf_ringbuf_output(&BaseTableBuf, handled, sizeof(*handled), BPF_ANY);

      if (handled->global_id % 100000 == 0)
        bpf_ringbuf_output(&BaseTableBuf, handled, sizeof(*handled), BPF_RB_FORCE_WAKEUP);
      else
        bpf_ringbuf_output(&BaseTableBuf, handled, sizeof(*handled), BPF_RB_NO_WAKEUP);

      // bpf_ringbuf_output_res = 2;
      if (bpf_ringbuf_output_res != 0 && shit == false)
      {
        uint32_t core_id = bpf_get_smp_processor_id();
        bpf_printk("NON ZERO result of \"bpf_ringbuf_output\": res \"%d\", glob_id %d, core_id %d;\n", bpf_ringbuf_output_res, handled->global_id, core_id);
        shit = true;
      }
    }

    bpf_map_delete_elem(&PIDActScl, &cur_pid_tgid);
  }

  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_clone")
int handle_tp_enter(struct sys_enter_args *ctx)
{
  if (is_relevant_enter())
  {
    common_handle_enter(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_clone")
int handle_tp_exit(struct sys_exit_args *ctx)
{
  if (is_relevant_exit())
  {
    common_handle_exit(ctx);
  }
  return 0;
}
