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
uint64_t base_table_local_number = 0;
uint32_t key = 0;
uint64_t nanosecs = 0;

unsigned long long dev;
unsigned long long ino;

uint64_t to_track_value = 0;

// bool enable_printk = true;

const uint64_t max_entries_BaseTableMap_c = 1000000;
const uint64_t max_entries_PIDActGlbSclN_c = 10000;

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, max_entries_BaseTableMap_c);
  __type(key, uint32_t);
  __type(value, struct BaseTableEntry);
} BaseTableMap SEC(".maps");

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, max_entries_PIDActGlbSclN_c);
  __type(key, uint64_t);
  __type(value, uint64_t);
} PIDActGlbSclN SEC(".maps");

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

  bpf_map_update_elem(&BaseTableMap, &key, &handled, BPF_ANY);
  bpf_map_update_elem(&PIDActGlbSclN, &(handled.process_ID), &(handled.global_id), BPF_ANY);

  global_number++;
  base_table_local_number = global_number % max_entries_BaseTableMap_c;

  key = base_table_local_number;

  return 0;
}

int common_handle_exit(struct sys_exit_args *ctx)
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();

  pid_t cur_pid = ((cur_pid_tgid << 32) >> 32);

  struct ProgNameType prog_val = {};
  bpf_get_current_comm((prog_val.proc_name), 30);
  bpf_map_update_elem(&PID_comm, &cur_pid, &prog_val, BPF_ANY);

  uint64_t *base_table_global_number_for_syscall = bpf_map_lookup_elem(&PIDActGlbSclN, &cur_pid_tgid);

  if (base_table_global_number_for_syscall != NULL)
  {
    uint64_t base_table_local_number_for_syscall = (*(base_table_global_number_for_syscall)) % max_entries_BaseTableMap_c;

    struct BaseTableEntry *handled = bpf_map_lookup_elem(&BaseTableMap, &base_table_local_number_for_syscall);

    if (handled != NULL)
    {
      if ((handled->global_id == (*base_table_global_number_for_syscall)) && (handled->syscall_number == ctx->__syscall_nr))
      {
        handled->exit_time = bpf_ktime_get_tai_ns();
        handled->returned_value = ctx->ret;
        handled->is_returned = 1;
        bpf_map_update_elem(&BaseTableMap, &base_table_local_number_for_syscall, handled, BPF_ANY);
      }

      bpf_map_delete_elem(&PIDActGlbSclN, &cur_pid_tgid);
    }
  }

  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_clone")
int handle_tp_enter(struct sys_enter_args *ctx)
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();

  if (is_relevant_enter())
  {
    /*if ((int)(ctx->__syscall_nr) == 1)
    {
      uint64_t count = ctx->count;

      static char buf[10] = {};

      bpf_printk("%d symbols", count);
      if (count < 10 && ((char *)(ctx->buf) != NULL))
      {
        char c = 0;

        for (int i = 0; i < count; i++)
        {
          if ((char *)(ctx->buf) != NULL)
          {
            char *cp = (char *)(ctx->buf);

            // buf[i] = *(((char *)(ctx->buf)) + i);
            c = *cp;
            buf[i] = c;
          }
        }
        buf[count] = 0;

        bpf_printk("data: %s", &buf);
      }
      // char *cp = (char *)(ctx->buf);

      // if (cp != NULL)
      //{
      //  bpf_printk("<%s>", cp);
      //  bpf_core_read(&c, 1, cp);
      //}

      //      bpf_printk("<%s>", &c);
    }*/

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
