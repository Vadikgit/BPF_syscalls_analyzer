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
uint32_t key = 0;
uint64_t nanosecs = 0;

unsigned long long dev;
unsigned long long ino;

uint64_t to_track_value = 0;

// bool enable_printk = true;

const uint64_t max_entries_BaseTableMap_c = 1000000;
const uint64_t max_entries_PIDActGlbSclN_c = 10000;

uint64_t to_track_value = 0;
uint64_t tracking_type = 0;
char tracking_program_n_a_name[32] = {};

struct
{ // pinned
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
} TGID_parent SEC(".maps");

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, pid_t);
  __type(value, struct ProgNameType);
} TGID_comm SEC(".maps");

bool is_relevant()
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  pid_t cur_tgid = ((cur_pid_tgid << 32) >> 32);

  if (((cur_pid_tgid << 32) >> 32) == to_track_value)
  {
    pid_t *pid_p = bpf_map_lookup_elem(&TGID_parent, &cur_tgid);

    if (pid_p)
    {
      return true;
    }
    else
    {
      pid_t zeropid = 0;
      bpf_map_update_elem(&TGID_parent, &cur_tgid, &zeropid, BPF_ANY);
    }

    return true;
  }

  pid_t *pid_p = bpf_map_lookup_elem(&TGID_parent, &cur_tgid);

  if (pid_p)
  {
    return true;
  }

  struct task_struct *task = (void *)bpf_get_current_task();
  pid_t rppid = BPF_CORE_READ(task, real_parent, tgid);

  pid_t *rppid_p = bpf_map_lookup_elem(&TGID_parent, &rppid);

  if (rppid_p)
  {
    bpf_map_update_elem(&TGID_parent, &cur_tgid, &rppid, BPF_ANY);
    return true;
  }

  return false;
}

int common_handle_enter(struct sys_enter_args *ctx)
{
  return 0;
}

int common_handle_exit(struct sys_exit_args *ctx)
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();

  pid_t cur_tgid = ((cur_pid_tgid << 32) >> 32);

  // struct ProgNameType * prog_val_p = bpf_map_lookup_elem(&TGID_comm, &cur_tgid);

  //  if (!prog_val_p) {
  struct ProgNameType prog_val = {};
  bpf_get_current_comm((prog_val.proc_name), 30);

  bpf_map_update_elem(&TGID_comm, &cur_tgid, &prog_val, BPF_ANY);

  //}

  /*if (enable_printk)
  {
    bpf_printk("In <%d, %d> process captured <%s> and returned <%d>\n",
               ((cur_pid_tgid << 32) >> 32),
               (cur_pid_tgid >> 32),
               syscalls_names[ctx->__syscall_nr],
               ctx->ret);
  }*/

  struct bpf_pidns_info ns;

  // struct task_struct *bpf_get_current_task_btf

  bpf_get_ns_current_pid_tgid(dev, ino, &ns, sizeof(ns));

  /*if (enable_printk)
  {
    bpf_printk("BPF triggered from PID %d, %d.\n", ns.pid, ns.tgid);
  }*/
  // uint32_t pid = bpf_get_current_pid_tgid();
  struct task_struct *task = (void *)bpf_get_current_task();

  pid_t rppid = BPF_CORE_READ(task, real_parent, tgid);

  // level = BPF_CORE_READ(task, thread_pid, level);
  // int level = 0;
  // level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
  //  int level2 = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, parent, pid_allocated);

  /*if (enable_printk)
  {
    bpf_printk("Ppid: %d.\n", rppid);
  }*/
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_clone")
int handle_tp_enter(struct sys_enter_args *ctx)
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();

  if (is_relevant())
  {
    common_handle_enter(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_clone")
int handle_tp_exit(struct sys_exit_args *ctx)
{
  if (is_relevant())
  {
    common_handle_exit(ctx);
  }
  return 0;
}
