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

const uint64_t ringbuffer_size_in_bytes = (1UL << 26);
const uint64_t max_entries_BaseTableMap_c = ringbuffer_size_in_bytes / sizeof(struct BaseTableEntry);
const uint64_t max_entries_PIDActGlbSclN_c = 10000;

bool shit = false;

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
  __type(value, pid_t);
} TGID_root SEC(".maps");

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1000);
  __type(key, pid_t);
  __type(value, struct ProgNameType);
} TGID_comm SEC(".maps");

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, ringbuffer_size_in_bytes);
} BaseTableBuf SEC(".maps");

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, pid_t);
} to_track_pid SEC(".maps"); // [0] - root container pid, 0 -> not specified, smth -> specified

struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, max_entries_PIDActGlbSclN_c);
  __type(key, uint64_t);
  __type(value, struct BaseTableEntry);
} PIDActScl SEC(".maps");

/*struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, uint8_t);
} cleanup_completed SEC(".maps"); // [0] - bool completion of extra branches cleanup, 0 -> no, 1 -> yes*/
uint64_t cleanup_completed = 0;

bool is_relevant_enter()
{
  struct task_struct *task = (void *)bpf_get_current_task();
  int level = 0;
  level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);

  if (level == 0)
  {
    return false;
  }

  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  pid_t cur_tgid = ((cur_pid_tgid << 32) >> 32);

  pid_t rppid = BPF_CORE_READ(task, real_parent, tgid);

  uint32_t to_track_pid_key = 0;
  pid_t *to_track_pid_value_p = bpf_map_lookup_elem(&to_track_pid, &to_track_pid_key);

  if (!to_track_pid_value_p) // should always be false
  {
    return false;
  }

  pid_t *ppid_p = bpf_map_lookup_elem(&TGID_parent, &cur_tgid);

  if (ppid_p) // pid is tracked, info exists in all maps
  {
    return true;
  }

  // pid is not tracked yet
  if ((*to_track_pid_value_p) == 0) // process all containered processes
  {
    pid_t *pppid_p = bpf_map_lookup_elem(&TGID_parent, &rppid); // is parent tracking
    if (pppid_p)
    { // yes, it is -> it is new tracked pid -> info should be added in all maps
      bpf_map_update_elem(&TGID_parent, &cur_tgid, &rppid, BPF_ANY);

      pid_t *root_ppid_p = bpf_map_lookup_elem(&TGID_root, &rppid);

      if (root_ppid_p) // should always be true
      {
        bpf_map_update_elem(&TGID_root, &cur_tgid, root_ppid_p, BPF_ANY); // root pid for this process is the same as for it parent
      }
    }
    else // no, it is not -> it is new root pid -> info should be added in all maps
    {
      bpf_map_update_elem(&TGID_root, &cur_tgid, &cur_tgid, BPF_ANY); // it is root for themself

      pid_t zeropid = 0;
      bpf_map_update_elem(&TGID_parent, &cur_tgid, &zeropid, BPF_ANY); // 0 parent pid
    }

    return true;
  }
  else // container root pid specified
  {
    if (cleanup_completed == 0) // needs clean up
    {
      // TODO: cleanup
      cleanup_completed = 1;
    }

    pid_t *pppid_p = bpf_map_lookup_elem(&TGID_parent, &rppid); // is parent tracking
    if (pppid_p)
    { // yes, it is

      pid_t *root_ppid_p = bpf_map_lookup_elem(&TGID_root, &rppid);

      if (!root_ppid_p) // May be, may be not
      {
        return false;
      }
      else if ((*root_ppid_p) != (*to_track_pid_value_p)) // root pid is not the right one
      {
        return false;
      }
      else // -> it is new tracked pid -> info should be added in all maps
      {
        bpf_map_update_elem(&TGID_root, &cur_tgid, root_ppid_p, BPF_ANY); // root pid for this process is the same as for it parent
        bpf_map_update_elem(&TGID_parent, &cur_tgid, &rppid, BPF_ANY);
        return true;
      }
    }
    else // no, it is not -> it is new root pid, but we do not need to track all branches more -> ignore
    {
      return false;
    }
  }
}

bool is_relevant_exit()
{
  struct task_struct *task = (void *)bpf_get_current_task();
  int level = 0;
  level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);

  if (level == 0)
  {
    return false;
  }

  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  pid_t cur_tgid = ((cur_pid_tgid << 32) >> 32);

  pid_t rppid = BPF_CORE_READ(task, real_parent, tgid);

  uint32_t to_track_pid_key = 0;
  pid_t *to_track_pid_value_p = bpf_map_lookup_elem(&to_track_pid, &to_track_pid_key);

  if (!to_track_pid_value_p) // should always be false
  {
    return false;
  }

  pid_t *ppid_p = bpf_map_lookup_elem(&TGID_parent, &cur_tgid);

  if (ppid_p) // pid is tracked, info exists in all maps
  {
    return true;
  }

  return false;
}

int common_handle_enter(struct sys_enter_args *ctx)
{
  uint64_t cur_uid_gid = bpf_get_current_uid_gid();
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t core_id = bpf_get_smp_processor_id();

  struct BaseTableEntry handled = {};
  handled.global_id = global_number;
  handled.syscall_number = (uint64_t)(ctx->__syscall_nr);
  handled.enter_time = bpf_ktime_get_tai_ns();
  handled.process_ID = cur_pid_tgid;
  handled.process_owner_user_ID = cur_uid_gid;
  handled.exit_time = 0;
  handled.returned_value = 0;
  handled.core_id = core_id;
  handled.is_returned = 0;

  bpf_map_update_elem(&PIDActScl, &(handled.process_ID), &(handled), BPF_ANY);

  global_number++;

  return 0;
}

int common_handle_exit(struct sys_exit_args *ctx)
{
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  uint32_t core_id = bpf_get_smp_processor_id();

  pid_t cur_tgid = ((cur_pid_tgid << 32) >> 32);

  // struct ProgNameType * prog_val_p = bpf_map_lookup_elem(&TGID_comm, &cur_tgid);

  struct ProgNameType prog_val = {};
  bpf_get_current_comm((prog_val.proc_name), 30);

  bpf_map_update_elem(&TGID_comm, &cur_tgid, &prog_val, BPF_ANY);

  struct BaseTableEntry *handled = bpf_map_lookup_elem(&PIDActScl, &cur_pid_tgid);

  long bpf_ringbuf_output_res = 0;

  if (handled != NULL)
  {
    if (handled->syscall_number == ctx->__syscall_nr)
    {
      handled->exit_time = bpf_ktime_get_tai_ns();
      handled->returned_value = ctx->ret;
      handled->is_returned = 1;
      bpf_ringbuf_output_res = bpf_ringbuf_output(&BaseTableBuf, handled, sizeof(*handled), BPF_ANY);

      // if (handled->global_id % 1000 == 0)
      //   bpf_ringbuf_output(&BaseTableBuf, handled, sizeof(*handled), BPF_RB_FORCE_WAKEUP);
      // else
      //   bpf_ringbuf_output(&BaseTableBuf, handled, sizeof(*handled), BPF_RB_NO_WAKEUP);

      if (bpf_ringbuf_output_res != 0 && shit == false)
      {
        bpf_printk("NON ZERO result of \"bpf_ringbuf_output\": res %d, glob_id %d;\n", bpf_ringbuf_output_res, handled->global_id);
        shit = true;
      }

      if (core_id != handled->core_id)
      {
        // bpf_printk("CORE IDS IN ENTERING AND IN EXIT ARE DIFFERENT: enter %d, exit %d;\n", handled->core_id, core_id);
        // bpf_printk("CORE IDS IN ENTERING AND IN EXIT ARE DIFFERENT: exit %d;\n", core_id);
        // bpf_printk("CORE IDS IN ENTERING AND IN EXIT ARE DIFFERENT\n");
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
