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

// uint64_t to_track_value = 0;

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
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, pid_t);
} to_track_pid SEC(".maps"); // [0] - root container pid, 0 -> not specified, smth -> specified

/*struct
{ // not pinned
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, uint8_t);
} cleanup_completed SEC(".maps"); // [0] - bool completion of extra branches cleanup, 0 -> no, 1 -> yes*/
uint64_t cleanup_completed = 0;

bool is_relevant()
{
  /*
  struct task_struct *task = (void *)bpf_get_current_task();

  pid_t rppid = BPF_CORE_READ(task, real_parent, tgid);

  if (rppid != 1)
    return false;

  // struct ProgNameType containerd_shim = {"containerd-shim"};
  struct ProgNameType containerd_shim = {"bash"};
  //  containerd_shim.proc_name = "containerd-shim";containerd-shim(11838)
  struct ProgNameType prog_val = {};

  bpf_get_current_comm((prog_val.proc_name), 30);

  for (int i = 0; i < 30; i++)
  {
    if (containerd_shim.proc_name[i] != prog_val.proc_name[i])
      return false;
  }

  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();

  pid_t cur_tgid = ((cur_pid_tgid << 32) >> 32);



  int level = 0;
  level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
  //  int level2 = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, parent, pid_allocated);


  bpf_printk("<%d> process is <%s>, it's level is <%d>\n", cur_tgid, prog_val.proc_name, level);
  return false;
  */

  struct task_struct *task = (void *)bpf_get_current_task();
  int level = 0;
  level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);

  if (level == 0)
  {
    // bpf_printk("Process <%d> with not actual level <%d>\n", cur_tgid, level);
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

int common_handle_enter(struct sys_enter_args *ctx)
{
  // struct task_struct *task = (void *)bpf_get_current_task();

  // pid_t rppid = BPF_CORE_READ(task, real_parent, tgid);

  // int level = 8;
  //  level = BPF_CORE_READ(task, thread_pid, level);
  //  if (task){
  // level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
  //   int level2 = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, parent, pid_allocated);
  // }
  //  bpf_printk("Level is <%d>\n", level);
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

  if (enable_printk)
  {
    bpf_printk("In <%d, %d> process captured <%s> and returned <%d>\n",
               ((cur_pid_tgid << 32) >> 32),
               (cur_pid_tgid >> 32),
               syscalls_names[ctx->__syscall_nr],
               ctx->ret);
  }

  struct bpf_pidns_info ns;

  // struct task_struct *bpf_get_current_task_btf

  bpf_get_ns_current_pid_tgid(dev, ino, &ns, sizeof(ns));

  if (enable_printk)
  {
    bpf_printk("BPF triggered from PID %d, %d.\n", ns.pid, ns.tgid);
  }

  // uint32_t pid = bpf_get_current_pid_tgid();
  struct task_struct *task = (void *)bpf_get_current_task();

  pid_t rppid = BPF_CORE_READ(task, real_parent, tgid);

  // int level = 8;
  // level = BPF_CORE_READ(task, thread_pid, level);
  // if (task){
  // level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
  //   int level2 = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, parent, pid_allocated);
  // }

  if (enable_printk)
  {
    bpf_printk("Ppid: %d.\n", rppid);
  }
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
