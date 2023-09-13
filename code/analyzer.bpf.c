// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
//#include "vmlinux.h"
//#define BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include "structs.h"
#include "syscalls_names.h"


char LICENSE[] SEC("license") = "GPL";

struct sys_enter_args {
  uint16_t common_type;	        // offset:0;	size:2;	signed:0;
  uint8_t common_flags;	        // offset:2;	size:1;	signed:0;
  uint8_t common_preempt_count; // offset:3;	size:1;	signed:0;
  uint32_t common_pid;	        // offset:4;	size:4;	signed:1;

  uint32_t __syscall_nr;	// offset:8;	size:4;	signed:1;
  uint64_t fd;	                // offset:16;	size:8;	signed:0;
  uint64_t buf;	                // offset:24;	size:8;	signed:0;
  uint64_t count;	        // offset:32;	size:8;	signed:0;
  
  uint32_t pad;
};

struct sys_exit_args {
  uint16_t common_type;	        // offset:0;	size:2;	signed:0;
  uint8_t common_flags;	        // offset:2;	size:1;	signed:0;
  uint8_t common_preempt_count; // offset:3;	size:1;	signed:0;
  uint32_t common_pid;	        // offset:4;	size:4;	signed:1;

  uint32_t __syscall_nr;	// offset:8;	size:4;	signed:1;
  uint64_t ret;	                // offset:16;	size:8;	signed:1;
  
   uint32_t pad;
};


uint64_t val = 0; 
uint64_t global_number = 0; 
uint64_t base_table_local_number = 0; 
uint32_t key = 0;
uint64_t nanosecs = 0;


const uint64_t max_entries_BaseTableMap_c = 1000000;
const uint64_t max_entries_PIDActGlbSclN_c = 10000;
const uint64_t max_entries_PIDName_c = 10000;
const uint64_t max_entries_SyscllStat_c = 1000;
const uint64_t max_entries_ProgNormalTrace_c = 100;


uint64_t to_track_value = 0;
uint64_t tracking_type = 0;
char tracking_program_n_a_name[32] = {};

struct { // pinned
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, max_entries_BaseTableMap_c);
	__type(key, uint32_t);
	__type(value, struct BaseTableEntry);
} BaseTableMap SEC(".maps");

struct { 
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, max_entries_PIDActGlbSclN_c);
	__type(key, uint64_t);
	__type(value, uint64_t);
} PIDActGlbSclN SEC(".maps");

struct { // pinned
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, max_entries_SyscllStat_c);
	__type(key, uint64_t);
	__type(value, uint64_t);
} SyscllStatMap SEC(".maps");

/*struct { // pinned
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, max_entries_PIDName_c);
	__type(key, uint64_t);
	__type(value, struct PIDNameEntry);
} PIDName SEC(".maps");*/

struct { // pinned
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, max_entries_ProgNormalTrace_c);
	__type(key, struct ProgNameType);
	__type(value, struct ProgSyscallsListType);
} ProgNormalTrace SEC(".maps");


bool is_relevant()
{
  uint64_t cur_uid_gid = bpf_get_current_uid_gid();
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  char comm_buf[32] = {};
  bpf_get_current_comm((comm_buf), 30);
  
  if ((tracking_type == 1) && (((cur_uid_gid << 32) >> 32) != to_track_value))
    return false;
  if ((tracking_type == 2) && (((cur_pid_tgid << 32) >> 32) != to_track_value))
    return false;
  if (tracking_type == 3) {
    for (int i = 0; i < 32; i++) {
      if(comm_buf[i] != tracking_program_n_a_name[i]) {
        return false;
      }
    }
  }
    
  return true;
}

/*void service_proc_name()
{
  uint64_t cur_tgid = (bpf_get_current_pid_tgid() >> 32);
  //uint64_t cur_tgid = (bpf_get_current_pid_tgid());
    
  struct PIDNameEntry * ptr_PID_name = bpf_map_lookup_elem(&PIDName, &(cur_tgid)); 
    
  if (ptr_PID_name == NULL) {
    struct PIDNameEntry entry_to_past = {};
    
    struct ProgNameType if_exist_key = {};
    bpf_get_current_comm((if_exist_key.proc_name), 30);
    struct ProgSyscallsListType * if_exist_val = bpf_map_lookup_elem(&ProgNormalTrace, &if_exist_key);    
    
    entry_to_past.is_tracked = (if_exist_val != NULL);
    bpf_get_current_comm((entry_to_past.proc_name), 30);
    
    bpf_map_update_elem(&PIDName, &(cur_tgid), &entry_to_past, BPF_ANY);
    
    
    char comm_buf[256];
bpf_get_current_comm((comm_buf), 256);
bpf_printk("%s\n", comm_buf);
  }
    //bpf_printk("11%s\n", comm_buf);
}*/

int analyse_syscall(struct sys_enter_args *ctx)
{   
  struct ProgNameType prog_key = {};
  bpf_get_current_comm((prog_key.proc_name), 30);
  struct ProgSyscallsListType * prog_val = bpf_map_lookup_elem(&ProgNormalTrace, &prog_key); 
   
  if (prog_val) {
    if ((ctx->__syscall_nr >= 0) && (ctx->__syscall_nr < 548)) {
      uint8_t compareval = prog_val->is_syscall_typical[ctx->__syscall_nr / 8];
      uint8_t shiftedval = (1 << (ctx->__syscall_nr % 8));
      if ((compareval & shiftedval) == 0) {
        bpf_printk("*** SYSTEM CALL ANOMALY DETECTED *** : in \"%s\" programm --- %s --- captured\n", prog_key.proc_name, syscalls_names[ctx->__syscall_nr]);
       }
    }
  }
  return 0;
}



int memorize_syscall(struct sys_enter_args *ctx)
{   
  struct ProgNameType prog_key = {};
  bpf_get_current_comm((prog_key.proc_name), 30);
  struct ProgSyscallsListType * prog_val = bpf_map_lookup_elem(&ProgNormalTrace, &prog_key); 
    
  if (prog_val) {
    if ((ctx->__syscall_nr >= 0) && (ctx->__syscall_nr < 600)) {
      prog_val->is_syscall_typical[ctx->__syscall_nr / 8] |= (1 << (ctx->__syscall_nr % 8));
      bpf_map_update_elem(&ProgNormalTrace, &prog_key, prog_val, BPF_ANY);
    }
  } else {
    struct ProgSyscallsListType new_prog_val = {};
    if ((ctx->__syscall_nr >= 0) && (ctx->__syscall_nr < 600)) {
      new_prog_val.is_syscall_typical[ctx->__syscall_nr / 8] |= (1 << (ctx->__syscall_nr % 8));
      bpf_map_update_elem(&ProgNormalTrace, &prog_key, &new_prog_val, BPF_ANY);
    }
  }
  
  return 0;
}



int common_handle(struct sys_enter_args *ctx)
{ 
    uint64_t cur_uid_gid = bpf_get_current_uid_gid();
    uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
    
    struct BaseTableEntry handled = {};
    handled.global_id = global_number;
    handled.syscall_number = (uint64_t)(ctx->__syscall_nr);
    handled.enter_time = bpf_ktime_get_ns();
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
    
// Statistic
    uint64_t count_for_syscall = 0;
    uint64_t * ptr_count_for_syscall = bpf_map_lookup_elem(&SyscllStatMap, &(handled.syscall_number)); 
    
    if (ptr_count_for_syscall) {
      count_for_syscall = *ptr_count_for_syscall;
    }
    
    count_for_syscall++;
    
    bpf_map_update_elem(&SyscllStatMap, &(handled.syscall_number), &count_for_syscall, BPF_ANY);

    return 0;
}

int common_handle_ex(struct sys_exit_args *ctx)
{     
  uint64_t cur_uid_gid = bpf_get_current_uid_gid();
  uint64_t cur_pid_tgid = bpf_get_current_pid_tgid();
  
  uint64_t * base_table_global_number_for_syscall = bpf_map_lookup_elem(&PIDActGlbSclN, &cur_pid_tgid); 
  
  if (base_table_global_number_for_syscall != NULL){
    uint64_t base_table_local_number_for_syscall = (*(base_table_global_number_for_syscall)) % max_entries_BaseTableMap_c; 
    
    struct BaseTableEntry * handled = bpf_map_lookup_elem(&BaseTableMap, &base_table_local_number_for_syscall);
    
    if (handled != NULL){
      if((handled->global_id == (*base_table_global_number_for_syscall)) && (handled->syscall_number == ctx->__syscall_nr)){
        handled->exit_time = bpf_ktime_get_ns();
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
SEC("tp/syscalls/sys_enter_read")
int handle_tp_read(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_tp_read_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_write")
int handle_tp_write(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_write")
int handle_tp_write_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_open")
int handle_tp_open(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_open")
int handle_tp_open_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_close")
int handle_tp_close(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_close")
int handle_tp_close_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_access")
int handle_tp_access(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_access")
int handle_tp_access_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_dup")
int handle_tp_dup(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_dup")
int handle_tp_dup_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_dup2")
int handle_tp_dup2(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_dup2")
int handle_tp_dup2_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_socket")
int handle_tp_socket(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_socket")
int handle_tp_socket_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_connect")
int handle_tp_connect(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int handle_tp_connect_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_clone")
int handle_tp_clone(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_clone")
int handle_tp_clone_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_fork")
int handle_tp_fork(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_fork")
int handle_tp_fork_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_vfork")
int handle_tp_vfork(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_vfork")
int handle_tp_vfork_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_execve")
int handle_tp_execve(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_execve")
int handle_tp_execve_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_chmod")
int handle_tp_chmod(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_chmod")
int handle_tp_chmod_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_fchmod")
int handle_tp_fchmod(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_fchmod")
int handle_tp_fchmod_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_chown")
int handle_tp_chown(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_chown")
int handle_tp_chown_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_fchown")
int handle_tp_fchown(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_fchown")
int handle_tp_fchown_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_lchown")
int handle_tp_lchown(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_lchown")
int handle_tp_lchown_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_umask")
int handle_tp_umask(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_umask")
int handle_tp_umask_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_sysinfo")
int handle_tp_sysinfo(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_sysinfo")
int handle_tp_sysinfo_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_ptrace")
int handle_tp_ptrace(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_ptrace")
int handle_tp_ptrace_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_getuid")
int handle_tp_getuid(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_getuid")
int handle_tp_getuid_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_syslog")
int handle_tp_syslog(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_syslog")
int handle_tp_syslog_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_getgid")
int handle_tp_getgid(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_getgid")
int handle_tp_getgid_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_setuid")
int handle_tp_setuid(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_setuid")
int handle_tp_setuid_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_setgid")
int handle_tp_setgid(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_setgid")
int handle_tp_setgid_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_geteuid")
int handle_tp_geteuid(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_geteuid")
int handle_tp_geteuid_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_getegid")
int handle_tp_getegid(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_getegid")
int handle_tp_getegid_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_setpgid")
int handle_tp_setpgid(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_setpgid")
int handle_tp_setpgid_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_getppid")
int handle_tp_getppid(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_getppid")
int handle_tp_getppid_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_getpgrp")
int handle_tp_getpgrp(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_getpgrp")
int handle_tp_getpgrp_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_setpriority")
int handle_tp_setpriority(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_setpriority")
int handle_tp_setpriority_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_sched_setparam")
int handle_tp_sched_setparam(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_sched_setparam")
int handle_tp_sched_setparam_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_sched_getparam")
int handle_tp_sched_getparam(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_sched_getparam")
int handle_tp_sched_getparam_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_sched_setscheduler")
int handle_tp_sched_setscheduler(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_sched_setscheduler")
int handle_tp_sched_setscheduler_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_sched_getscheduler")
int handle_tp_sched_getscheduler(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_sched_getscheduler")
int handle_tp_sched_getscheduler_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_dup3")
int handle_tp_dup3(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_dup3")
int handle_tp_dup3_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}

////////////////////////////////////////////////////
SEC("tp/syscalls/sys_enter_clone3")
int handle_tp_clone3(struct sys_enter_args *ctx) {
  if(is_relevant()){
    common_handle(ctx);
    if (tracking_type == 3)
      memorize_syscall(ctx);
    else
      analyse_syscall(ctx);
  }
  return 0;
}

SEC("tp/syscalls/sys_exit_clone3")
int handle_tp_clone3_ex(struct sys_exit_args *ctx) {
  if(is_relevant()){
    common_handle_ex(ctx);
  }
  return 0;
}
