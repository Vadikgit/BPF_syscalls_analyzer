// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include "syscalls_names.h"
#include "structs.h"


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	int err;
        libbpf_set_print(libbpf_print_fn);

        int BaseTableMap_map_fd = bpf_obj_get("/sys/fs/bpf/BaseTableMap");
        
        bool not_found_BaseTableMap = (BaseTableMap_map_fd < 0);
        printf("\n----------------------------------\n");
        printf("\nBaseTableMap_map_fd: %d\n", BaseTableMap_map_fd);
        printf("\n----------------------------------\n");
        
        if (not_found_BaseTableMap) {
          printf("\n----------------------------------\n");
          printf("\nPinned map NOT FOUND\n");
          printf("\nExiting\n");
          printf("\n----------------------------------\n");
          return 0;
        }

        struct bpf_map_info info = {};
        uint32_t info_len = sizeof(struct bpf_map_info);
      
        bpf_map_get_info_by_fd(BaseTableMap_map_fd, &info, &info_len);
        
        printf("\nMax entries: %d\n", info.max_entries);
        
        uint32_t first_key_to_print = 0;
        uint32_t num_of_entries_to_print = info.max_entries;
        
        if (argc == 2){
          num_of_entries_to_print = atoll(argv[1]);
          printf("\nPrinting first %llu entries\n", num_of_entries_to_print);
          
        } else if (argc == 3){
          first_key_to_print = atoll(argv[1]);
          num_of_entries_to_print = atoll(argv[2]);
          printf("\nPrinting %llu\n entries since %llu", num_of_entries_to_print, first_key_to_print);
        }
        
        for (int i = first_key_to_print; i < first_key_to_print + num_of_entries_to_print; i++){
          struct BaseTableEntry MapElem;
          
          bpf_map_lookup_elem(BaseTableMap_map_fd, &i, &MapElem);
          
          if(MapElem.is_returned) {
            printf("\n%10llu | glob_id: %llu | syscall: %s | TGID: %lu | PID: %lu | GID: %lu | UID: %lu | ret: %llu | enter: %llu | exit: %llu (%llu ns)",  
            i, 
            MapElem.global_id, 
            syscalls_names[MapElem.syscall_number], 
            MapElem.process_ID >> 32,
            (MapElem.process_ID << 32) >> 32,
            MapElem.process_owner_user_ID >> 32,
            (MapElem.process_owner_user_ID << 32) >> 32,
            MapElem.returned_value,
            MapElem.enter_time, 
            MapElem.exit_time,
            (MapElem.exit_time - MapElem.enter_time));
          }
          else
          {
            printf("\n%10llu | glob_id: %llu | syscall: %s | enter: %llu | TGID: %lu | PID: %lu | GID: %lu | UID: %lu | --NO RETURN-- ", 
            i, 
            MapElem.global_id, 
            syscalls_names[MapElem.syscall_number], 
            MapElem.enter_time,
            MapElem.process_ID >> 32,
            (MapElem.process_ID << 32) >> 32,
            MapElem.process_owner_user_ID >> 32,
            (MapElem.process_owner_user_ID << 32) >> 32);
          }
        }
        
        printf("\n");
        return 0;
}
