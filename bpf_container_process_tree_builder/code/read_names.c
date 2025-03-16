// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <stdlib.h>

#include "structs.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	int err;
        libbpf_set_print(libbpf_print_fn);

        int PIDName_map_fd = bpf_obj_get("/sys/fs/bpf/PIDName");
        
        bool not_found_PIDName = (PIDName_map_fd < 0);
        printf("\n----------------------------------\n");
        printf("\nPIDName_map_fd: %d\n", PIDName_map_fd);
        printf("\n----------------------------------\n");
        
        if (not_found_PIDName) {
          printf("\n----------------------------------\n");
          printf("\nPinned map NOT FOUND\n");
          printf("\nExiting\n");
          printf("\n----------------------------------\n");
          return 0;
        }

        struct bpf_map_info info = {};
        uint32_t info_len = sizeof(struct bpf_map_info);
      
        bpf_map_get_info_by_fd(PIDName_map_fd, &info, &info_len);
        
        printf("\nMax entries: %d\n", info.max_entries);
        
        
        uint64_t p_key = 0, p_next_key = 0;
        int ret = bpf_map_get_next_key(PIDName_map_fd, NULL, &p_next_key);
        
        while (ret != -ENOENT) {
          struct PIDNameEntry value = {};
          p_key = p_next_key;
          ret = bpf_map_get_next_key(PIDName_map_fd, &p_key, &p_next_key);
        
          bpf_map_lookup_elem(PIDName_map_fd, &p_key, &value);
          
          if(value.is_tracked){
            printf("\nTGID: %llu | %s | TRACKED", p_key, value.proc_name);
          }
          else
          {
            printf("\nTGID: %llu | %s | UNTRACKED", p_key, value.proc_name);
          }
        }
        
        printf("\n");
        return 0;
}
