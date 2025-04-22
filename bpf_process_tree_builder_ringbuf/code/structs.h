#ifndef BASE_TABLE_ENTRY
#define BASE_TABLE_ENTRY

struct BaseTableEntry
{
  uint64_t global_id;
  uint64_t syscall_number;
  uint64_t enter_time;
  uint64_t process_ID;
  uint64_t process_owner_user_ID;
  uint64_t exit_time;
  uint64_t returned_value;
  uint32_t core_id;
  uint32_t is_returned;
};

/*struct PIDNameEntry {
  bool is_tracked;
  char proc_name[32];
};*/

struct ProgNameType
{
  char proc_name[32];
};

struct ProgSyscallsListType
{
  char is_syscall_typical[75]; // 8 bits * 75  = 600 bits
};

#endif
