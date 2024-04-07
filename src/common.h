#ifndef _COMMON_HEADER
#define _COMMON_HEADER

#define ARG_MAX                                 131072
#define IPROG_INFO_SIZE                         1024

#define USER_MAX                                sysconf(_SC_LOGIN_NAME_MAX)
#define FILE_NAME_MAX_LEN                       255
#define CHILD_MAX                               sysconf(_SC_CHILD_MAX)
#define PID_MAX_LEN                             7
#define COMM_MAX_LEN                            17
#define PIPE_RD                                 0
#define PIPE_WR                                 1

#define INTERACTIVE_PROGRAMS_COUNT              1
#define TBMARK_SINGLE_ENTRY_SIZE                4096
#define MAX_TBMARK_TABS                         20
#define MAX_TBMARK_ENTRIES                      50
#define MAX_TAG_LEN                             15      // Longest tag being 'pane_at_bottom:' from 'tmux' thus far

#endif // _COMMON_HEADER
