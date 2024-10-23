#ifndef TBMARK_COMMON_H
#define TBMARK_COMMON_H

#define ARG_MAX                                 131072
#define IPROG_INFO_SIZE                         1024

#define USER_MAX                                sysconf(_SC_LOGIN_NAME_MAX)
#define FILE_NAME_MAX_LEN                       255
#define CHILD_MAX                               sysconf(_SC_CHILD_MAX)
#define PID_MAX_LEN                             7
#define PID_MAX_LEN_WITH_NB                     8
#define COMM_MAX_LEN                            17

#define INTERACTIVE_PROGRAMS_COUNT              1
#define TBMARK_SINGLE_ENTRY_SIZE                4096
#define MAX_TBMARK_TABS                         20
#define MAX_TBMARK_ENTRIES                      50
#define MAX_TAG_LEN                             15      // Longest tag being 'pane_at_bottom:' from 'tmux' thus far

enum tbm_options {
        OPTION_SAVE = 1,
        OPTION_RESTORE = 2,
        OPTION_LIST = 4,
        OPTION_VERBOSE = 8,
};

enum tbm_actions {
        TBM_SILENT = 1, // Omits debug messages
        TBM_RDWR_PIDINFO = 2, // Defaults to read-only if this flag is not set
        TBM_CALLED_FROM_IPROG = 4,
};

#endif // TBMARK_COMMON_H
