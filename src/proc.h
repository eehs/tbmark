#ifndef _PROC_HEADER
#define _PROC_HEADER

#include <stdbool.h>
#include <aio.h>
#include <linux/limits.h>

#define ARGMAX 131072
#define USER_MAX 32
#define FILE_NAME_MAX_LEN 255
#define CHILD_MAX sysconf(_SC_CHILD_MAX)
#define PIPE_RD 0
#define PIPE_WR 1

#define INTERACTIVE_PROGRAMS_COUNT 1
#define TBMARK_SINGLE_ENTRY_SIZE 4096
#define MAX_TBMARK_TABS 20

enum tbm_flags {
	// Flags for omitting debug output
	TBM_SILENT = 1,
	TBM_RDONLY_PIDINFO = 2, // This bit flag isn't tbm_flagsually used anywhere, but solely exists for explicity purposes
	TBM_RDWR_PIDINFO = 4,

	// Option to skip current PID when obtaining process info of terminal tabs (Since `get_proc_info_ttabs` will be reused, we don't always want to skip the PID of the current terminal)
	TBM_SKIP_CURRENT_PID = 8,
	TBM_CALLED_FROM_IPROG = 16
};

typedef struct {
	pid_t pid;
	char comm[17];
	char state;
	pid_t ppid, sid, pgid;
	dev_t ctty;
	char cwd[ARGMAX];
	char cmdlargs[ARGMAX];
} PIDInfo; 

typedef struct {
	PIDInfo *pidlist;
	size_t pidlist_len;
	bool has_children;
} PIDInfoArr;

int get_proc_stat(pid_t pid, PIDInfo *status_result);
int get_proc_cmdargs(pid_t pid, PIDInfo *cmdargs_result);
int get_proc_info(pid_t pid, PIDInfo *result);
int get_terminal_emu_and_proc_info(PIDInfoArr **ttabs, int cfg_fd, pid_t ppid, enum tbm_flags flags);
int getpid_of_tabs(PIDInfoArr **ttabs, pid_t ppid, pid_t mypid);

// PID of terminal and shell processes
int get_proc_info_ttabs(PIDInfoArr **ttabs, int cfg_fd, pid_t term_pid, pid_t ppid, enum tbm_flags flags);

// PID of the actual shell programs running
void get_proc_info_cttabs(int cfg_fd, PIDInfo shell, PIDInfoArr *child, enum tbm_flags flags);
int write_proc_stdin(pid_t pid, const char *cmd, size_t cmd_len);

#endif // _PROC_HEADER
