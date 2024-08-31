#ifndef TBMARK_PROC_H
#define TBMARK_PROC_H

#include <stdbool.h>
#include <aio.h>
#include <xdo.h>
#include "common.h"

typedef struct {
	pid_t pid;
	char comm[17];
	char state;
	pid_t ppid, sid, pgid;
	dev_t ctty;
	char cwd[ARG_MAX];
	char cmdlargs[ARG_MAX];
} PIDInfo; 

typedef struct {
	PIDInfo *pidlist;
	size_t pidlist_len;
	bool has_children;
} PIDInfoArr;

int get_proc_stat(pid_t pid, PIDInfo *statusOut);
int get_proc_cmdargs(pid_t pid, PIDInfo *cmdargsOut);
Window get_proc_window_id(pid_t pid);
int get_terminal_emu_and_proc_info(PIDInfoArr **ttabs, int cfg_fd, pid_t ppid, enum tbm_actions actions);
int getpid_of_tabs(PIDInfoArr **ttabs, pid_t ppid, pid_t mypid);

// PID of terminal and shell processes
int get_proc_info_ttabs(PIDInfoArr **ttabs, int cfg_fd, pid_t term_pid, pid_t ppid, enum tbm_actions actions);

// PID of the actual shell programs running
void get_proc_info_cttabs(int cfg_fd, PIDInfo shell, PIDInfoArr **child, enum tbm_actions actions);
int write_proc_stdin(pid_t pid, const char *cmd, size_t cmdLen);

#endif // TBMARK_PROC_H
