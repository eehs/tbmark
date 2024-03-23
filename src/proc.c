#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

#include "proc.h"
#include "debug.h"
#include "config.h"
#include "helpers.h"

int get_proc_stat(pid_t pid, PIDInfo *status_result) {
	char procfs_status_buf[1024];
	char stat_path[PATH_MAX], cwd_path[PATH_MAX];
	int statfd, bytes_read, items;
	int getcwd_res;

	snprintf(stat_path, PATH_MAX, "/proc/%d/stat", pid);
	statfd = open(stat_path, O_RDONLY);
	ASSERT_RET(statfd != -1);

	memset(procfs_status_buf, 0, sizeof(procfs_status_buf));
	bytes_read = read(statfd, procfs_status_buf, sizeof(procfs_status_buf));
	if (bytes_read < 0) {
		close(statfd);
		ASSERT_RET(false);
	}

	items = sscanf(procfs_status_buf, "%d (%16[^)]) %c %d %d %d %lu", 
			&status_result->pid, status_result->comm, &status_result->state,
			&status_result->ppid, &status_result->sid, &status_result->pgid, &status_result->ctty);
	if (items != 7) {
		close(statfd);
		ASSERT_RET(false);
	}

	snprintf(cwd_path, PATH_MAX, "/proc/%d/cwd", pid);
	getcwd_res = readlink(cwd_path, status_result->cwd, sizeof(status_result->cwd));
	if (getcwd_res < 0) {
		close(statfd);
		ASSERT_RET(false);
	}

	return 0;
}

int get_proc_cmdargs(pid_t pid, PIDInfo *cmdargs_result) {
	PIDInfo procfs_cmdargs_buf;
	pid_t shell_pid;
	char extract_cmdargs[PATH_MAX + 100];
	int extract_cmdargs_res;

	shell_pid = getppid();
	ASSERT_RET(get_proc_stat(shell_pid, &procfs_cmdargs_buf) != -1);

	// Capture output of parsed '/proc/[pid]/cmdline' and store it in `cmdlargs` 
	snprintf(extract_cmdargs, sizeof(extract_cmdargs), "tr '\\0' ' ' < /proc/%d/cmdline", pid);

	extract_cmdargs_res = exec_and_capture_output(extract_cmdargs, cmdargs_result->cmdlargs);
	ASSERT_RET(extract_cmdargs_res != -1);

	return 0;
}

int get_proc_info(pid_t pid, PIDInfo *result) {
	ASSERT_RET(get_proc_stat(pid, result) != -1);
	ASSERT_RET(get_proc_cmdargs(pid, result) != -1);

	return 0;
}

int get_terminal_emu_and_proc_info(PIDInfoArr **ttabs, int cfg_fd, pid_t ppid, enum tbm_flags flags) {
	PIDInfo shell_pinfo, terminal_pinfo, real_pinfo;

	ASSERT_RET(get_proc_stat(ppid, &shell_pinfo) != -1);
	ASSERT_RET(get_proc_stat(shell_pinfo.ppid, &terminal_pinfo) != -1);

	// If program is ran with superuser privileges (sudo), we traverse one level deeper in the process tree 
	if (getuid() != 0) {
		if (~flags & TBM_SILENT) {
			printf("\nTerminal Emulator: %s (%d)\n", terminal_pinfo.comm, terminal_pinfo.pid);
		}

		return get_proc_info_ttabs(ttabs, cfg_fd, terminal_pinfo.pid, ppid, flags);
	} else {
		ASSERT_RET(get_proc_stat(terminal_pinfo.ppid, &real_pinfo) != -1);

		return get_proc_info_ttabs(ttabs, cfg_fd, real_pinfo.ppid, real_pinfo.pid, flags);
	}
}

// Excluding PID of tab where script was ran (function isn't called directly normally, but instead used as a wrapper in `get_proc_info_ttabs` and `get_proc_info_cttabs`) [cpid = child PID] 
int getpid_of_tabs(PIDInfoArr **ttabs, pid_t ppid, pid_t mypid) {
	char procfs_cpid_path[PATH_MAX], procfs_cpid_data[1024];
	int childpid_fd, bytes_read;

	// Get child PIDs given their parent PID 
	snprintf(procfs_cpid_path, PATH_MAX, "/proc/%d/task/%d/children", ppid, ppid);
	childpid_fd = open(procfs_cpid_path, O_RDONLY);
	ASSERT_RET(childpid_fd != -1);

	bytes_read = read(childpid_fd, procfs_cpid_data, sizeof(procfs_cpid_data));
	ASSERT_RET(bytes_read >= 0);

	// Buffer holding precisely right amount of bytes from `/proc/[ppid]/task/[ppid]/children` 
	char childpid_buf[bytes_read];
	strncpy(childpid_buf, procfs_cpid_data, bytes_read);

	// Split `childpid_buf` into substrings and append the child PIDs to an array (which we will use for future accesses) 
	char *temp = childpid_buf;

	// The third argument saveptr is a pointer to a (char *)
	// variable that is used internally by strtok_r() in 
	// order to maintain context between successive calls
	// that parse the same string.
	char *childpid = strtok_r(temp, " ", &temp);

	pid_t *childpid_arr = calloc(CHILD_MAX, sizeof(pid_t));
	ASSERT_RET(*childpid_arr != -1);

	// Populate `childpid_arr` with string-split child PIDs done above 
	int childpid_index = 0;
	while (childpid != NULL) {
		char *endptr = NULL;
		childpid_arr[childpid_index++] = strtoul(childpid, &endptr, 10);
		childpid = strtok_r(temp, " ", &temp);
	}

        // The default index number, and therefore length of the `childpid_arr` is set to 1 despite being empty. This is done so that terminal tabs not running any program (but reside in a directory) can be saved with tbmark 
        childpid_index = (!childpid_index) ? 1 : childpid_index;

	*ttabs = calloc(1, sizeof(PIDInfoArr));
	if (*ttabs == NULL) {
		free(childpid_arr);
		return -1;
	}

	int childpid_count = 0;
	for (int i = 0; i < CHILD_MAX; i++) {
		if (childpid_arr[i]) childpid_count++;
        }

	PIDInfoArr *cttabs = *ttabs;
	if (childpid_index > 0) {
		cttabs->pidlist = calloc(childpid_count, sizeof(PIDInfo));
		if (cttabs->pidlist == NULL) {
			free(childpid_arr);
			return -1;
		}
	}
	cttabs->pidlist_len = childpid_count;
	// Set flag if child pid has any children 
	cttabs->has_children = (!bytes_read) ? false : true; // Only used for formatting when displaying saved terminal tabs (so far)

	// Skip over current tab (its PID) and return the rest 
	for (int i = 0, hit_mypid_flag = 0; i < cttabs->pidlist_len; i++) {
        	if (childpid_arr[i] == mypid) {
                	cttabs->pidlist[i].pid = childpid_arr[i + 1];
                	hit_mypid_flag = 1;
        	} else {
	        	cttabs->pidlist[i].pid = (hit_mypid_flag) 
		       		? childpid_arr[i + 1] 
		        	: childpid_arr[i];
                }
	}
	free(childpid_arr);

	return 0;
}

int get_proc_info_ttabs(PIDInfoArr **ttabs, int cfg_fd, pid_t term_pid, pid_t ppid, enum tbm_flags flags) {
	ASSERT_RET(getpid_of_tabs(ttabs, term_pid, ppid) != -1);

	// A temporary struct `terminal_tabs` is used within this function to avoid deferencing/manipulating data in `ttabs` by accident (which is passed by reference in parent functions) 
	PIDInfoArr *terminal_tabs = *ttabs;
	if (flags & TBM_SKIP_CURRENT_PID) {
		terminal_tabs->pidlist_len -= 1;
	}

	if (~flags & TBM_SILENT) {
		// NOTE: PID of current tab is skipped 
		printf("Child PIDs: %ld\n\nParent\n------\n%d\n", terminal_tabs->pidlist_len, term_pid);
	}

	// Processes that all share the terminal emulator's PID as their parent process 
	for (int i = 0; i < terminal_tabs->pidlist_len; i++) {
		if (~flags & TBM_SILENT) {
			printf("  \u21b3 ");
                }

		ASSERT_RET(get_proc_stat(terminal_tabs->pidlist[i].pid, &terminal_tabs->pidlist[i]) != -1);

		// Get actual programs that user runs in each terminal tab here 
		PIDInfoArr *cttabs;
		ASSERT_RET(getpid_of_tabs(&cttabs, terminal_tabs->pidlist[i].pid, 0) != -1);

		if (~flags & TBM_SILENT) {
			printf("%d (%s) [%ld]\n", terminal_tabs->pidlist[i].pid, terminal_tabs->pidlist[i].comm, cttabs->pidlist_len);
		}
		
		get_proc_info_cttabs(cfg_fd, terminal_tabs->pidlist[i], cttabs, flags);
		free(cttabs->pidlist);
		free(cttabs);
	}

	return 0;
}

// TODO: Support logging of multiple tmux windows running simultaneously
// Counter that controls spacing of processes' debug info output
static int indentation_counter = 0;

// Logging of terminal tab programs reside here 
void get_proc_info_cttabs(int cfg_fd, PIDInfo shell, PIDInfoArr *child, enum tbm_flags flags) {
	char buf[TBMARK_SINGLE_ENTRY_SIZE];

	if (~flags & TBM_SILENT) {
		if (child->has_children) {
			for (int i = 0; i <= indentation_counter; i++) {
				printf("      ");
			}
			printf("\u21b3  ");
		} else 
			indentation_counter = (!child->has_children) ? 0 : indentation_counter + 1;
	}

        // Empty shell tabs running nothing will be saved into the auto-generated config file, alongside existing shell programs 
        pid_t pid = child->pidlist[0].pid;
        pid_t ppid = shell.pid;
        char *cwd = (!pid) ? shell.cwd : child->pidlist[0].cwd;
        char *cmdlargs = (!pid) ? " " : child->pidlist[0].cmdlargs;

        if (pid) {
               	get_proc_stat(pid, &child->pidlist[0]);
                get_proc_cmdargs(pid, &child->pidlist[0]);
        }

	if (~flags & TBM_SILENT && pid) {
		printf("%d (%s)\n", pid, cmdlargs);
	}

	// Log to tbmark config file (each 'iprogram' handles their own output formatting) 
	if (flags & TBM_RDWR_PIDINFO) {
		int iprogram_index = 0;
		char *iprogram_metadata = NULL;

		// NOTE: So no infinite loops arise
		if (~flags & TBM_CALLED_FROM_IPROG) {
			iprogram_index = is_iprogram(cmdlargs);
			if (iprogram_index != -1) {
				// All iprogram logger functions must return a buffer containing its program information, which we then use to concatenate to the main tbmark entry buf 
				iprogram_metadata = iprogram_loggers[iprogram_index](cfg_fd);
                        }
		}

		size_t ttab_entry_size = strnlen(cwd, PATH_MAX) + strnlen(cmdlargs, ARGMAX) + 18;
		switch (iprogram_index) {
                        // tmux
			case 0: ;
				// tmux is executed before subcommands are ran in their panes/windows 
				char *tmux_server_metadata;
				int get_tmux_server_metadata_res;
				char *count;
				int get_window_pane_count_res;
				size_t tmux_pane_count;
				char **tmux_panes_arr;

				// `cfgpath` here is used for adding metadata information and removing pre-parsed entries in the tbmark configuration file 
				char cfg_fdpath[22], cfgpath[PATH_MAX], tmux_buf[IPROG_INFO_SIZE];

				tmux_server_metadata = calloc(PATH_MAX, sizeof(char));
				ASSERT_EXIT(tmux_server_metadata != NULL);

				// Log socket path and pane count for our tmux server 
				get_tmux_server_metadata_res = exec_and_capture_output("tmux list-window -F 'socket_path:#{socket_path} pane_count:#{window_panes}'", tmux_server_metadata);
				ASSERT_EXIT(get_tmux_server_metadata_res != -1);

				// NOTE: Since `exec_and_capture_output` returns a string via its arguments, it will need a heap-allocated string 
				count = calloc(2, sizeof(char));
				ASSERT_EXIT(count != NULL);

				// With help of a tmux subcommand, we get the amount of panes in the most recently selected tmux window 
				get_window_pane_count_res = (int)exec_and_capture_output("tmux list-panes -F '#{window_panes}' | head -1", count);
				ASSERT_EXIT(get_window_pane_count_res != -1);
				tmux_pane_count = atoi(count);
				free(count);

				// Append tmux pane command and metadata to `buf`
				ttab_entry_size = strnlen(cwd, PATH_MAX) + strnlen(cmdlargs, ARGMAX) + 31; // This number amounts to the total length of other non-variable formatted strings below
				(strncmp(cmdlargs, "tmux", ARGMAX) != 0)
				       	? snprintf(buf, ttab_entry_size, "ppid:%d cwd:%s cmdlargs:<%s>\n", ppid, cwd, cmdlargs)
					: snprintf(buf, ttab_entry_size + strnlen(tmux_server_metadata, PATH_MAX), "cwd:%s cmdlargs:<%s> (metadata) %s\n", cwd, cmdlargs, tmux_server_metadata);

				if (iprogram_metadata != NULL) {
					char cfg[IPROG_INFO_SIZE];
					char **tbmark_cfg_entries;
					size_t tbmark_cfg_entries_len = 0;
					int fd;

					tmux_panes_arr = split(iprogram_metadata, '\n', tmux_pane_count, 0);

                                        // Obtain full path of tbmark config file, we do it this way since the config file's name may be user-defined
                                        snprintf(cfg_fdpath, 22, "/proc/self/fd/%d", cfg_fd);
                                        readlink(cfg_fdpath, cfgpath, PATH_MAX);

                                        // Open the config file for appending tmux data
					ASSERT_EXIT((fd = cfg_open(cfgpath)) != -1);
					memset(&cfg, 0, IPROG_INFO_SIZE);
					ASSERT_EXIT(read(fd, cfg, IPROG_INFO_SIZE) != -1);

					tbmark_cfg_entries = split(cfg, '\n', MAX_TBMARK_TABS, &tbmark_cfg_entries_len);

					for (int j = 0; j < tmux_pane_count; j++) {
						for (int k = 0; k < tbmark_cfg_entries_len; k++) {
							if (strstr(tbmark_cfg_entries[k], "ppid:") != NULL) {
								char *tmux_panes_arr_pid = extract_tbm_entry_field_str(tmux_panes_arr[j], 16, "pane_pid:");
								char *tbmark_cfg_entries_pid = extract_tbm_entry_field_str(tbmark_cfg_entries[k], 12, "ppid:");

								// NOTE: Only tmux pane programs in the most recently selected window will be appended (ONE tmux window ONLY)
								if (strncmp(tmux_panes_arr_pid, tbmark_cfg_entries_pid, 7) == 0) {
									snprintf(tmux_buf, IPROG_INFO_SIZE, "%s [tmux] %s\n", 
											tbmark_cfg_entries[k] + (6 + strnlen(tbmark_cfg_entries_pid, 7)), 
											tmux_panes_arr[j] + (10 + strnlen(tbmark_cfg_entries_pid, 7)));
									strncat(buf, tmux_buf, strnlen(tmux_buf, IPROG_INFO_SIZE));
								}
								free(tbmark_cfg_entries_pid);
								free(tmux_panes_arr_pid);
							}
						}
					}
					free_str_arr(tbmark_cfg_entries, MAX_TBMARK_TABS);
					free_str_arr(tmux_panes_arr, tmux_pane_count);
				}
				free(tmux_server_metadata);
				free(iprogram_metadata);

				if (cfg_write(cfg_fd, buf, strnlen(buf, sizeof(buf))) == -1) break;
				break;
			default:
				snprintf(buf, ttab_entry_size, "cwd:%s cmdlargs:<%s>\n", cwd, cmdlargs);
				if (cfg_write(cfg_fd, buf, strnlen(buf, sizeof(buf))) == -1) break;
				break;
		}
        }
}

int write_proc_stdin(pid_t pid, const char *cmd, size_t cmd_len) {
	int fd;
	char fdpath[PATH_MAX];
	fd_set rfds;
	int select_ret;

	snprintf(fdpath, PATH_MAX, "/proc/%d/fd/0", pid);
	fd = open(fdpath, O_RDWR);
	ASSERT_RET(fd != -1);

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	// Checks if stdin of `pid` is ready to be written to
	// NOTE: Running `tbmark open` with strace returns a -ENOTTY since input doesn't come from a terminal
	select_ret = select(fd + 1, NULL, &rfds, NULL, NULL);
	ASSERT_EXIT(select_ret != -1);

       	if (FD_ISSET(fd, &rfds)) {
		// Don't write NULL byte to stdin
		for (int i = 0; i < cmd_len; i++) {
			ASSERT_EXIT(ioctl(fd, TIOCSTI, &cmd[i]) != -1);
		}
	} 
	close(fd);

	return 0;
}
