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

int get_proc_stat(pid_t pid, PIDInfo *pibuf) {
	char buf[1024];
	char stat_path[PATH_MAX], cwd_path[PATH_MAX];
	int statfd, bytes_read, items;
	int getcwd_res;

	snprintf(stat_path, PATH_MAX, "/proc/%d/stat", pid);
	statfd = open(stat_path, O_RDONLY);
	ASSERT_RET(statfd != -1);

	memset(buf, 0, sizeof(buf));
	bytes_read = read(statfd, buf, sizeof(buf));
	if (bytes_read < 0) {
		close(statfd);
		ASSERT_RET(false);
	}

	items = sscanf(buf, "%d (%16[^)]) %c %d %d %d %lu", 
			&pibuf->pid, pibuf->comm, &pibuf->state,
			&pibuf->ppid, &pibuf->sid, &pibuf->pgid, &pibuf->ctty);
	if (items != 7) {
		close(statfd);
		ASSERT_RET(false);
	}

	snprintf(cwd_path, PATH_MAX, "/proc/%d/cwd", pid);
	getcwd_res = readlink(cwd_path, pibuf->cwd, sizeof(pibuf->cwd));
	if (getcwd_res < 0) {
		close(statfd);
		ASSERT_RET(false);
	}

	return 0;
}

int get_proc_cmdargs(pid_t pid, PIDInfo *pibuf) {
	PIDInfo buf;
	pid_t shell_pid;
	char extract_cmdargs[PATH_MAX + 100];
	int extract_cmdargs_res;

	shell_pid = getppid();
	ASSERT_RET(get_proc_stat(shell_pid, &buf) != -1);

	/* Capture output of parsed '/proc/[pid]/cmdline' and store it in `cmdlargs` */
	snprintf(extract_cmdargs, sizeof(extract_cmdargs), "tr '\\0' ' ' < /proc/%d/cmdline", pid);

	extract_cmdargs_res = exec_and_capture_output(extract_cmdargs, pibuf->cmdlargs);
	ASSERT_RET(extract_cmdargs_res != -1);

	return 0;
}

int get_proc_info(pid_t pid, PIDInfo *pibuf) {
	ASSERT_RET(get_proc_stat(pid, pibuf) != -1);
	ASSERT_RET(get_proc_cmdargs(pid, pibuf) != -1);

	return 0;
}

int get_terminal_emu_and_proc_info(PIDInfoArr **ttabs, int cfg_fd, pid_t ppid, enum action act) {
	PIDInfo shell_pinfo, terminal_pinfo, real_pinfo;

	ASSERT_RET(get_proc_stat(ppid, &shell_pinfo) != -1);
	ASSERT_RET(get_proc_stat(shell_pinfo.ppid, &terminal_pinfo) != -1);

	/* If program is ran with superuser priviledges (sudo), we traverse one level deeper into the process tree */
	if (getuid() != 0) {
		if (~act & TBM_SILENT) {
			printf("\nTerminal Emulator: %s (%d)\n", terminal_pinfo.comm, terminal_pinfo.pid);
		}

		return get_proc_info_ttabs(ttabs, cfg_fd, terminal_pinfo.pid, ppid, act);
	} else {
		ASSERT_RET(get_proc_stat(terminal_pinfo.ppid, &real_pinfo) != -1);

		return get_proc_info_ttabs(ttabs, cfg_fd, real_pinfo.ppid, real_pinfo.pid, act);
	}
}

/* Excluding PID of tab where script was ran (function isn't called directly normally, but instead used as a wrapper in `get_proc_info_ttabs` and `get_proc_info_cttabs`)  */
int getpid_of_tabs(PIDInfoArr **ttabs, pid_t ppid, pid_t mypid) {
	char buf[1024];
	char children_path[PATH_MAX];
	int childrenfd, bytes_read;

	/* Get child PIDs given their parent PID */
	snprintf(children_path, PATH_MAX, "/proc/%d/task/%d/children", ppid, ppid);
	childrenfd = open(children_path, O_RDONLY);
	ASSERT_RET(childrenfd != -1);

	bytes_read = read(childrenfd, buf, sizeof(buf));
	ASSERT_RET(bytes_read >= 0);

	/* Buffer holding precisely right amount of bytes from `/proc/[ppid]/task/[ppid]/children` */
	char cpid_buf[bytes_read];
	strncpy(cpid_buf, buf, bytes_read);

	/* Split `cpid_buf` into substrings and append children PID to yet another placeholder buf */
	char *temp = cpid_buf;
	// The third argument saveptr is a pointer to a char * 
	// variable that is used internally by strtok_r() in 
	// order to maintain context between successive calls
	// that parse the same string.
	char *childpid = strtok_r(temp, " ", &temp);

	pid_t *childpid_arr = calloc(CHILD_MAX, sizeof(pid_t));
	ASSERT_RET(*childpid_arr != -1);

	/* Populate the placeholder array for children PIDs */
	int cparr_index = 0;
	while (childpid != NULL) {
		char *endptr = NULL;
		childpid_arr[cparr_index++] = strtoul(childpid, &endptr, 10);
		childpid = strtok_r(temp, " ", &temp);
	}

        cparr_index = (!cparr_index) ? 1 : cparr_index;

	*ttabs = calloc(1, sizeof(PIDInfoArr));
	if (*ttabs == NULL) {
		free(childpid_arr);
		return -1;
	}

	int cpid_count = 0;
	for (int i = 0; i < CHILD_MAX; i++) {
		if (childpid_arr[i]) cpid_count++;
        }

	PIDInfoArr *cttabs = *ttabs;
	if (cparr_index > 0) {
		cttabs->pidlist = calloc(cpid_count, sizeof(PIDInfo));
		if (cttabs->pidlist == NULL) {
			free(childpid_arr);
			return -1;
		}
	}
	cttabs->pidlist_len = cpid_count;
	/* Set flag if child pid has any children */
	cttabs->has_children = (!bytes_read) ? false : true;

	/* Skip over PID of current tab and return the rest */
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

int get_proc_info_ttabs(PIDInfoArr **ttabs, int cfg_fd, pid_t term_pid, pid_t ppid, enum action act) {
	ASSERT_RET(getpid_of_tabs(ttabs, term_pid, ppid) != -1);

	/* A temporary struct `terminal_tabs` is used within this function to avoid deferencing/manipulating data in `ttabs` by accident (which is passed by reference in parent functions) */
	PIDInfoArr *terminal_tabs = *ttabs;
	if (act & TBM_SKIP_CURRENT_PID) {
		terminal_tabs->pidlist_len -= 1;
	}

	if (~act & TBM_SILENT) {
		/* NOTE: PID of current tab is skipped */
		printf("Child PIDs: %ld\n\nParent\n------\n%d\n", terminal_tabs->pidlist_len, term_pid);
	}

	/* Processes that all share the terminal emulator's PID as their parent process */
	for (int i = 0; i < terminal_tabs->pidlist_len; i++) {
		if (~act & TBM_SILENT)
			printf("  \u21b3 ");

		ASSERT_RET(get_proc_stat(terminal_tabs->pidlist[i].pid, &terminal_tabs->pidlist[i]) != -1);

		/* Get actual programs that user runs in the terminal here */
		PIDInfoArr *cttabs;
		ASSERT_RET(getpid_of_tabs(&cttabs, terminal_tabs->pidlist[i].pid, 0) != -1);

		/* Debug messages shown by default */
		if (~act & TBM_SILENT) {
			printf("%d (%s) [%ld]\n", terminal_tabs->pidlist[i].pid, terminal_tabs->pidlist[i].comm, cttabs->pidlist_len);
		}
		
		get_proc_info_cttabs(cfg_fd, terminal_tabs->pidlist[i], cttabs, act);
		free(cttabs->pidlist);
		free(cttabs);
	}

	return 0;
}

// TODO: Support logging of multiple tmux windows running simultaneously
// Counter that controls spacing of processes' debug info output
static int indentation_counter = 0;

/* Logging of terminal tab programs reside here */
void get_proc_info_cttabs(int cfg_fd, PIDInfo shell, PIDInfoArr *child, enum action act) {
	char buf[TBMARK_SINGLE_ENTRY_SIZE];

	if (~act & TBM_SILENT) {
		if (child->has_children) {
			for (int i = 0; i <= indentation_counter; i++) {
				printf("      ");
			}
			printf("\u21b3  ");
		} else 
			indentation_counter = (!child->has_children) 
				? 0 
				: indentation_counter + 1;
	}

        /* Empty shell tabs running nothing will be saved into the auto-generated config file, alongside existing shell programs */
        pid_t pid = child->pidlist[0].pid;
        pid_t ppid = shell.pid;
        char *cwd = (!pid) ? shell.cwd : child->pidlist[0].cwd;
        char *cmdlargs = (!pid) ? " ": child->pidlist[0].cmdlargs;

        if (pid) {
               	get_proc_stat(pid, &child->pidlist[0]);
                get_proc_cmdargs(pid, &child->pidlist[0]);
        }

	/* Print debug messages by default */
	if (~act & TBM_SILENT && pid) {
		printf("%d (%s)\n", pid, cmdlargs);
	}

	/* Log to tbmark config file (each 'iprogram' handles their own output formatting) */
	if (act & TBM_RDWR_PIDINFO) {
		int iprogram_index;
		char *iprogram_metadata = NULL;

		// NOTE: So no infinite loops arise
		if (~act & TBM_CALLED_FROM_IPROG) {
			iprogram_index = is_iprogram(cmdlargs);
			if (iprogram_index != -1) 
				/* All iprogram logger functions must return a buffer containing its program information, which we then use to concatenate to the main tbmark entry buf */
				iprogram_metadata = iprogram_loggers[iprogram_index](cfg_fd);
		}

		size_t ttab_entry_size = strnlen(cwd, PATH_MAX) + strnlen(cmdlargs, ARGMAX) + 18;
		switch (iprogram_index) {
			case 0:
				/* tmux is executed before subcommands are ran in their panes/windows */
				char *tmux_server_metadata;
				int get_tmux_server_metadata_res;
				char *count;
				int get_window_pane_count_res;
				size_t tmux_pane_count;
				char **tmux_panes_arr;
				/* `path` here is used for adding metadata information as well as removing pre-parsed entries in `tbmark.cfg` */
				char tmux_buf[IPROG_INFO_SIZE], path[PATH_MAX]; 

				tmux_server_metadata = calloc(PATH_MAX, sizeof(char));
				ASSERT_EXIT(tmux_server_metadata != NULL);

				/* Log socket path and pane count for our tmux server */
				get_tmux_server_metadata_res = exec_and_capture_output("tmux list-window -F 'socket_path:#{socket_path} pane_count:#{window_panes}'", tmux_server_metadata);
				ASSERT_EXIT(get_tmux_server_metadata_res != -1);

				/* NOTE: Since `exec_and_capture_output` returns a string via its arguments, it will need a heap-allocated string */
				count = calloc(2, sizeof(char));
				ASSERT_EXIT(count != NULL);

				/* With help of a tmux subcommand, we get the amount of panes in the most recently selected tmux window */
				get_window_pane_count_res = (int)exec_and_capture_output("tmux list-panes -F '#{window_panes}' | head -1", count);
				ASSERT_EXIT(get_window_pane_count_res != -1);
				tmux_pane_count = atoi(count);
				free(count);

				/* Append iprogram metadata to `buf` */
				ttab_entry_size = strnlen(cwd, PATH_MAX) + strnlen(cmdlargs, ARGMAX) + 31; // This number amounts to the length of other non-variable formatted strings below
				(strncmp(cmdlargs, "tmux", ARGMAX) != 0)
				       	? snprintf(buf, ttab_entry_size, "ppid:%d cwd:%s cmdlargs:<%s>\n", ppid, cwd, cmdlargs)
					: snprintf(buf, ttab_entry_size + strnlen(tmux_server_metadata, PATH_MAX), "cwd:%s cmdlargs:<%s> (metadata) %s\n", cwd, cmdlargs, tmux_server_metadata);

				if (iprogram_metadata != NULL) {
					char cfg[IPROG_INFO_SIZE];
					char **tbmark_cfg_entries;
					size_t tbmark_cfg_entries_len = 0;
					int fd;

					tmux_panes_arr = split(iprogram_metadata, '\n', tmux_pane_count, 0);
					snprintf(path, PATH_MAX, "%s/.tbmark-cfg", get_homedir_of_user(getuid()));
					ASSERT_EXIT((fd = cfg_open(path)) != -1);
					memset(&cfg, 0, IPROG_INFO_SIZE);
					ASSERT_EXIT(read(fd, cfg, IPROG_INFO_SIZE) != -1);
					tbmark_cfg_entries = split(cfg, '\n', TBMARK_PROG_MAX, &tbmark_cfg_entries_len);

					for (int j = 0; j < tmux_pane_count; j++) {
						for (int x = 0; x < tbmark_cfg_entries_len; x++) {
							if (strstr(tbmark_cfg_entries[x], "ppid:") != NULL) {
								char *tmux_panes_arr_pid = extract_tbm_entry_field_str(tmux_panes_arr[j], 16, "pane_pid:");
								char *tbmark_cfg_entries_pid = extract_tbm_entry_field_str(tbmark_cfg_entries[x], 12, "ppid:");

								/* Only append tmux pane programs in most recently selected window */
								if (strncmp(tmux_panes_arr_pid, tbmark_cfg_entries_pid, 7) == 0) {
									snprintf(tmux_buf, IPROG_INFO_SIZE, "%s [tmux] %s\n", 
											tbmark_cfg_entries[x] + (6 + strnlen(tbmark_cfg_entries_pid, 7)), 
											tmux_panes_arr[j] + (10 + strnlen(tbmark_cfg_entries_pid, 7)));
									strncat(buf, tmux_buf, strnlen(tmux_buf, IPROG_INFO_SIZE));
								}
								free(tbmark_cfg_entries_pid);
								free(tmux_panes_arr_pid);
							}
						}
					}
					free_str_arr(tbmark_cfg_entries, TBMARK_PROG_MAX);
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

	/* Check if stdin of `pid` is ready to be written to */
	// NOTE: Running `tbmark open` with strace returns a -ENOTTY since input doesn't come from a terminal
	select_ret = select(fd+1, NULL, &rfds, NULL, NULL);
	ASSERT_EXIT(select_ret != -1);

       	if (FD_ISSET(fd, &rfds)) {
		/* Don't write the NULL byte to stdin */
		for (int i = 0; i < cmd_len; i++) {
			ASSERT_EXIT(ioctl(fd, TIOCSTI, &cmd[i]) != -1);
		}
	} 
	close(fd);

	return 0;
}
