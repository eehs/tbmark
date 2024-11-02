#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <regex.h>

#include "proc.h"
#include "config.h"
#include "helpers.h"
#include "debug.h"

int get_proc_stat(pid_t pid, PIDInfo *statusOut) {
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
			&statusOut->pid, statusOut->comm, &statusOut->state,
			&statusOut->ppid, &statusOut->sid, &statusOut->pgid, &statusOut->ctty);
	if (items != 7) {
		close(statfd);
		ASSERT_RET(false);
	}

	snprintf(cwd_path, PATH_MAX, "/proc/%d/cwd", pid);
	getcwd_res = readlink(cwd_path, statusOut->cwd, sizeof(statusOut->cwd));
	if (getcwd_res < 0) {
		close(statfd);
		ASSERT_RET(false);
	}

	return 0;
}

int get_proc_cmdargs(pid_t pid, PIDInfo *cmdArgsOut) {
	char extract_cmdargs_cmd[PATH_MAX + 100];
	int extract_cmdargs_cmd_res;

	// Capture output of parsed '/proc/[pid]/cmdline'
	snprintf(extract_cmdargs_cmd, sizeof(extract_cmdargs_cmd), "tr '\\0' ' ' < /proc/%d/cmdline", pid);

	extract_cmdargs_cmd_res = exec_cmd_and_capture_output(extract_cmdargs_cmd, cmdArgsOut->cmdlargs, sizeof(cmdArgsOut->cmdlargs));
	ASSERT_RET(extract_cmdargs_cmd_res != -1);

	return 0;
}

Window get_proc_window_id(pid_t pid) {
        char extract_environ_cmd[40];
        int extract_environ_cmd_res;
        char environ_buf[4096]; // this ceiling may not be enough, given the number of environment variables one might have

        regex_t window_id_regex;
        regmatch_t window_id_index;
        int window_id_regex_res;

        char window_id_str[25];

	// Capture window id of parsed '/proc/[pid]/environ' 
	snprintf(extract_environ_cmd, sizeof(extract_environ_cmd), "tr '\\0' ' ' < /proc/%d/environ", pid);

        extract_environ_cmd_res = exec_cmd_and_capture_output(extract_environ_cmd, environ_buf, sizeof(environ_buf));
        ASSERT_RET(extract_environ_cmd_res != -1);

        regcomp(&window_id_regex, "WINDOWID=([0-9]{1,10})", REG_EXTENDED);
        window_id_regex_res = regexec(&window_id_regex, environ_buf, 1, &window_id_index, 0);

        regfree(&window_id_regex);
        if (window_id_regex_res == 0) {
                int j = 0;
                for (int i = window_id_index.rm_so; i < window_id_index.rm_eo; i++, j++) {
                        window_id_str[j] = environ_buf[i];
                }

                window_id_str[j] = '\0';
        }

        return (Window)atoi(window_id_str + 9);
}

int get_terminal_emu_and_proc_info(PIDInfoArr **ttabs, int cfg_fd, pid_t ppid, enum tbm_actions actions) {
	PIDInfo shell_pinfo, terminal_pinfo, real_pinfo;

	ASSERT_RET(get_proc_stat(ppid, &shell_pinfo) != -1);
	ASSERT_RET(get_proc_stat(shell_pinfo.ppid, &terminal_pinfo) != -1);

        if (~actions & TBM_SILENT)
                DEBUG("Obtaining shell process information");

	// If program is ran with superuser privileges (sudo), we traverse one layer deeper in the process tree 
	if (getuid() != 0) {
		if (~actions & TBM_SILENT)
			printf("\n%d (%s) ", terminal_pinfo.pid, terminal_pinfo.comm);

		return get_proc_info_ttabs(ttabs, cfg_fd, terminal_pinfo.pid, ppid, actions);

	} else {
		ASSERT_RET(get_proc_stat(terminal_pinfo.ppid, &real_pinfo) != -1);

		return get_proc_info_ttabs(ttabs, cfg_fd, real_pinfo.ppid, real_pinfo.pid, actions);
	}
}

// Excludes PID of tab where tbmark ran 
int getpid_of_tabs(PIDInfoArr **ttabs, pid_t ppid, pid_t mypid) {
        Window active_window_id;
	char procfs_cpid_path[PATH_MAX], procfs_cpid_data[1024];
	int childpid_fd, bytes_read;

        // Get active window id
        xdo_t *xdo = xdo_new(NULL);
        xdo_get_active_window(xdo, &active_window_id);
        xdo_free(xdo);

	// Get child pids given their parent pid 
	snprintf(procfs_cpid_path, PATH_MAX, "/proc/%d/task/%d/children", ppid, ppid);
	childpid_fd = open(procfs_cpid_path, O_RDONLY);
	ASSERT_RET(childpid_fd != -1);

	bytes_read = read(childpid_fd, procfs_cpid_data, sizeof(procfs_cpid_data));
	ASSERT_RET(bytes_read >= 0);

	// Buffer holding precisely right amount of bytes from '/proc/[ppid]/task/[ppid]/children'
	char proc_children_buf[bytes_read];
	strncpy(proc_children_buf, procfs_cpid_data, bytes_read);

	// Split list of children pids into substrings 
	char *temp = proc_children_buf;
	char *childpid_str = strtok_r(temp, " ", &temp); // The third argument, 'saveptr', is a pointer to a (char *) variable that is used internally by strtok_r() in order to maintain context between successive calls that parse the same string

	pid_t *childpid_arr = calloc(CHILD_MAX, sizeof(pid_t));
	ASSERT_RET(*childpid_arr != -1);

	// Populate placeholder array with relevant child pids and note it's size simultaneously
	int childpid_count = 0;
	while (childpid_str != NULL) {
                char *endptr = NULL;

                pid_t childpid = strtoul(childpid_str, &endptr, 10);
                if (childpid > 0) {
                        // Hop over current tab and make sure we filter out tabs that are not part of the current window
                        if (childpid != mypid) {
                                if (strlen(childpid_str) > 1 && get_proc_window_id(childpid) == active_window_id)
        	        	        childpid_arr[childpid_count++] = childpid;
                        }
                }

		childpid_str = strtok_r(temp, " ", &temp);
	}

	*ttabs = calloc(1, sizeof(PIDInfoArr));
	if (*ttabs == NULL) {
		free(childpid_arr);
		return -1;
	}

        // We set the number of children pids to 1 here if no children pid was found, which is equivalent to ONE shell program (like vim or less) being parented by a shell process
        if (childpid_count == 0)
                childpid_count = 1;

        (*ttabs)->pidlist = calloc(childpid_count, sizeof(PIDInfo));
        if ((*ttabs)->pidlist == NULL) {
                free(childpid_arr);
                return -1;
        }

        // Only used for formatting when displaying saved terminal tabs (can definitely be refactored)
        (*ttabs)->has_children = (!bytes_read) ? false : true;
        (*ttabs)->pidlist_len = 0;

	for (int i = 0; i < childpid_count; i++) {
	        (*ttabs)->pidlist[i].pid = childpid_arr[i];
                (*ttabs)->pidlist_len++;
	}

	free(childpid_arr);

	return 0;
}

int get_proc_info_ttabs(PIDInfoArr **ttabs, int cfg_fd, pid_t term_pid, pid_t ppid, enum tbm_actions actions) {
	ASSERT_RET(getpid_of_tabs(ttabs, term_pid, ppid) != -1);

	PIDInfoArr *terminal_tabs = *ttabs;

	if (~actions & TBM_SILENT && ~actions & TBM_CALLED_FROM_IPROG)
		printf("[%ld]\n", terminal_tabs->pidlist_len);

	for (int i = 0; i < terminal_tabs->pidlist_len; i++) {
                if (~actions & TBM_SILENT) {
                        if (i > 0 && ~actions & TBM_CALLED_FROM_IPROG)
                                printf("\n");

                        if (actions & TBM_CALLED_FROM_IPROG)
                                printf("        ");

			printf("  \u21b3 ");
                }

		ASSERT_RET(get_proc_stat(terminal_tabs->pidlist[i].pid, &terminal_tabs->pidlist[i]) != -1);

		// Get actual programs that user runs in each terminal tab here 
		PIDInfoArr *cttabs;
		ASSERT_RET(getpid_of_tabs(&cttabs, terminal_tabs->pidlist[i].pid, 0) != -1);

		if (~actions & TBM_SILENT)
			printf("%d (%s) [%ld]\n", terminal_tabs->pidlist[i].pid, terminal_tabs->pidlist[i].comm, cttabs->pidlist_len);
		
                get_proc_info_cttabs(cfg_fd, terminal_tabs->pidlist[i], &cttabs, actions);

		free(cttabs->pidlist);
		free(cttabs);
	}
        
	return 0;
}

// TODO: Support logging of multiple tmux windows running simultaneously
// Counter controlling spacing of debug output
static int indentation_counter = 0;

// Logging of terminal tab programs occur here 
void get_proc_info_cttabs(int cfg_fd, PIDInfo shell, PIDInfoArr **child, enum tbm_actions actions) {
	char buf[TBMARK_SINGLE_ENTRY_SIZE];

	if (~actions & TBM_SILENT) {
		if ((*child)->has_children) {
                        if (actions & TBM_CALLED_FROM_IPROG)
                                printf("        ");

			for (int i = 0; i <= indentation_counter; i++) {
				printf("      ");
                        }

			printf("\u21b3 ");
		} else {
			indentation_counter = (!(*child)->has_children) ? 0 : indentation_counter + 1;
                }
	}

        // Empty shell tabs running nothing are saved into the auto-generated config file, alongside shell programs 
        pid_t pid = (*child)->pidlist[0].pid;
        pid_t ppid = shell.pid;
        char *cwd = (!pid) ? shell.cwd : (*child)->pidlist[0].cwd;
        char *cmdlargs = (!pid) ? " " : (*child)->pidlist[0].cmdlargs;

        if (pid) {
               	get_proc_stat(pid, &(*child)->pidlist[0]);
                get_proc_cmdargs(pid, &(*child)->pidlist[0]);

	        if (~actions & TBM_SILENT)
	        	printf("%d (%s)\n", pid, cmdlargs);
        }

	// Log to tbmark config file (each 'iprogram' handles their own output formatting) 
	if (actions & TBM_RDWR_PIDINFO) {
		int iprogram_index = 0;
		char *iprogram_metadata = NULL;

		// NOTE: So no infinite loops arise
		if (~actions & TBM_CALLED_FROM_IPROG) {
			iprogram_index = is_iprogram(cmdlargs, true);
			if (iprogram_index != -1) {
				// All iprogram logger functions must return a buffer containing its program information, which we then use to concatenate to the main tbmark entry buf 
				iprogram_metadata = iprogram_loggers[iprogram_index](cfg_fd, actions);
                        }
		}

		size_t ttab_entry_size = strlen(cwd) + strlen(cmdlargs) + 18;
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

				char cfg_procfs_path[22] = {0}, cfg_path[PATH_MAX] = {0}, tmux_buf[IPROG_INFO_SIZE] = {0};

				tmux_server_metadata = calloc(PATH_MAX, sizeof(char));
				ASSERT_EXIT(tmux_server_metadata != NULL);

				// Log socket path and pane count for our tmux server 
				get_tmux_server_metadata_res = exec_cmd_and_capture_output("tmux list-window -F 'socket_path:#{socket_path} pane_count:#{window_panes}'", tmux_server_metadata, PATH_MAX);
				ASSERT_EXIT(get_tmux_server_metadata_res != -1);

				// With help from a tmux subcommand, we get the amount of panes in the most recently selected tmux window 
				count = calloc(2, sizeof(char)); // you can't possible have 10 panes or above, right?
				ASSERT_EXIT(count != NULL);

				get_window_pane_count_res = (int)exec_cmd_and_capture_output("tmux list-panes -F '#{window_panes}' | head -1", count, 2);
				ASSERT_EXIT(get_window_pane_count_res != -1);

				tmux_pane_count = atoi(count);
				free(count);

				// Append tmux pane command and metadata to temporary buffer
				ttab_entry_size = strlen(cwd) + strlen(cmdlargs) + 31; // This number amounts to the total length of other non-variable formatted strings below
                                if (strncmp(cmdlargs, "tmux", 4) == 0) {
					snprintf(buf, ttab_entry_size + strlen(tmux_server_metadata), "cwd:%s cmdlargs:<%s> (metadata) %s\n", cwd, cmdlargs, tmux_server_metadata);
                                } else {
				     	snprintf(buf, ttab_entry_size, "ppid:%d cwd:%s cmdlargs:<%s>\n", ppid, cwd, cmdlargs);
                                }

				if (iprogram_metadata != NULL) {
					char cfg[IPROG_INFO_SIZE];
					char **tbmark_cfg_entries;
					size_t tbmark_cfg_entries_len = 0;
					int fd;

					tmux_panes_arr = split_into_arr(iprogram_metadata, '\n', tmux_pane_count, 0);

                                        // Obtain full path of tbmark config file, we do it this way since the config file's name may be user-defined
                                        snprintf(cfg_procfs_path, 22, "/proc/self/fd/%d", cfg_fd);
                                        readlink(cfg_procfs_path, cfg_path, PATH_MAX);

                                        // Open the config file and append tmux data
					ASSERT_EXIT((fd = cfg_open(cfg_path)) != -1);
					memset(cfg, 0, IPROG_INFO_SIZE);
					ASSERT_EXIT(read(fd, cfg, IPROG_INFO_SIZE) != -1);

					tbmark_cfg_entries = split_into_arr(cfg, '\n', MAX_TBMARK_TABS, &tbmark_cfg_entries_len);

					for (int j = 0; j < tmux_pane_count; j++) {
						for (int k = 0; k < tbmark_cfg_entries_len; k++) {
							if (strstr(tbmark_cfg_entries[k], "ppid:") != NULL) {
								char *tmux_panes_arr_pid = extract_tbm_entry_field_str(tmux_panes_arr[j], 16, "pane_pid:");
								char *tbmark_cfg_entries_pid = extract_tbm_entry_field_str(tbmark_cfg_entries[k], 12, "ppid:");

								// NOTE: Only tmux pane programs in the most recently selected window will be appended (ONE tmux window ONLY)
								if (strncmp(tmux_panes_arr_pid, tbmark_cfg_entries_pid, PID_MAX_LEN) == 0) {
									snprintf(tmux_buf, IPROG_INFO_SIZE, "%s [tmux] %s\n", 
											tbmark_cfg_entries[k] + (6 + strlen(tbmark_cfg_entries_pid)), 
											tmux_panes_arr[j] + (10 + strlen(tbmark_cfg_entries_pid)));

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

				if (cfg_write(cfg_fd, buf, strlen(buf)) == -1) break;
				break;
			default:
				snprintf(buf, ttab_entry_size, "cwd:%s cmdlargs:<%s>\n", cwd, cmdlargs);
				if (cfg_write(cfg_fd, buf, strlen(buf)) == -1) break;
				break;
		}
        }
}

int write_proc_stdin(pid_t pid, const char *cmd, size_t cmdLen) {
	int fd;
	char fdpath[PATH_MAX];
	fd_set rfds;
	int select_ret;

	snprintf(fdpath, PATH_MAX, "/proc/%d/fd/0", pid);
	fd = open(fdpath, O_RDWR);
	ASSERT_RET(fd != -1);

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	// Check if stdin of supplied pid is ready to be written to
	// NOTE: Running 'tbmark open' with strace returns a -ENOTTY since input doesn't come from a terminal
	select_ret = select(fd + 1, NULL, &rfds, NULL, NULL);
	ASSERT_EXIT(select_ret != -1);

       	if (FD_ISSET(fd, &rfds)) {
		// Don't write NULL byte to stdin
		for (int i = 0; i < cmdLen; i++) {
			ASSERT_EXIT(ioctl(fd, TIOCSTI, &cmd[i]) != -1);
		}
	} 

	close(fd);
	return 0;
}
