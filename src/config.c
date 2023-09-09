#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>
#include <xdo.h>
#include <regex.h>
#include "iprograms/tmux.h"

#include "config.h"
#include "debug.h"
#include "helpers.h"

//#define DEBUG

char *extract_tbm_entry_field_str(const char *buf, size_t max_tag_and_value_len, char *tag) {
	char *substr_ptr = strstr(buf, tag);
	char *field_value = calloc(max_tag_and_value_len, sizeof(char));
	int tag_len = strnlen(tag, MAX_TAG_LEN);

	/* Tagged substring exists in `buf` */
	if (substr_ptr != NULL) {
		/* String that comes after tag is stored in `field_value` */
	        snprintf(field_value, max_tag_and_value_len, "%.*s\n", 
				(int)strnlen(substr_ptr, max_tag_and_value_len) - tag_len,
				substr_ptr + tag_len);

		for (int i = 0; i < strnlen(field_value, max_tag_and_value_len); i++) {
        		/* Stop string at current element if we hit a newline character, OR if the supplied tags != [cmdlargs, tmux, and if a whitespace character was hit] */
        		if (field_value[i] == '\n' || (strncmp(tag, "cmdlargs:", 9) != 0 && strncmp(tag, "[tmux] ", 6) != 0 && field_value[i] == ' ')) {
	        		field_value[i] = '\0';
		        	break;
        		}
		}
		return field_value;
	}
	free(field_value);

	return NULL;
}

int extract_tbm_entry_field_int(const char *buf, size_t max_tag_and_value_len, char *tag) {
	char *substr_ptr = strstr(buf, tag);
	char *field_value = calloc(max_tag_and_value_len, sizeof(char));
	int field_value_int;
	int tag_len = strnlen(tag, MAX_TAG_LEN);

	/* String that comes after tag is stored in `field_value` */
        snprintf(field_value, max_tag_and_value_len, "%.*s\n", 
			(int)strnlen(substr_ptr, max_tag_and_value_len) - tag_len,
			substr_ptr + tag_len);

	/* Tagged substring exists in `buf` */
	if (substr_ptr != NULL) {
		for (int i = 0; i < strnlen(field_value, max_tag_and_value_len); i++) {
			/* Generic formatting and cleanup of the matched `field_value`, since it may contain stray newline and whitespace characters (we don't want these characters when writing to our tbmark config file) */
			if (field_value[i] == '\n' || (strncmp(tag, "cmdlargs:", 9) != 0 && field_value[i] == ' ')) {
				field_value[i] = '\0';
				break;
			}
		}
		field_value_int = atoi(field_value);
		free(field_value);

		return field_value_int;
	}
	free(field_value);

	return -1;
}

/* Strips the argument portion of a command and return it */
char *strip_args_from_cmd(const char *cmd, size_t max_cmd_len) {
        char *stripped = calloc(strnlen(cmd, max_cmd_len), sizeof(char));
        ASSERT_NULL(stripped != NULL);

        regex_t strip_delim_regex;
        regmatch_t strip_delim_index;
        int status;

        /* NOTE: This hack might not be defined behaviour, should be looked into deeper (it works though) */
        ASSERT_NULL(regcomp(&strip_delim_regex, "\\<(.*)>", REG_EXTENDED) == 0);
        ASSERT_NULL((status = regexec(&strip_delim_regex, cmd, 1, &strip_delim_index, 0)) != REG_NOMATCH);

        regfree(&strip_delim_regex);
        if (status == 0) {
                for (int i = strip_delim_index.rm_so, j = 0;
                                i < (strip_delim_index.rm_eo - 1); 
                                i++, j++) {
                        stripped[j] = cmd[i];
                }
        }

        return stripped;
}

int cfg_create(const char *pathname) {
        int res = open(pathname, O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        ASSERT_RET(res != -1);

	close(res);

	return 0;
}

void cfg_delete(const char *pathname) {
	int res = unlink(pathname);
	ASSERT_EXIT(res != -1);
}

int cfg_open(const char *pathname) {
	int cfg_fd;

	cfg_fd = open(pathname, O_RDWR);
	ASSERT_EXIT(cfg_fd != -1);

	return cfg_fd;
}

/* tbmark config file follows this format (CWD, CMDLARGS, [IPROG_MDATA]) */
CfgInfoArr *cfg_parse(int fd) {
	char *buf;
	struct stat sbuf;
	char *iprog_args, *iprog_name, *iprog_info, *cwdir, *cmd, *comm, *args, *stripped_args, *metadata;
	CfgInfoArr *cfginfo_list;
	size_t lines[MAX_TBMARK_ENTRIES] = {0}, tbmark_entries_len = 0;

	ASSERT_NULL(fstat(fd, &sbuf) != -1);
	buf = mmap(NULL, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	ASSERT_NULL(buf != NULL);

	/* NOTE: ~30ms slower when sequentially looping over file contents */
	/* Get line count of tbmark's config file */
	int line_index = 1;
        for (int i = 0; i < sbuf.st_size; i++) {
                if (buf[i] == '\n' && !isspace(buf[i + 1])) {
                        lines[line_index++] = i;
                        tbmark_entries_len++;
                }
        }
	cfginfo_list = calloc(1, sizeof(CfgInfoArr));
	cfginfo_list->entries = calloc(tbmark_entries_len, sizeof(CfgInfo));
	cfginfo_list->entries_len = tbmark_entries_len;

	for (int i = 0; i < tbmark_entries_len; i++) {
		cwdir = extract_tbm_entry_field_str(buf + lines[i], PATH_MAX, "cwd:");
		cmd = extract_tbm_entry_field_str(buf + lines[i], PATH_MAX, "cmdlargs:");
		comm = extract_tbm_entry_field_str(cmd, MAX_COMM_LEN, "");


		// NOTE: In cases where a '[' character is found in the `cmdlargs` field, our solution below breaks
		args = (strstr(cmd, "") == NULL || strstr(cmd, "(metadata)") != NULL || cmd[strnlen(comm, MAX_COMM_LEN) + 1] == '[')
			? "" 
			: extract_tbm_entry_field_str(cmd + strnlen(comm, MAX_COMM_LEN) + 1, PATH_MAX, "");

                /* Here we strip the arguments variable of its angle brackets (acting as a delimeter) */
                if (strnlen(comm, MAX_COMM_LEN) > 1 && strnlen(args, PATH_MAX) > 1) {
                        stripped_args = strip_args_from_cmd(cmd + strnlen(comm, MAX_COMM_LEN) + 1, PATH_MAX);
                        strncpy(args, stripped_args, PATH_MAX);

                        free(stripped_args);
                } else if (strnlen(comm, MAX_COMM_LEN) > 1 && !strnlen(args, PATH_MAX)) {
                        /* Equivalent to a terminal tab with a command and no arguments */
                        comm[strnlen(comm, MAX_COMM_LEN) - 1] = '\0';
                } else {
                        /* Equivalent to an empty terminal tab with no commands inputted */
                        strncpy(args, " ", 2);
                }

		metadata = (strstr(cmd, "(metadata) ") == NULL) 
			? ""
			: cmd + strnlen(comm, MAX_COMM_LEN) + 12;

		/* We check and see if the current command was started within an `iprogram` */
		iprog_args = extract_tbm_entry_field_str(buf + lines[i], PATH_MAX, "cmdlargs:");
		int iprogram_index = is_iprogram(iprog_args + strnlen(comm, MAX_COMM_LEN) + strnlen(args, PATH_MAX) + 2);
		free(iprog_args);

		if (iprogram_index != -1) {
			iprog_name = get_iprogram_name(iprogram_index);
			iprog_info = iprogram_parsers[iprogram_index](buf + lines[i]);
		} else {
			iprog_name = NULL;
			iprog_info = "";
		}

#ifdef DEBUG
		printf("\n");
		LOG("(cwdir): %s (%ld)\n", cwdir, strnlen(cwdir, PATH_MAX));
		LOG("(comm): %s (%ld)\n", comm + 1, strnlen(comm, MAX_COMM_LEN));

		if (strnlen(args, PATH_MAX) > 0) {
			LOG("(args): %s (%ld)\n", args, strnlen(args, PATH_MAX));
		}

		if (strnlen(metadata, ARGMAX) > 0) {
			LOG("(metadata): %s (%ld)\n", metadata, strnlen(metadata, ARGMAX));
		}

		if (iprogram_index != -1) {
			LOG("(iprogram): %s\n", iprog_name);
			LOG("(iprog_info): %s (%ld)\n", iprog_info, strnlen(iprog_info, IPROG_INFO_SIZE));
		}
#endif

		// NOTE: ASan might've been masking the crash on the following lines since some buffer zones are added before and after memory allocations for instrumentation purposes
		strncpy(cfginfo_list->entries[i].cwd, cwdir, strnlen(cwdir, PATH_MAX));
		strncpy(cfginfo_list->entries[i].comm, comm + 1, strnlen(comm, MAX_COMM_LEN));
		strncpy(cfginfo_list->entries[i].cmdlargs, args, strnlen(args, ARGMAX));
		strncpy(cfginfo_list->entries[i].metadata, metadata, strnlen(metadata, ARGMAX));

		if (iprogram_index != -1) {
			strncpy(cfginfo_list->entries[i].iprogram_name, iprog_name, MAX_COMM_LEN);
			strncpy(cfginfo_list->entries[i].iprogram_info, iprog_info, strnlen(iprog_info, IPROG_INFO_SIZE));
			cfginfo_list->entries[i].iprogram_index = iprogram_index;
		} else {
			cfginfo_list->entries[i].iprogram_index = -1;
		}

		free(cwdir);
		free(cmd);
		free(comm);
		if (strnlen(args, PATH_MAX) > 0) free(args);
		if (strnlen(iprog_info, IPROG_INFO_SIZE) > 0) free(iprog_info);
	}

	return cfginfo_list;
}

// TODO: On top of executing regular programs, add support for `iprograms` as well
int cfg_exec(int fd, pid_t ppid, CfgInfoArr *cfginfo_list) {
        char OPEN_TBMARK_ENTRIES_CMD[ARGMAX + 5120];
	xdo_t *xdo;

	/* Tmux-specific variables */
	int tmux_pane_id = 0, tmux_pane_count;
	char *tmux_socket_path;

	PIDInfoArr *ttabs_list;
	int normal_prog_counter = 0; // Since `iprograms` may include panes containing programs such as tmux, we keep a counter over the 'regular' programs

	if (cfginfo_list->entries_len) {
		printf("Reopening tabs...\n\n");
	} else {
		printf("No tabs were saved.\n");
	}

	/* t (index for all tbmark entries), i (index for iprogram-specific windows/structures only), r (index for regular programs only) */
	for (int t = 0, i = 0, r = 0; 
                        t < cfginfo_list->entries_len; t++) {
		/* `iprogram` tabs are formatted here + iprogram-specific metadata assignment to their respective variables */
		if (strnlen(cfginfo_list->entries[t].iprogram_name, MAX_COMM_LEN) > 0) {
			printf(" ↳ %s %d (%s): \"%s", iprogram_glossary[cfginfo_list->entries[t].iprogram_index], i + 1, cfginfo_list->entries[t].cwd, cfginfo_list->entries[t].comm);

			if (strncmp(cfginfo_list->entries[t].cmdlargs, "", 1) != 0) {
				printf(" %s", cfginfo_list->entries[t].cmdlargs);
			}
			printf("\"\n");
			i++;
		} else {
			printf("Tab %d (%s): \"%s", r + 1, cfginfo_list->entries[t].cwd, cfginfo_list->entries[t].comm);

			if (strncmp(cfginfo_list->entries[t].cmdlargs, "", 1) != 0) {
				printf(" %s", cfginfo_list->entries[t].cmdlargs);
			}
			printf("\"\n");
			r++;

			/* Switch-case below is used for obtaining `iprogram` metadata */
			switch (is_iprogram(cfginfo_list->entries[t].comm)) {
				case 0:
					tmux_socket_path = extract_tbm_entry_field_str(cfginfo_list->entries[t].metadata, PATH_MAX + 12, "socket_path:"); 
					tmux_pane_count = extract_tbm_entry_field_int(cfginfo_list->entries[t].metadata, 12, "pane_count:"); 
					break;
			}
		}
	}

        // TODO: Restoration of terminal tabs break if a saved CLI arguments begins with a special character
        /* We escape special characters found in CLI arguments here */
        char *escaped_cmdlargs, special_chars[18] = "&*{}[]<>,=-().+;'/";
        for (int i = 0; i < cfginfo_list->entries_len; i++) {
                for (int j = 0; j < 18; j++) {
                        if (strchr(cfginfo_list->entries[i].cmdlargs, special_chars[j]) != NULL) {
                                escaped_cmdlargs = calloc(strnlen(cfginfo_list->entries[i].cmdlargs, ARGMAX), sizeof(char));

                                snprintf(escaped_cmdlargs, strnlen(cfginfo_list->entries[i].cmdlargs, ARGMAX) + 3, "'%s'", cfginfo_list->entries[i].cmdlargs);
                                strncpy(cfginfo_list->entries[i].cmdlargs, escaped_cmdlargs, ARGMAX);

                                free(escaped_cmdlargs);
                                break;
                        }
                }
        }

        /* Open a new terminal tab and cd into tbmark config file's respective directories and run their commands */
        xdo = xdo_new(NULL);
	for (int cfg_entry_index = 0; cfg_entry_index < cfginfo_list->entries_len; cfg_entry_index++) {
		switch (cfginfo_list->entries[cfg_entry_index].iprogram_index) {
			case 0:
				// TODO: Find a more efficient way to determine if a tmux window has been opened
				usleep(300000);

				TmuxPaneInfo *tmux_pane_metadata;
				char GET_TMUX_SERVER_PID_CMD[ARGMAX], *first_tmux_pane_metadata_pid;
			       
				tmux_pane_metadata = populate_tmux_pane_metadata(cfginfo_list->entries[cfg_entry_index].iprogram_info);
				ASSERT_RET(tmux_pane_metadata != NULL);

				first_tmux_pane_metadata_pid = malloc(7 * sizeof(char));
				if (first_tmux_pane_metadata_pid == NULL) {
					free(tmux_pane_metadata);
					return -1;
				}
				snprintf(GET_TMUX_SERVER_PID_CMD, ARGMAX, "tmux -S %s list-window -F '#{pane_pid}'", tmux_socket_path);

				if (exec_and_capture_output(GET_TMUX_SERVER_PID_CMD, first_tmux_pane_metadata_pid) == -1) {
					free(first_tmux_pane_metadata_pid);
					free(tmux_pane_metadata);
					return -1;
				}

				// TODO: Support more pane layouts (current approach for re-opening tmux panes isn't really that scalable)
			        /* Execute command in tbmark entry */
				// NOTE: Cleanup not performed at `write_proc_stdin` since -EPERM is returned
				int active_pane_id;
				char TMUX_SELECT_PANE_CMD[ARGMAX];

				// Store active pane id in a temporary variable
				if (tmux_pane_metadata->active) {
					active_pane_id = tmux_pane_id;
				}

				switch(tmux_pane_count) {
					case 2:
						//  ---------
						//  |   |   |
						//  |   |   |
						//  |   |   |
						//  ---------
						if (tmux_pane_metadata->at_top 
								&& tmux_pane_metadata->at_bottom 
								&& tmux_pane_metadata->at_left 
								&& !tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -h && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (tmux_pane_metadata->at_top 
								&& tmux_pane_metadata->at_bottom 
								&& !tmux_pane_metadata->at_left 
								&& tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && cd %s && %s %s\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						}

						//  ---------
						//  |       |
						//  |--------
						//  |       |
						//  ---------
						else if (tmux_pane_metadata->at_top 
								&& !tmux_pane_metadata->at_bottom 
								&& tmux_pane_metadata->at_left 
								&& tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux split-window -v && cd %s && %s %s && clear\n", cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (!tmux_pane_metadata->at_top 
								&& tmux_pane_metadata->at_bottom 
								&& tmux_pane_metadata->at_left 
								&& tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && cd %s && %s %s\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						}

						/* Set the active tmux pane */
						if (tmux_pane_id == 1) {
							snprintf(TMUX_SELECT_PANE_CMD, ARGMAX, "tmux -S %s select-pane -t %d", tmux_socket_path, active_pane_id);
							exec_and_capture_output(TMUX_SELECT_PANE_CMD, NULL);
						}

						tmux_pane_id++;
						break;
					
					case 3: ;
						TmuxPaneInfo *next_tmux_pane_metadata = NULL;
						if (cfg_entry_index+1 == cfginfo_list->entries_len) {
							next_tmux_pane_metadata = populate_tmux_pane_metadata(cfginfo_list->entries[cfg_entry_index].iprogram_info);
							ASSERT_RET(next_tmux_pane_metadata != NULL);
						} else if (strnlen(cfginfo_list->entries[cfg_entry_index+1].iprogram_info, IPROG_INFO_SIZE) > 0 && cfg_entry_index+1 != cfginfo_list->entries_len) {
							next_tmux_pane_metadata = populate_tmux_pane_metadata(cfginfo_list->entries[cfg_entry_index+1].iprogram_info);
							ASSERT_RET(next_tmux_pane_metadata != NULL);
						}

						//  ---------
						//  |   |   |
						//  |--------
						//  |       |
						//  ---------
						if (tmux_pane_metadata->at_top 
								&& !tmux_pane_metadata->at_bottom 
								&& tmux_pane_metadata->at_left 
								&& !tmux_pane_metadata->at_right
								&& next_tmux_pane_metadata->at_top
								&& !next_tmux_pane_metadata->at_bottom
								&& !next_tmux_pane_metadata->at_left
								&& next_tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -v && tmux select-pane -t 0 && tmux split-window -h && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (tmux_pane_metadata->at_top
								&& !tmux_pane_metadata->at_bottom
								&& !tmux_pane_metadata->at_left
								&& tmux_pane_metadata->at_right
								&& !next_tmux_pane_metadata->at_top
								&& next_tmux_pane_metadata->at_bottom
								&& next_tmux_pane_metadata->at_left
								&& next_tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux select-pane -t 2 && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (!tmux_pane_metadata->at_top
								&& tmux_pane_metadata->at_bottom
								&& tmux_pane_metadata->at_left
								&& tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && cd %s && %s %s\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						}

						//  ---------
						//  |       |
						//  |--------
						//  |   |   |
						//  ---------
						else if (tmux_pane_metadata->at_top
								&& !tmux_pane_metadata->at_bottom
								&& tmux_pane_metadata->at_left
								&& tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -v && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (!tmux_pane_metadata->at_top
								&& tmux_pane_metadata->at_bottom
								&& tmux_pane_metadata->at_left
								&& !tmux_pane_metadata->at_right
								&& !next_tmux_pane_metadata->at_top
								&& next_tmux_pane_metadata->at_bottom
								&& !next_tmux_pane_metadata->at_left
								&& next_tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -h && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (!tmux_pane_metadata->at_top
								&& tmux_pane_metadata->at_bottom
								&& !tmux_pane_metadata->at_left
								&& tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && cd %s && %s %s\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						}

						//  ---------
						//  |   |   |
						//  |---|   |
						//  |   |   |
						//  ---------
						else if (tmux_pane_metadata->at_top
								&& !tmux_pane_metadata->at_bottom
								&& tmux_pane_metadata->at_left
								&& !tmux_pane_metadata->at_right
								&& !next_tmux_pane_metadata->at_top
								&& next_tmux_pane_metadata->at_bottom
								&& next_tmux_pane_metadata->at_left
								&& !next_tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -h && tmux select-pane -t 0 && tmux split-window -v && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (!tmux_pane_metadata->at_top
								&& tmux_pane_metadata->at_bottom
								&& tmux_pane_metadata->at_left
								&& !tmux_pane_metadata->at_right
								&& next_tmux_pane_metadata->at_top
								&& next_tmux_pane_metadata->at_bottom
								&& !next_tmux_pane_metadata->at_left
								&& next_tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux select-pane -t 2 && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (tmux_pane_metadata->at_top
								&& tmux_pane_metadata->at_bottom
								&& !tmux_pane_metadata->at_left
								&& tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && cd %s && %s %s\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						}

						//  ---------
						//  |   |   |
						//  |   |---|
						//  |   |   |
						//  ---------
						else if (tmux_pane_metadata->at_top
								&& tmux_pane_metadata->at_bottom
								&& tmux_pane_metadata->at_left
								&& !tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -h && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (tmux_pane_metadata->at_top
								&& !tmux_pane_metadata->at_bottom
								&& !tmux_pane_metadata->at_left
								&& tmux_pane_metadata->at_right
								&& !next_tmux_pane_metadata->at_top
								&& next_tmux_pane_metadata->at_bottom
								&& !next_tmux_pane_metadata->at_left
								&& next_tmux_pane_metadata->at_right) {
							snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -v && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						}
						
						/* Set the active tmux pane */
						if (tmux_pane_id == 2) {
							snprintf(TMUX_SELECT_PANE_CMD, ARGMAX, "tmux -S %s select-pane -t %d", tmux_socket_path, active_pane_id);
							exec_and_capture_output(TMUX_SELECT_PANE_CMD, NULL);
						}

						if (next_tmux_pane_metadata != NULL) {
							free(next_tmux_pane_metadata);
						}
						tmux_pane_id++;
						break;

					case 4:
						//  ---------
						//  |   |   |
						//  |---|---|
						//  |   |   |
						//  ---------
						if (tmux_pane_metadata->at_top 
								&& !tmux_pane_metadata->at_bottom 
								&& tmux_pane_metadata->at_left 
								&& !tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -h && tmux select-pane -t 0 && tmux split-window -v && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (!tmux_pane_metadata->at_top 
								&& tmux_pane_metadata->at_bottom 
								&& tmux_pane_metadata->at_left 
								&& !tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux select-pane -t 2 && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (tmux_pane_metadata->at_top 
								&& !tmux_pane_metadata->at_bottom 
								&& !tmux_pane_metadata->at_left 
								&& tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && tmux split-window -v && cd %s && %s %s && clear\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						} else if (!tmux_pane_metadata->at_top 
								&& tmux_pane_metadata->at_bottom 
								&& !tmux_pane_metadata->at_left 
								&& tmux_pane_metadata->at_right) {
						        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "tmux resize-pane -t %d -x %d -y %d && cd %s && %s %s\n", tmux_pane_id, tmux_pane_metadata->width, tmux_pane_metadata->height, cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						}

						/* Set the active tmux pane */
						if (tmux_pane_id == 3) {
							snprintf(TMUX_SELECT_PANE_CMD, ARGMAX, "tmux -S %s select-pane -t %d", tmux_socket_path, active_pane_id);
							exec_and_capture_output(TMUX_SELECT_PANE_CMD, NULL);
						}

						tmux_pane_id++;
						break;

					default:
					        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "cd %s && %s %s\n", cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);
						break;
				}

			        ASSERT_RET(write_proc_stdin(atoi(first_tmux_pane_metadata_pid), OPEN_TBMARK_ENTRIES_CMD, strnlen(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD))) != -1);

				free(first_tmux_pane_metadata_pid);
				free(tmux_pane_metadata);
				break;

			default:
			        if (xdo_send_keysequence_window(xdo, CURRENTWINDOW, "ctrl+shift+t", 0) == 1) break;
				// TODO: Find a better way to determine if a terminal window has opened
				usleep(700000);
		
			        ASSERT_RET(get_terminal_emu_and_proc_info(&ttabs_list, fd, ppid, TBM_RDONLY_PIDINFO | TBM_SKIP_CURRENT_PID | TBM_SILENT) != -1);

			        /* Execute command in tbmark entry */
			        snprintf(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD), "cd %s && %s %s\n", cfginfo_list->entries[cfg_entry_index].cwd, (strnlen(cfginfo_list->entries[cfg_entry_index].comm, MAX_COMM_LEN) == 0) ? "clear" : cfginfo_list->entries[cfg_entry_index].comm, cfginfo_list->entries[cfg_entry_index].cmdlargs);

				// NOTE: Cleanup not performed at `write_proc_stdin` since -EPERM is returned
				ASSERT_RET(write_proc_stdin(ttabs_list->pidlist[normal_prog_counter].pid, OPEN_TBMARK_ENTRIES_CMD, strnlen(OPEN_TBMARK_ENTRIES_CMD, sizeof(OPEN_TBMARK_ENTRIES_CMD))) != -1);
		
				normal_prog_counter++;
				free(ttabs_list->pidlist);
				free(ttabs_list);
				break;
		}
	        if (xdo_send_keysequence_window(xdo, CURRENTWINDOW, "alt+1", 0) == 1) break;
	}
	xdo_free(xdo);
	free(tmux_socket_path);

	return 0;
}

ssize_t cfg_write(int fd, const char *buf, size_t size) {
	ssize_t written_bytes;

	written_bytes = write(fd, buf, size);
	ASSERT_RET(written_bytes != -1);
		
	return written_bytes;
}
