#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "config.h"
#include "debug.h"
#include "helpers.h"
#include "iprograms/tmux.h"

/* Glossary: 
 * - iprograms: Interactive programs that implement some form of terminal multiplexing involving little-to-heavy terminal I/O, such programs are 'tmux' and 'screen' for example. They also include any other programs whose process information are not directly available through procfs.
 *
 */

const char *iprograms[INTERACTIVE_PROGRAMS_COUNT] = {
        [TBM_TMUX] = "tmux"
};

const char *iprogram_glossary[INTERACTIVE_PROGRAMS_COUNT] = {
	[TBM_TMUX] = "Pane"
};

fp_interactive_progs_int iprogram_loggers[INTERACTIVE_PROGRAMS_COUNT] = {
        [TBM_TMUX] = log_tmux_info
};

fp_interactive_progs_str iprogram_parsers[INTERACTIVE_PROGRAMS_COUNT] = {
        [TBM_TMUX] = parse_tmux_info
};

int is_iprogram(const char *cmdlargs, bool saving_tabs) {
        int res = -1;
        for (int i = 0; i < INTERACTIVE_PROGRAMS_COUNT; i++) {
                if (saving_tabs) {
                        if (strncmp(cmdlargs, iprograms[i], PATH_MAX) == 0) {
                                res = i;
                                break;
                        }
                } else {
                        if (strstr(cmdlargs, iprograms[i]) != NULL && strstr(cmdlargs, "socket_path") == NULL) {
                                res = i;
                                break;
                        }
                }
        }

        return res;
}

bool has_cfg_suffix(const char *filename) {
        const char *filename_suffix = filename + strlen(filename) - 4;

        if (strncmp(".cfg", filename_suffix, 4) == 0)
                return true;

        return false;
}

bool running_as_root() {
        if (getuid() != 0 && geteuid() != 0 && getgid() != 0)
                return false;

        return true;
}

char *get_iprogram_name(int index) {
	return (char *)iprograms[index];
}

int exec_and_capture_output(const char *cmd_in, char *cmd_out) {
        FILE *stream;
        char stream_ch;
        int stream_index = 0;

        // Capture stdout/stderr of upon execution of a shell command
        stream = popen(cmd_in, "r");
        ASSERT_RET(stream != NULL);

	if (cmd_out != NULL) {
        	while ((stream_ch = fgetc(stream)) != EOF) {
        	        cmd_out[stream_index++] = stream_ch;
		}

        	cmd_out[stream_index-1] = '\0';
	}

        pclose(stream);

        return 0;
}

char *get_homedir_of_user(uid_t uid) {
        struct passwd *pwd = getpwuid(uid);
        if (pwd == NULL)
                return NULL;

        return pwd->pw_dir;
}

// Splits a string into an array of strings, provided a delimeter
char **split(char *str, char delim, size_t max_arr_len, size_t *out_arr_len) {
        char **arr = calloc(max_arr_len, sizeof(char *));
        ASSERT_NULL(arr != NULL);

        int pos = 0;
        char buf[1024] = {0};
        for (int i = 0; i < max_arr_len; i++) {
                arr[i] = calloc(1024, sizeof(char));
                if (arr[i] == NULL) {
                        free(arr);
                        return NULL;
                }

		memset(arr[i], 0, 1024);

                pos = 0;
                for (int j = 0; j < strnlen(str, 1024); j++) {
                        if (str[j] == delim) {
                                if (out_arr_len != 0)
					*out_arr_len += 1;

                                str += (j + 1);
                                break;
                        } else {
				buf[pos++] = str[j];
			}
                }

                strncpy(arr[i], buf, 1024);
                arr[i][pos] = '\0';
        }

        return arr;
}

// NOTE: Kind of a hacky way to cleanup the tbmark config file (only used once)
// Remove lines from a file that match the provided delimeter at the start of each line
int format_tbmark_cfg(char *path) {
        const char *delim = "ppid:";

        int read_fd, write_fd;
        char *entries = calloc(8092, sizeof(char));
        char *updated_entries = calloc(8092, sizeof(char));

        ASSERT_RET((read_fd = cfg_open(path)) != -1);
        ASSERT_RET(read(read_fd, entries, 8092) != -1);
	close(read_fd);

	// Count the amount of lines in tbmark config file
        size_t lines = 0;
        for (int i = 0; i < strlen(entries); i++) {
                if (entries[i] == '\n')
			lines++;
		else 
                        continue;
        }

        // Recreate tbmark config file and write updated and parsed entries to it
	ASSERT_RET(cfg_create(path) != -1);
	ASSERT_RET((write_fd = cfg_open(path)) != -1);
	
	// Append tbmark entries that don't match the provided delimeter at the start of each line, to our buffer of updated tbmark entries
	char **entries_arr = split(entries, '\n', lines, 0);
	if (entries_arr != NULL) {
		for (int i = 0; i < lines; i++) {
			for (int j = 0; j < strlen(delim); j++) {
				if (entries_arr[i][j] != delim[j]) {
					strncat(entries_arr[i], "\n", 2);
					strncat(updated_entries, entries_arr[i], strlen(entries_arr[i]));
					break;
				}
			}
		}
	}

        ASSERT_RET(cfg_write(write_fd, updated_entries, strlen(updated_entries)) != -1);

        free(entries);
	free_str_arr(entries_arr, lines);
	free(updated_entries);

        return 0;
}

void free_str_arr(char **arr, size_t arr_len) {
	for (int i = 0; i < arr_len; i++) {
		free(arr[i]);
        }

	free(arr);
}
