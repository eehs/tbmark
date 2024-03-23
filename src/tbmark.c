#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>

#include "tbmark.h"
#include "proc.h"
#include "config.h"
#include "helpers.h"
#include "debug.h"

// TODO: Make memory deallocations explicit (on crashes and exits)
// TODO: Get tbmark to play nice with commands ran over SSH (could make use of `sshpass` or something similar)
// TODO: Add some form of testing (different scenarios, e.g., multiple terminal tabs, CLI arguments with space characters, etc)

// Arbitrary length that covers the names of majority shell programs I've came across thus far, may change in the future 

// Currently supported flags: save, open, delete, help 

int tbm_index(const char *subcmd) {
	for (int i = 0; i < TBM_NUM_SUBCMDS; i++) {
		if (!subcmd) break;

		if (strncmp(subcmd, tbm_subcmd_table[i].cmd, strnlen(tbm_subcmd_table[i].cmd, 30)) == 0) {
			return tbm_subcmd_table[i].cmd_int;
		}
	}

	return -1;
}

int tbm_save(const char *shell, const char *filename) {
	pid_t ppid;
	char cfgdir[PATH_MAX - FILE_NAME_MAX_LEN], cfgpath[PATH_MAX];
	int cfg_fd;
	
	// Parent PID needed to identify terminal program 
	ppid = getppid();
	printf("Saving open tabs...\n");

	// Create config file and start logging terminal info to it 
        snprintf(cfgdir, PATH_MAX - FILE_NAME_MAX_LEN, "%s/%s", get_homedir_of_user(getuid()), TBMARK_DIRNAME);
        mkdir(cfgdir, 0777);

        if (filename != NULL) {
        	snprintf(cfgpath, PATH_MAX, "%s/%s.cfg", cfgdir, filename);
        } else {
        	snprintf(cfgpath, PATH_MAX, "%s/tbmark.cfg", cfgdir);
        }
	ASSERT_RET((cfg_create(cfgpath)) != -1);
	ASSERT_RET((cfg_fd = cfg_open(cfgpath)) != -1);

	// Scraping and parsing of process data starts here 
	PIDInfoArr *ttabs;
	ASSERT_RET(get_terminal_emu_and_proc_info(&ttabs, cfg_fd, ppid, TBM_RDWR_PIDINFO | TBM_SKIP_CURRENT_PID) != -1);

	printf("\n");

	free(ttabs->pidlist);
	free(ttabs);

	// Get rid of pre-parsed tmux pane programs (if any) 
	remove_lines_from_file(cfgpath, "ppid:", 4096);
	close(cfg_fd);

	return 0;
}

// Must be executed with root privileges (direct write to process stdin) 
int tbm_open(const char *shell, const char *filename) {
	pid_t ppid;
	char cwd[PATH_MAX];
        regex_t userhome_regex;
        regmatch_t userhome_index;
        int userhome_ret;
        char userhome[PATH_MAX], cfgpath[PATH_MAX];
	int cfg_fd;
	CfgInfoArr *cfg_prog_entry_list;

	if (continue_if_root() == -1) {
		ERROR("`open` must be ran as root!\n");
		exit(1);
	}

	ppid = getppid();

	// Get user's home directory through current working directory (Could possibly find another way to get user's $HOME) 
        ASSERT_RET(getcwd(cwd, PATH_MAX) != NULL);
        ASSERT_RET(regcomp(&userhome_regex, "(\\/home\\/[a-z0-9_-]{0,31})", REG_EXTENDED) == 0);
        ASSERT_RET((userhome_ret = regexec(&userhome_regex, cwd, 1, &userhome_index, 0)) != REG_NOMATCH);

        regfree(&userhome_regex);
        if (userhome_ret == 0) {
                for (int i = userhome_index.rm_so, j = 0; i < userhome_index.rm_eo; i++, j++) {
                        userhome[j] = cwd[i];
		}
        }

        // Open and parse tbmark config file for program restoration
        if (filename != NULL) {
                char *cfg_ext_in_filename = strstr(filename, ".cfg");
                char *dot_cfg_str_extension = (cfg_ext_in_filename != NULL) ? "" : ".cfg";
                
                snprintf(cfgpath, PATH_MAX, "%s/%s/%s%s", userhome, TBMARK_DIRNAME, filename, dot_cfg_str_extension);
        } else {
                snprintf(cfgpath, PATH_MAX, "%s/%s/tbmark.cfg", userhome, TBMARK_DIRNAME);
        }

        cfg_fd = cfg_open(cfgpath);
	ASSERT_RET((cfg_prog_entry_list = cfg_parse(cfg_fd)) != NULL);

	if (cfg_exec(cfg_fd, ppid, cfg_prog_entry_list) == -1) {
                free(cfg_prog_entry_list->entries);
                free(cfg_prog_entry_list);
                close(cfg_fd);

                return -1;
        }

	free(cfg_prog_entry_list->entries);
	free(cfg_prog_entry_list);
	close(cfg_fd);

	return 0;
}

int tbm_delete(const char *shell, const char *filename) {
	char cfgpath[PATH_MAX];

        if (filename != NULL) {
                char *cfg_ext_in_filename = strstr(filename, ".cfg");
                char *dot_cfg_str_extension = (cfg_ext_in_filename != NULL) ? "" : ".cfg";
                
                snprintf(cfgpath, PATH_MAX, "%s/%s/%s%s", get_homedir_of_user(getuid()), TBMARK_DIRNAME, filename, dot_cfg_str_extension);
        }

	cfg_delete(cfgpath);
	printf("Deleting %s\n", cfgpath);

	return 0;
}

void tbm_help() {
	printf("  save:   Saves currently opened terminal tabs to a file (excluding tab where `tbmark` was ran)\n  open:	  Opens saved tabs from a tbmark config file\n  delete: Deletes a tbmark config file\n  help:   Prints this help message and exits\n");
	exit(1);
}

int main(int argc, char **argv) {
	int tbm_command;
	char shell[MAX_TBMARK_TABS];
        char filename[FILE_NAME_MAX_LEN];

        tbm_command = tbm_index(argv[1]);
        if (tbm_command != -1) {
                if (argc == 2) {
                        tbm_func_table[tbm_command](shell, NULL);
                } else if (argc == 3) {
                        strncpy(filename, argv[2], FILE_NAME_MAX_LEN);
                        tbm_func_table[tbm_command](shell, filename);
                }

                return 0;
        }

	printf("Usage: tbmark <subcommand> [config file] (defaults to 'tbmark.cfg' if empty)\n\nList of available commands:\n");
	tbm_help();

	return 1;
}
