#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex.h>

#include "tbmark.h"
#include "proc.h"
#include "config.h"
#include "helpers.h"
#include "debug.h"

#define NUM_CAPABILITIES 1

// TODO: Make memory deallocations explicit (on crashes and exits)
// TODO: Make tbmark aware of piped programs
// TODO: Add some form of testing (different scenarios, e.g., multiple terminal tabs, CLI arguments with space characters, etc)
// TODO: Support more programs (tmux, etc)

/* Arbitrary length that covers the names of majority shell programs I've came across thus far, may change in the future */

/* Currently supported flags: save, open, delete, help */

int tbm_index(const char *subcmd) {
	for (int i = 0; i < TBM_NUM_SUBCMDS; i++) {
		if (!subcmd) break;

		if (strncmp(subcmd, tbm_subcmd_table[i].cmd, strnlen(tbm_subcmd_table[i].cmd, 30)) == 0) {
			return tbm_subcmd_table[i].cmd_int;
		}
	}

	return -1;
}

int tbm_save(const char *shell) {
	pid_t ppid;
	char cfgpath[PATH_MAX];
	int cfg_fd;
	
	/* Parent PID needed to identify terminal program */
	ppid = getppid();
	printf("Saving open tabs...\n");

	/* Create config file and start logging terminal info to it */
	snprintf(cfgpath, PATH_MAX, "%s/.tbmark-cfg", get_homedir_of_user(getuid()));
	ASSERT_RET((cfg_create(cfgpath)) != -1);
	ASSERT_RET((cfg_fd = cfg_open(cfgpath)) != -1);

	// TODO: I should pass `ttabs` to functions in the process scraping hierarchy by reference, so I'm able to free it properly afterwards
	/* Scraping and parsing of process data starts here */
	PIDInfoArr *ttabs;
	ASSERT_RET(get_terminal_emu_and_proc_info(&ttabs, cfg_fd, ppid, TBM_RDWR_PIDINFO | TBM_SKIP_CURRENT_PID) != -1);

	printf("\n");

	free(ttabs->pidlist);
	free(ttabs);

	/* Get rid of pre-parsed tmux pane programs (if any) */
	remove_lines_from_file(cfgpath, "ppid:", 4096);
	close(cfg_fd);

	return 0;
}

/* Must be executed with root privileges (direct injection to process stdin) */
int tbm_open(const char *shell) {
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

	/* Get user's home directory through current working directory (Could possibly find another way to get user's $HOME) */
        ASSERT_RET(getcwd(cwd, PATH_MAX) != NULL);
        ASSERT_RET(regcomp(&userhome_regex, "(\\/home\\/[a-z0-9_-]{0,31})", REG_EXTENDED) == 0);
        ASSERT_RET((userhome_ret = regexec(&userhome_regex, cwd, 1, &userhome_index, 0)) != REG_NOMATCH);

        regfree(&userhome_regex);
        if (userhome_ret == 0) {
                for (int i = userhome_index.rm_so, j = 0; i < userhome_index.rm_eo; i++, j++) {
                        userhome[j] = cwd[i];
		}
        }

        /* Open and parse tbmark config file for program restoration */
        snprintf(cfgpath, strnlen(userhome, PATH_MAX)+13, "%s/.tbmark-cfg", userhome);
	ASSERT_RET((cfg_fd = cfg_open(cfgpath)) != -1);
	ASSERT_RET((cfg_prog_entry_list = cfg_parse(cfg_fd)) != NULL);
	ASSERT_RET(cfg_exec(cfg_fd, ppid, cfg_prog_entry_list) != -1);

	free(cfg_prog_entry_list->entries);
	free(cfg_prog_entry_list);
	close(cfg_fd);

	return 0;
}

int tbm_delete(const char *shell) {
	char cfgpath[PATH_MAX];

	snprintf(cfgpath, PATH_MAX, "%s/.tbmark-cfg", get_homedir_of_user(getuid()));
	cfg_delete(cfgpath);
	printf("Deleting %s\n", cfgpath);

	return 0;
}

void tbm_help() {
	printf("  save:   Saves currently opened terminal tabs to a file (excluding tab where `tbmark` was ran)\n  open:	  Opens saved tabs from a tbmark config file\n  delete: Deletes a tbmark config file\n  help:   Prints this help message and exits\n");
	exit(-1);
}

int main(int argc, char **argv) {
	int tbm_command;
	char shell[TBMARK_PROG_MAX];

	tbm_exec_name = argv[0];
	tbm_command = tbm_index(argv[1]);

	if (argc == 2 && tbm_command != -1) {
		tbm_func_table[tbm_command](shell);
		return 0;
	} 

	printf("Usage: tbmark [command] <config file>\n\nList of available commands:\n");
	tbm_help();

	return -1;
}
