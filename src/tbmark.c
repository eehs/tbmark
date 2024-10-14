#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>
#include <getopt.h>

#include "tbmark.h"
#include "proc.h"
#include "config.h"
#include "helpers.h"
#include "debug.h"

// TODO: Make memory deallocations explicit (on crashes and exits)
// TODO: Add some form of testing (different scenarios, e.g., multiple terminal tabs, CLI arguments with space characters, etc)

static struct option long_options[] = {
          { "save", no_argument, NULL, 's' },
          { "restore", no_argument, NULL, 'r' },
          { "list", no_argument, NULL, 'l' },
          { "verbose", no_argument, NULL, 'v' },
          { "help", no_argument, NULL, 'h' },
          { NULL, 0, NULL, 0 }
};

int tbm_index(enum tbm_options options) {
	for (int i = 0; i < TBMARK_SUBCMDS_LEN; i++) {
		if (options & tbm_subcmd_table[i].options) {
			return tbm_subcmd_table[i].cmd_int;
		}
	}

	return -1;
}

int tbm_save(const char *filename, enum tbm_options options) {
	char cfgdir[PATH_MAX - FILE_NAME_MAX_LEN];
	int cfg_fd = -1;

	// Create config file and start logging terminal info to it 
        snprintf(cfgdir, PATH_MAX - FILE_NAME_MAX_LEN, "%s/%s", get_homedir_of_user(getuid()), TBMARK_DIRNAME);
        mkdir(cfgdir, 0700);

        size_t filename_len = (filename != NULL) ? strnlen(filename, FILE_NAME_MAX_LEN) : FILE_NAME_MAX_LEN;
        char cfgpath[(PATH_MAX - FILE_NAME_MAX_LEN) + filename_len + PATH_MAX + 1];

        if (filename != NULL) {
                char filtered_filename[filename_len + 1];
                strncpy(filtered_filename, filename, filename_len);
                
                if (has_cfg_suffix(filename)) {
                        filtered_filename[filename_len - 4] = '\0';
                }

        	snprintf(cfgpath, (PATH_MAX - FILE_NAME_MAX_LEN) + strlen(filtered_filename) + PATH_MAX, "%s/%s.cfg", cfgdir, filtered_filename);
        } else {
        	snprintf(cfgpath, PATH_MAX, "%s/tbmark.cfg", cfgdir);
        }
        
        // Prevent overwriting existing config files
        cfg_fd = open(cfgpath, O_CREAT | O_EXCL | O_TRUNC, S_IRUSR | S_IWUSR);
        if (cfg_fd == -1 && errno == EEXIST) {
                ERROR("'%s' already exists!", cfgpath);
                exit(1);
        }

        printf("Saving terminal tabs to '%s'\n", cfgpath);

        if (cfg_fd < 0)
	        ASSERT_RET((cfg_create(cfgpath)) != -1);

       	ASSERT_RET((cfg_fd = cfg_open(cfgpath)) != -1);

        enum tbm_actions actions = TBM_RDWR_PIDINFO;
        if (~options & OPTION_VERBOSE)
                actions |= TBM_SILENT;

	// Scraping and parsing of process data starts here 
	PIDInfoArr *ttabs;
	ASSERT_RET(get_terminal_emu_and_proc_info(&ttabs, cfg_fd, getppid(), actions) != -1);

        if (options & OPTION_VERBOSE) {
                printf("\n");
                DEBUG("Gathering information on terminal tab and interactive programs");
        }

	free(ttabs->pidlist);
	free(ttabs);

	// Get rid of pre-parsed tmux pane programs (if any) 
	format_tbmark_cfg(cfgpath);
	close(cfg_fd);

	return 0;
}

// NOTE: You can probably avoid this unnecessary privilege escalation by setting the appropriate capability on the tbmark binary before running, and unsetting it after
// Must be executed with root privileges
int tbm_restore(const char *filename, enum tbm_options options) {
	pid_t ppid;
	char *cwd;
        regex_t userhome_regex;
        regmatch_t userhome_index;
        int userhome_ret;
        char userhome[PATH_MAX], cfgpath[PATH_MAX];
	int cfg_fd;
	CfgInfoArr *cfg_prog_entry_list;

	if (!running_as_root()) {
		ERROR("This subcommand must be ran with root privileges!");
		exit(1);
        }	

        enum tbm_actions actions = {0};
        if (~options & OPTION_VERBOSE)
                actions |= TBM_SILENT;

	ppid = getppid();

	// Get user's home directory through current working directory (breaks if user runs tbmark outside their home directory) 
        cwd = getcwd(NULL, 0);
        ASSERT_RET(cwd != NULL);

        ASSERT_RET(regcomp(&userhome_regex, "(\\/home\\/[a-z0-9_-]{0,31})", REG_EXTENDED) == 0);
        ASSERT_RET((userhome_ret = regexec(&userhome_regex, cwd, 1, &userhome_index, 0)) != REG_NOMATCH);

        regfree(&userhome_regex);
        if (userhome_ret == 0) {
                for (int i = userhome_index.rm_so, j = 0; i < userhome_index.rm_eo; i++, j++) {
                        userhome[j] = cwd[i];
		}

                free(cwd);
        }

        // Open and parse tbmark config file when restoring terminal tabs
        if (filename != NULL) {
                snprintf(cfgpath, PATH_MAX, "%s", filename);
        } else {
                snprintf(cfgpath, PATH_MAX + USER_MAX, "%s/%s/tbmark.cfg", userhome, TBMARK_DIRNAME);
        }

        printf("Restoring saved terminal tabs from '%s'\n", cfgpath);

        cfg_fd = cfg_open(cfgpath);

        if (options & OPTION_VERBOSE) {
                printf("\n");
                DEBUG("Opening '%s' for reading", cfgpath);
        }

	ASSERT_RET((cfg_prog_entry_list = cfg_parse(cfg_fd)) != NULL);

        if (options & OPTION_VERBOSE)
                DEBUG("Parsing saved terminal tabs\n");

	if (cfg_exec(cfg_fd, ppid, cfg_prog_entry_list, actions) == -1) {
                free(cfg_prog_entry_list->entries);
                free(cfg_prog_entry_list);
                close(cfg_fd);

                return -1;
        }

        if (options & OPTION_VERBOSE) {
                printf("\n");
                DEBUG("Re-opening programs in newly created tabs");
        }

	free(cfg_prog_entry_list->entries);
	free(cfg_prog_entry_list);
	close(cfg_fd);

	return 0;
}

int tbm_list(const char *filename, enum tbm_options options) {
        int fd;

        if (filename == NULL) {
		ERROR("Feed me a config file!");
                exit(1);
        }

        fd = cfg_open(filename);
        print_cfg_tabs_from_fd(fd, true, filename, false, NULL, (int *)-1);

        return 0;
}

void tbm_usage() {
        fprintf(stderr, "Usage: tbmark [OPTION] [FILE]\n\n");
        
        fprintf(stderr, "Options:\n");
        fprintf(stderr, "  -s, --save\t\tsaves opened terminal tabs to file (excluding tab where tbmark ran)\n");
        fprintf(stderr, "  -r, --restore\t\trestores saved terminal tabs from file\n");
        fprintf(stderr, "  -l, --list\t\tdisplays saved terminal tabs given a file\n");
        fprintf(stderr, "  -v, --verbose\t\tshow verbose information\n");
        fprintf(stderr, "  -h, --help\t\tdisplay help message and exits\n");
}

int main(int argc, char **argv) {
	int tbm_command;
        enum tbm_options options= {0};

        int param;
        while ((param = getopt_long(argc, argv, "srlvh", long_options, NULL)) != -1) {
                switch (param) {
                        case 's':
                                options |= OPTION_SAVE;
                                break;
                        case 'r':
                                options |= OPTION_RESTORE;
                                break;
                        case 'l':
                                options |= OPTION_LIST;
                                break;
                        case 'v':
                                options |= OPTION_VERBOSE;
                                break;
                        case 'h':
                        default:
                                tbm_usage();
                                exit(1);
                }
        }

        tbm_command = tbm_index(options);
        if (tbm_command != -1) {
                tbm_func_table[tbm_command](argv[optind], options);

                return 0;
        }

        tbm_usage();
	return 1;
}
