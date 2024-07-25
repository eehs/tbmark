#ifndef TBMARK_HELPERS_H
#define TBMARK_HELPERS_H

#define IPROG_INFO_SIZE 1024 // seems like a decent threshold value for holding iprogram information

typedef enum {
	TBM_TMUX
} tbmark_supported_iprograms;

// Dedicated function pointers for arguments of a specific type
typedef char *(*fp_interactive_progs_int)(int cfg_fd, enum tbm_actions actions);
typedef char *(*fp_interactive_progs_str)(char *str);
extern const char *iprograms[INTERACTIVE_PROGRAMS_COUNT];
extern const char *iprogram_glossary[INTERACTIVE_PROGRAMS_COUNT];
extern fp_interactive_progs_int iprogram_loggers[INTERACTIVE_PROGRAMS_COUNT];
extern fp_interactive_progs_str iprogram_parsers[INTERACTIVE_PROGRAMS_COUNT];

// Returns index to 'iprograms' on successful match of substring
int is_iprogram(const char *cmdlargs, bool savingTabs);
char *get_iprogram_name(int index);

bool has_cfg_suffix(const char *filename);
bool running_as_root();
char *get_homedir_of_user();
int exec_and_capture_output(const char *cmdIn, char *cmdOut);
char **split(char *str, char delim, size_t maxArrLen, size_t *outArrLen);
int format_tbmark_cfg(char *path);
void print_cfg_tabs_from_fd(int fd, bool showDebug, const char *filename, bool getInteractiveProgramMetadata, char **tmuxSocketPath, int *tmuxPaneCount);
void free_str_arr(char **arr, size_t arrLen);

#endif // TBMARK_HELPERS_H
