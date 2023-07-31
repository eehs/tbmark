#ifndef _HELPERS_HEADER
#define _HELPERS_HEADER

#define IPROG_INFO_SIZE 1024
#define MAX_USERNAME_LEN 8

typedef enum {
	TBM_TMUX
} tbmark_supported_iprograms;

/* Dedicated function pointers for arguments of a specific type */
typedef char *(*fp_interactive_progs_int)(int cfg_fd);
typedef char *(*fp_interactive_progs_str)(char *str);
extern const char *iprograms[INTERACTIVE_PROGRAMS_COUNT];
extern const char *iprogram_glossary[INTERACTIVE_PROGRAMS_COUNT];
extern fp_interactive_progs_int iprogram_loggers[INTERACTIVE_PROGRAMS_COUNT];
extern fp_interactive_progs_str iprogram_parsers[INTERACTIVE_PROGRAMS_COUNT];

/* Returns index to `iprograms` on successful match of substring */
int is_iprogram(const char *cmdlargs);
char *get_iprogram_name(int index);

int continue_if_root();
char *get_homedir_of_user();
int exec_and_capture_output(const char *cmd_in, char *cmd_out);
char **split(char *str, char delim, size_t max_arr_len, size_t *out_arr_len);
int remove_lines_from_file(char *path, char *delim, size_t max_file_size);
void free_str_arr(char **arr, size_t arr_len);

#endif // _HELPERS_HEADER
