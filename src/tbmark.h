#ifndef _TBMARK_HEADER
#define _TBMARK_HEADER

#define TBM_NUM_SUBCMDS (sizeof(tbm_subcmd_table)/sizeof(tbm_subcmd_table[0]))
#define TBMARK_DIRNAME ".tbmark"

int tbm_index(const char *subcmd);
int tbm_save(const char *shell, const char *filename);
int tbm_open(const char *shell, const char *filename);
void tbm_help();

// Basically atoi(cmdarg)
typedef struct str_int_map {
	const char *cmd;
	int cmd_int;
} str_int_map;

str_int_map tbm_subcmd_table[] = {
	{"save", 0},
	{"open", 1}
};

typedef int (*tbm_func)(const char *shell, const char *filename);
tbm_func tbm_func_table[] = {tbm_save, tbm_open};

#endif // _TBMARK_HEADER
