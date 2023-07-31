#ifndef _TBMARK_HEADER
#define _TBMARK_HEADER

#define TBM_NUM_CMDARGS (sizeof(tbm_cmdarg_table)/sizeof(tbm_cmdarg_table[0]))

int tbm_index(const char *cmdarg);
int tbm_save(const char *shell);
int tbm_open(const char *shell);
int tbm_delete(const char *shell);
void tbm_help();

// argv[0]
static const char *tbm_exec_name;

// Basically atoi(cmdarg)
typedef struct str_int_map {
	const char *cmd;
	int cmd_int;
} str_int_map;

str_int_map tbm_cmdarg_table[] = {
	{"save", 0},
	{"open", 1},
	{"delete", 2}
};

typedef int (*tbm_func)(const char *shell);
tbm_func tbm_func_table[] = {tbm_save, tbm_open, tbm_delete};

#endif // _TBMARK_HEADER
