#ifndef TBMARK_MAIN_H
#define TBMARK_MAIN_H

#include "common.h"

#define TBMARK_SUBCMDS_LEN (sizeof(tbm_subcmd_table)/sizeof(tbm_subcmd_table[0]))
#define TBMARK_DIRNAME ".tbmark"

int tbm_index(enum tbm_options option);
int tbm_save(const char *filename, enum tbm_options flags);
int tbm_open(const char *filename, enum tbm_options flags);
int tbm_list(const char *filename, enum tbm_options flags);

// Basically atoi(cmdarg)
typedef struct option_int_map {
        enum tbm_options options;
	int cmd_int;
} option_int_map;

option_int_map tbm_subcmd_table[] = {
	{ OPTION_SAVE, 0 },
	{ OPTION_RESTORE, 1 },
        { OPTION_LIST, 2 }
};

typedef int (*tbm_func)(const char *filename, enum tbm_options flags);
tbm_func tbm_func_table[] = { tbm_save, tbm_open, tbm_list };

#endif // TBMARK_MAIN_H
