#ifndef _CONFIG_HEADER
#define _CONFIG_HEADER

#include <ctype.h>
#include <linux/limits.h>
#include "common.h"
#include "proc.h"

typedef struct {
	char cwd[PATH_MAX];
	char comm[COMM_MAX_LEN];
	char cmdlargs[ARG_MAX];
	char metadata[ARG_MAX];
	char iprogram_name[COMM_MAX_LEN];
	char iprogram_info[IPROG_INFO_SIZE];
	int iprogram_index;
} CfgInfo;

typedef struct {
	CfgInfo *entries;
	size_t entries_len;
} CfgInfoArr;

// Takes in a buffer containing file contents and returns the tbmark entry field
char *extract_tbm_entry_field_str(const char *buf, size_t max_tag_and_value_len, char *tag);
int extract_tbm_entry_field_int(const char *buf, size_t max_tag_and_value_len, char *tag);

char *strip_args_from_cmd(const char *cmd);

int cfg_create(const char *pathname);
int cfg_open(const char *pathname);
CfgInfoArr *cfg_parse(int fd);
int cfg_exec(int fd, pid_t ppid, CfgInfoArr *cfginfo_list);
ssize_t cfg_write(int fd, const char *buf, size_t size);

#endif // _CONFIG_HEADER
