#ifndef TBMARK_IPROG_TMUX_H
#define TBMARK_IPROG_TMUX_H

#include "../proc.h"
#include "../config.h"
#include "../common.h"

typedef struct {
	int width;
	int height;
	bool active;
	bool at_top;
	bool at_bottom;
	bool at_left;
	bool at_right;
} TmuxPaneInfo;

char *get_tmux_panes_info(PIDInfoArr *pane_pids);
char *log_tmux_info(int cfg_fd, enum tbm_actions actions);
char *parse_tmux_info(char *str);
TmuxPaneInfo *populate_tmux_pane_metadata(char *tmux_iprog_info);

#endif // TBMARK_IPROG_TMUX_H
