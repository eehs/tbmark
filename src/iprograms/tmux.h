#ifndef _TBM_TMUX_HEADER
#define _TBM_TMUX_HEADER

#include "../proc.h"
#include "../config.h"

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
char *log_tmux_info(int cfg_fd);
char *parse_tmux_info(char *str);
TmuxPaneInfo *populate_tmux_pane_metadata(char *tmux_iprog_info);

#endif // _TBM_TMUX_HEADER
