#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tmux.h"
#include "../proc.h"
#include "../config.h"
#include "../debug.h"
#include "../helpers.h"

/* Steps to retrieve process metadata of tmux panes
 * ------------------------------------------------
 * 1. tmux's server '#{pid}' returns PIDs of all pane processes (shell program)' 
 * 2. Identify which subprocesses ran within the shell program belong to which tmux client and pane respectively.
 * 3. Log process info to the tbmark config file.
 *
 */

#define GET_PANES_INFO_CMD "tmux list-panes -F 'pane_pid:#{pane_pid} pane_width:#{pane_width} pane_height:#{pane_height} pane_active:#{pane_active} pane_at_top:#{pane_at_top} pane_at_bottom:#{pane_at_bottom} pane_at_left:#{pane_at_left} pane_at_right:#{pane_at_right}'"
#define GET_WINDOW_PANE_COUNT_CMD "tmux list-panes -F '#{window_panes}' | head -1"
#define GET_TMUX_SERVER_PID_CMD "tmux list-panes -F '#{pid}' | head -1"

// TODO: Get rid of magic numbers when allocating memory

char *get_tmux_panes_info(PIDInfoArr *pane_pids) {
	/* This tmux subcommand returns metadata pertaining to pane(s) of the most recently selected window */
	char *buf = calloc(1024, sizeof(char));
	ASSERT_NULL(buf != NULL);

	int get_panes_info_res, get_window_pane_count_res;

	char *tmux_panes_info = calloc(1024, sizeof(char));
	ASSERT_NULL(tmux_panes_info != NULL);

	get_panes_info_res = exec_and_capture_output(GET_PANES_INFO_CMD, buf);
	ASSERT_NULL(get_panes_info_res != -1);
	strncpy(tmux_panes_info, buf, 1024);

	/* Outputs the pane count in the most recently selected tmux window into the same buffer as above */
	buf[0] = '\0';
	get_window_pane_count_res = exec_and_capture_output(GET_WINDOW_PANE_COUNT_CMD, buf);
	ASSERT_NULL(get_window_pane_count_res != -1);

	free(buf);

	return tmux_panes_info;
}

char *log_tmux_info(int cfg_fd) {
	pid_t tmux_spid;
	int get_tmux_spid_res;
	PIDInfoArr *tmux_first_programs;
	char *out;

	/* Get PID of tmux server */
	char *pid_buf = calloc(7, sizeof(char));
	ASSERT_NULL(pid_buf != NULL);

	get_tmux_spid_res = exec_and_capture_output(GET_TMUX_SERVER_PID_CMD, pid_buf);
	ASSERT_NULL(get_tmux_spid_res != -1);

	char *tmux_spid_str = pid_buf;
	tmux_spid = atoi(tmux_spid_str);
	ASSERT_NULL(tmux_spid != 0);

	/* 3rd argument of `getpid_of_tabs` is 0 here since we are treating tmux panes (shell as parent and actual program the child) as fake 'terminal tabs' */
	ASSERT_NULL(get_proc_info_ttabs(&tmux_first_programs, cfg_fd, tmux_spid, 0, TBM_CALLED_FROM_IPROG | TBM_RDWR_PIDINFO) != -1);

	out = get_tmux_panes_info(tmux_first_programs);

	free(tmux_first_programs->pidlist);
	free(tmux_first_programs);
	free(tmux_spid_str);

	return out;
}

char *parse_tmux_info(char *str) {
	char *out = extract_tbm_entry_field_str(str, IPROG_INFO_SIZE, "[tmux] ");

	return out;
}

TmuxPaneInfo *populate_tmux_pane_metadata(char *tmux_iprog_info) {
	TmuxPaneInfo *pane = calloc(1, sizeof(TmuxPaneInfo));
	ASSERT_NULL(pane != NULL);

	pane->width = extract_tbm_entry_field_int(tmux_iprog_info, 14, "pane_width:");
	pane->height = extract_tbm_entry_field_int(tmux_iprog_info, 15, "pane_height:");
	pane->active = (bool)extract_tbm_entry_field_int(tmux_iprog_info, 13, "pane_active:");
	pane->at_top = (bool)extract_tbm_entry_field_int(tmux_iprog_info, 13, "pane_at_top:");
	pane->at_bottom = (bool)extract_tbm_entry_field_int(tmux_iprog_info, 16, "pane_at_bottom:");
	pane->at_left = (bool)extract_tbm_entry_field_int(tmux_iprog_info, 14, "pane_at_left:");
	pane->at_right = (bool)extract_tbm_entry_field_int(tmux_iprog_info, 15, "pane_at_right:");

	return pane;
}
