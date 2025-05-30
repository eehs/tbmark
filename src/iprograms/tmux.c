#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iprograms/tmux.h>
#include <proc.h>
#include <config.h>
#include <helpers.h>
#include <debug.h>

/* Steps to retrieve process metadata of tmux panes
 * ------------------------------------------------
 * 1. tmux's server '#{pid}' returns PIDs of all pane processes (shell program)' 
 * 2. Identify which subprocesses ran within the shell program belong to which tmux client and pane respectively.
 * 3. Log process info to the tbmark config file.
 */
 

#define GET_PANES_INFO_CMD "tmux list-panes -F 'pane_pid:#{pane_pid} pane_width:#{pane_width} pane_height:#{pane_height} pane_active:#{pane_active} pane_at_top:#{pane_at_top} pane_at_bottom:#{pane_at_bottom} pane_at_left:#{pane_at_left} pane_at_right:#{pane_at_right}'"
#define GET_TMUX_SERVER_PID_CMD "tmux list-panes -F '#{pid}' | head -1"

// This tmux subcommand returns metadata pertaining to pane(s) of the most recently selected window 
char *get_tmux_panes_info(PIDInfoArr *pane_pids) {
	char *tmux_panes_info = calloc(IPROG_INFO_SIZE, sizeof(char));
	ASSERT_NULL(tmux_panes_info != NULL);

	int get_panes_info_res = exec_cmd_and_capture_output(GET_PANES_INFO_CMD, tmux_panes_info, IPROG_INFO_SIZE);
	ASSERT_NULL(get_panes_info_res != -1);

	return tmux_panes_info;
}

char *log_tmux_info(int cfg_fd, enum tbm_actions actions) {
	pid_t tmux_spid;
	int get_tmux_spid_res;
	PIDInfoArr *tmux_first_programs;
	char *out;

	// Get tmux server pid
	char *pid_buf = calloc(PID_MAX_LEN_WITH_NB, sizeof(char));
	ASSERT_NULL(pid_buf != NULL);

	get_tmux_spid_res = exec_cmd_and_capture_output(GET_TMUX_SERVER_PID_CMD, pid_buf, PID_MAX_LEN);
	ASSERT_NULL(get_tmux_spid_res != -1);

	char *tmux_spid_str = pid_buf;
	tmux_spid = atoi(tmux_spid_str);
	ASSERT_NULL(tmux_spid != 0);

	// Get tmux pane programs and their metadata
        enum tbm_actions tmux_actions = TBM_CALLED_FROM_IPROG | TBM_RDWR_PIDINFO;
        if (actions & TBM_SILENT)
                tmux_actions |= TBM_SILENT;

	ASSERT_NULL(get_proc_info_ttabs(&tmux_first_programs, cfg_fd, tmux_spid, 0, tmux_actions) != -1);
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
