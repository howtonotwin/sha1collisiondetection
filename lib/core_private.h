#pragma once
#include "core.h"
#include "private.h"

// Number of distinct values for `sha1dc_disturbance_vectors[*].test_state`.
extern const size_t sha1dc_n_needed_states [[gnu::visibility("hidden")]];
// Summary of the `test_state`s of all the `sha1dc_disturbance_vectors`. States
// (numbered 0 to 80, inclusive) have a nonnegative entry here if any DV needs
// them, and they have a -1 if they are never needed.
//
// The nonnegative number for states that are needed is the number of that state
// among the needed states. I.e. it is the index for that state into an array of
// states where the unneeded states do not get array elements.
extern const signed char sha1dc_need_state [[gnu::visibility("hidden")]][81];
// Space for `sha1dc_process` to put `sha1dc_n_needed_states` saved states.
extern thread_local sha1_chaining_value
  sha1dc_process_block_states [[gnu::visibility("hidden")]][];

DECLARE_PROTECTED(process);

extern DECLARE_PROTECTED(dvmask_bytes);
// Imagine these to use "... dvmask[PROTECTED(dvmask_bytes)]" parameters.
DECLARE_PROTECTED(ubc_check);
DECLARE_PROTECTED(check_dvmask);
