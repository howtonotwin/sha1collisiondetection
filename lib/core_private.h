// © 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
// © 2026 Rasheeq Azad <rasheeqazad@howtonotwin.net>
// SPDX-License-Identifier: MIT
//
// License text available in accompanying file LICENSE.txt, or at
// https://opensource.org/licenses/MIT.
#pragma once
#include "private.h"
#include "data.h"
#include "sha1_private.h"

#include "core.h"

DECLARE_PROTECTED(dvmask_bytes);
DECLARE_PROTECTED(check_dvmask);

// Summary of the `test_state`s of all the `sha1dc_disturbance_vectors`: a state
// (numbered from 0 to 80, inclusive) has a nonnegative entry here if any DV
// needs it (has it as `test_state`), and has a -1 if it is never needed.
//
// The nonnegative number for states that are needed is the number of that
// state among the needed states. I.e. it is the index for that state into a
// "compressed" array of states where unneeded states are left out.
extern const signed char sha1dc_need_state [[gnu::visibility("hidden")]][81];
// The number of distinct values of `test_state` among the DVs, and the number
// of nonnegative entries in `compress`.
extern const size_t sha1dc_n_needed_states [[gnu::visibility("hidden")]];

DECLARE_PROTECTED(process);
// The parameter should be "... dvmask[PROTECTED(dvmask_bytes)()]".
DECLARE_PROTECTED(ubc_check);
