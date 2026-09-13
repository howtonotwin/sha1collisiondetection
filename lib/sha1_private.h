#pragma once
#include "sha1.h"
#include "private.h"

extern DECLARE_PROTECTED(n_needed_states);
extern DECLARE_PROTECTED(ctx_size);
extern DECLARE_PROTECTED(disturbance_vectors);
extern DECLARE_PROTECTED(n_disturbance_vectors);
extern DECLARE_PROTECTED(dvmask_bytes);
// Imagine this to use a "... dvmask[PROTECTED(dvmask_bytes)]" parameter.
DECLARE_PROTECTED(check_dvmask);
extern DECLARE_PROTECTED(need_state);
