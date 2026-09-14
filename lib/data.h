#pragma once
#include <stddef.h>
#include <stdint.h>

// Adapt the output of the parse_bitrel program, renaming things nicely.
#define sha1dc_disturbance_vector_dv_class     class
#define sha1dc_disturbance_vector_k            k
#define sha1dc_disturbance_vector_b            b
#define sha1dc_disturbance_vector_test_state   test_state
#define sha1dc_disturbance_vector_message_mask message_mask
#define sha1dc_ubc_a      a
#define sha1dc_ubc_b      b
#define sha1dc_ubc_i      i
#define sha1dc_ubc_j      j
#define sha1dc_ubc_c      c
#define sha1dc_ubc_dvmask dvmask
#define sha1dc_disturbance_vectors sha1dc_disturbance_vectors_defn
#define sha1dc_n_needed_states     sha1dc_n_needed_states_defn
#define sha1dc_need_state          sha1dc_need_state_defn
#include "parse_bitrel.inc"
#undef sha1dc_disturbance_vectors
#undef sha1dc_n_needed_states
#undef sha1dc_need_state
#undef sha1dc_disturbance_vector_dv_class
#undef sha1dc_disturbance_vector_k
#undef sha1dc_disturbance_vector_b
#undef sha1dc_disturbance_vector_test_state
#undef sha1dc_disturbance_vector_message_mask
#undef sha1dc_ubc_a
#undef sha1dc_ubc_b
#undef sha1dc_ubc_i
#undef sha1dc_ubc_j
#undef sha1dc_ubc_c
#undef sha1dc_ubc_dvmask
