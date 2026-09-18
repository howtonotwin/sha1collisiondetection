#pragma once
// Tweakable.
//
// Not "is -funroll-loops on?" but rather "should '#pragma GCC unroll' be used?"
// If this is off, `STATIC_FOR` is just `for`, and other logic in and around
// loops (usually conditionals of some kind) may also disable itself.
//
// If a sensitive loop still gets unrolled (despite this being off), its
// code may be a little suboptimal but will usually be "fine". If this is on
// and sensitive loops are not unrolled (e.g. `-Og` makes GCC ignore unroll
// pragmas), the generated code may be *awful* (e.g. ubc_check_avx512 gets ~70%
// percent slower). Do not allow this to happen.
#ifndef UNROLLING_LOOPS
  // This is just a best guess
# define UNROLLING_LOOPS (__OPTIMIZE__ && !__OPTIMIZE_SIZE__)
#endif

#define STRICT1(F, x) F(x)
#define STRINGIFY(x)  # x

// Nice way to apply a stored list of processor features to a block of code.
#define PRAGMA_WORDS(...)            _Pragma(# __VA_ARGS__)
#define FEATURE_INTO_TARGET(feature) feature ","
#define SET_FEATURES(F)              \
   _Pragma("GCC push_options")                              \
   STRICT1(PRAGMA_WORDS, GCC target F(FEATURE_INTO_TARGET))
#define RESET_FEATURES               _Pragma("GCC pop_options")
#define CHECK_FEATURE_AND(f)         __builtin_cpu_supports(f) &&

// A `for` loop marked for "complete" compile-time unrolling (we actually just
// specify the maximum unroll count GCC will take). Odd idiosyncracy of GCC: it
// will complain if it is manually asked to unroll a for loop with an empty
// condition. Supply `true` instead, which has exactly the same meaning but
// makes GCC happy.
//
// There is no automated check for successful unrolling. Always check the
// assembly! Unrolling can also be suppressed (out of our control) by compiler
// options (e.g. `-Og` causes GCC to ignore unroll directives), and this base
// variant of the macro also voluntarily disables itself under `-Os` and more
// generally whenever `UNROLLING_LOOPS` is set to false.
#if UNROLLING_LOOPS
#define STATIC_FOR _Pragma("GCC unroll 65534") for
#else
#define STATIC_FOR for
#endif

// A variant of `STATIC_FOR` for loops that are expected to get *smaller* when
// unrolled (usually due to further optimization). This variant always tries to
// unroll, ignoring `UNROLLING_LOOPS` (and thus the `!__OPTIMIZE_SIZE__` check
// embedded by default in that condition).
#define SMALL_STATIC_FOR _Pragma("GCC unroll 65534") for
