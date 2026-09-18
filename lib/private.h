#pragma once

#include "util.h"

#define SHA1DC_INSIDE_LIBRARY 1

#define PROTECTED(sym)         sha1dc_ ## sym ## _
#define DECLARE_PROTECTED(sym) \
  typeof(sha1dc_ ## sym) PROTECTED(sym) [[                  \
    gnu::copy(sha1dc_ ## sym), gnu::visibility("hidden")]]; \
  static_assert(true)
// Do NOT use on functions marked [[gnu::ifunc]]! Doing so totally confuses GCC.
// The "alias" must be marked with [[gnu::ifunc]] again, which is already a
// definition and thus makes the [[gnu::alias]] in here moot.
#define EXPORT_PROTECTED(sym)  \
  typeof(PROTECTED(sym))                                \
    PROTECTED(sym) [[gnu::visibility("hidden")]],       \
    sha1dc_ ## sym [[                                   \
      gnu::copy(PROTECTED(sym))                         \
    , gnu::alias(STRICT1(STRINGIFY, PROTECTED(sym)))]]; \
  static_assert(true)
