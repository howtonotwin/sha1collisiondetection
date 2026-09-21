// © 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow <danshu@microsoft.com>
// © 2026 Rasheeq Azad <rasheeqazad@howtonotwin.net>
// SPDX-License-Identifier: MIT
//
// License text available in accompanying file LICENSE.txt, or at
// https://opensource.org/licenses/MIT.

#include <stdcountof.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
#include <libgen.h>
#endif

#include "sha1.h"

#ifdef _WIN32
char *basename(const char *path) {
  const char *base = path;
  for(const char *cur = path; *cur;) {
    if(*cur == '\\') base = ++cur;
    else             cur++;
  }
  return (char*)base;
}
#endif

static unsigned char buffer[65536];
int main(int, char **argv) {
  const char *self = argv[0] ? basename(argv[0]) : "sha1dcsum";
  const char *const *files =
      argv[0] && argv[1]
    ? (typeof(files))(argv + 1)
    : (static const char *const[]) { "-", nullptr };
  alignas(sha1dc_ctx_alignment) char ctx_storage[sha1dc_ctx_size()];
  struct sha1dc_ctx *ctx = (void*)ctx_storage;

  bool any_error = false, all_error = true;
  for(; *files; files++) {
    sha1dc_init(ctx);

    // If the program name includes the word "partial", then also test for
    // reduced-round SHA-1 collisions
    sha1dc_set_detect_reduced_round_coll(ctx, strstr(self, "partial"));

    FILE *f = strcmp(*files, "-") ? fopen(*files, "rb") : stdin;
    if(!f) {
      fprintf(
        stderr, "%s: cannot open file '%s': %s\n"
      , self, *files, strerror(errno));
      return 1;
    }

    for(size_t read; read = fread(buffer, 1, sizeof buffer, f);) {
      sha1dc_ingest(ctx, buffer, read);
      if(read != sizeof buffer) break;
    }
    if(ferror(f)) {
      fprintf(
        stderr, "%s: error while reading file '%s': %s\n"
      , self, *files, strerror(errno));
      any_error = true;
      continue;
    } else if(fclose(f)) {
      fprintf(
        stderr, "%s: error while closing file '%s': %s\n"
      , self, *files, strerror(errno));
      any_error = true;
    }
    all_error = false;

    unsigned char hash[sizeof(sha1_chaining_value)];
    bool collision = sha1dc_finish(hash, ctx);
    for(size_t i = 0; i < countof hash; i++) printf("%02x", hash[i]);
    fputs(
        collision
      ? " *coll* "
      : "        "
    , stdout);
    puts(*files);
  }
  return any_error + 2 * all_error;
}
