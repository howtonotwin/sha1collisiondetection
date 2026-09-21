# sha1collisiondetection
Library and command line tool to detect SHA-1 collisions in files

Copyright 2017 Marc Stevens <marc@marc-stevens.nl>\
Copyright 2026 Rasheeq Azad <rasheeqazad@howtonotwin.net>

Distributed under the MIT Software License.

See accompanying file LICENSE.txt or copy at https://opensource.org/licenses/MIT.

## Developers

Original (https://github.com/cr-marcstevens/sha1collisiondetection):
- Marc Stevens, CWI Amsterdam (https://marc-stevens.nl/)
- Dan Shumow, Microsoft Research (https://www.microsoft.com/en-us/research/people/danshu/)

This fork (https://github.com/howtonotwin/sha1collisiondetection):
- Rasheeq Azad (https://howtonotwin.net/)

## About
This library and command line tool were designed as near drop-in replacements
for common SHA-1 libraries and sha1sum. They will compute the SHA-1 hash of any
given file and additionally will detect cryptanalytic collision attacks against
SHA-1 present in each file.

More specifically, they will detect any cryptanalytic collision attack against
SHA-1 using any of the top 32 SHA-1 disturbance vectors with probability 1:
```
    I(43,0), I(44,0), I(45,0), I(46,0), I(47,0), I(48,0), I(49,0), I(50,0),
    I(51,0), I(52,0), I(46,2), I(47,2), I(48,2), I(49,2), I(50,2), I(51,2),
    II(45,0), II(46,0), II(47,0), II(48,0), II(49,0), II(50,0), II(51,0),
    II(52,0), II(53,0), II(54,0), II(55,0), II(56,0), II(46,2), II(49,2),
    II(50,2), II(51,2)
```
The probability of a false positive is smaller than 2^-90 and can be neglected.

The library supports both an indicator flag that applications can check and act
on, as well as a special "safe hash" mode that returns the real SHA-1 hash when
no collision is detected and a different "safe" hash when a collision is
detected. Colliding files will have the same SHA-1 hash, but will have different
unpredictable safe-hashes. This essentially enables protection of applications
against SHA-1 collisions with no further changes in the application, e.g.,
digital signature forgeries based on SHA-1 collisions automatically become
invalid.

For the theoretical explanation of collision detection see the award-winning
paper on _Counter-Cryptanalysis_:

Counter-cryptanalysis, Marc Stevens, CRYPTO 2013, Lecture Notes in Computer
Science, vol. 8042, Springer, 2013, pp. 129-146,
https://marc-stevens.nl/research/papers/C13-S.pdf

This particular repository is a fork of the original project, with the goal of
achieving performance comparable to optimized implementations of plain SHA-1. It
has, so far, been optimized for x86-64 processors with support for AVX-512 and
hardware SHA extensions. On such hardware, the implementation runs at over half
the speed of the plain SHA-1 implementation in OpenSSL. (Tests on Intel Rocket
Lake and Granite Rapids processors show absolute throughputs of about 1 GiB/s.)

## Compiling

Run:
```
make
```

This fork of the project expects to be compiled with GCC 17 with link-time
optimization (the `Makefile` defaults to passing `-O2` and `-flto` to GCC). It
also expects to run in an environment that supports the GNU "ifunc" mechanism,
which is required in order to select the correct optimized code for the hardware
found at runtime.

The following outputs should appear in a directory named `bin`:
* `sha1dcsum`: this is an executable program meant to act as a drop-in
  replacement for `sha1sum`. It interprets each of its command-line arguments as
  a file name and computes the "safe SHA-1" hash of each file. (It does not
  support any options, though.)

  This program is dynamically linked against `libsha1detectcoll.so`, and thus is
  unlikely to work until that library is installed on the system. For testing,
  one may use the script `./run`, like so: `./run sha1dcsum <arguments>`.
* `sha1dcsum_static`: this is the same program as `sha1dcsum`, except it
  statically links `libsha1detectcoll.a`. This makes it a few percent faster and
  also means it works on systems without the library installed.
* `sha1dcsum_partialcoll`: this is a version of `sha1dcsum` that detects and
  warns for files that were generated with a cryptanalytic collision attack
  against reduced-round SHA-1. This is used for testing, as it is much easier to
  break the reduced hash.
* `libsha1detectcoll.o`: this is a relocatable object that can be statically
  linked into client programs. It also includes GCC LTO information, so client
  programs can link against it with LTO, at their choice.
* `libsha1detectcoll.a`: this is a static library containing a copy of
  `libsha1detectcoll.o`.
* `libsha1detectcoll.so`: this is a shared object against which client programs
  can dynamically link.

The installable products can be installed by running `make install`, or deleted
from the system by running `make uninstall`.

## Command-line usage

Examples:
```sh
./run sha1dcsum             test/sha1_reducedsha_coll.bin test/shattered-1.pdf
./run sha1dcsum_partialcoll test/sha1_reducedsha_coll.bin test/shattered-1.pdf
pipe_data | bin/sha1dcsum_static
```

## Library usage

See the documentation in `include/sha1.h`. Here is a simple example code snippet:
```c
#include <sha1dc/sha1.h>

unsigned char hash[20];
alignas(sha1dc_ctx_alignment) char storage[sha1dc_ctx_size()];
struct sha1dc_ctx *ctx = (void*)storage;
sha1dc_init(ctx);

// // disable safe-hash mode (safe-hash mode is enabled by default)
// sha1dc_set_do_safe_hash(ctx, false);
// // install a handler to act on attacks as soon as they are detected
// sha1dc_set_callback(ctx, my_handler, my_handler_data);

sha1dc_ingest(ctx, buffer, sizeof buffer);

bool found_collision = sha1dc_finish(hash, ctx);
if(found_collision) puts("collision detected");
else                puts("no collision detected");
```

## Inclusion in other programs

The original version of this library had several preprocessor knobs for use by
projects directly including the library source code. Those customization points
have been removed in this fork. Due to the rather particular compilation
requirements of this version, it is recommended that users use the provided
Makefile to produce a binary form of the library, and link against that.

This fork marks its ABI as version 2 to distinguish it from the original (which
uses version 1). (This is *not* to imply that it is an "official" continuation.)
Specifically, the library soname is `libsha1detectcoll.so.2`. In order to link
against the library, one may use the provided header file `include/sha1.h`. This
header, by default, installs to the system include directory under the name
`sha1dc/sha1.h` (see example code, above). This header itself requires a C23
compatible compiler (and it is *not* compatible with C++).

## Configuration

The source code contains some C preprocessor logic to auto-detect certain facts
about the compilation environment and the target CPU/platform and accordingly
enable/disable certain features. These choices can be overridden by adding
appropriate flags to `CPPFLAGS` during compilation. (E.g. instead of `make`, you
may run `make 'CPPFLAGS = -DENABLE_AVX512=0'`.)

The following is a non-exhaustive list of configurable options (there may be/are
more in the source code, but these are the ones that make the most sense for a
user to change):

- `ALLOW_UNALIGNED_ACCESS`

  Set to `1` to indicate that unaligned input data need not be copied into
  aligned buffers before processing, or set to `0` to indicate that such copying
  should be done. By default, this is set to `1` when compiling for x86 and
  x86-64 targets, and to `0` otherwise.

- `ENABLE_X86_EXTENSIONS`

  Set to `1` to indicate that architecture specific code making use of x86-64
  instruction set extensions should be built, or `0` to indicate it shouldn't.
  By default, this is set to `1` when building for x86-64 and to `0` otherwise.
  Setting this to `1` does not make the code *require* the extensions: the
  unoptimized code is still built, and the code most appropriate for the
  hardware is selected at runtime.

  It can be set to `0` on x86-64 if the optimized code is not wanted (e.g. if it
  is known that the target processor has none of the used extensions). This may
  marginally improve performance, by making the code smaller and removing the
  runtime selection logic. The extension sets used are SSSE3, SHA, and AVX-512s
  F, BW, VL, and VBMI.

- `ALWAYS_AVX512`

  Set to `1` to indicate that AVX-512 instructions should be assumed to be
  present, and the non-AVX-512 code should simply not be built. Unlike
  `ENABLE_X86_EXTENSIONS`, setting this to `1` does drop support for hardware
  without the extensions. This is always `0` by default.

  (As AVX-512 is a collective name for partly independent instruction sets, the
  meaning of this setting is a little imprecise.)

- `DO_SAFE_HASH_DEFAULT`

  If `1`, "safe hash" mode (see above) will be enabled by default (but a client
  program can still disable it). If `0`, "safe hash" mode will be disabled by
  default (but a client program can still enable it). This setting is `1` by
  default.
