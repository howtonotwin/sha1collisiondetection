##
## Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow (danshu@microsoft.com)
## Distributed under the MIT Software License.
## See accompanying file LICENSE.txt or copy at
## https://opensource.org/licenses/MIT
##

# dynamic library compatibility
# 1. If the library source code has changed at all since the last update,
#    then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# 2. If any interfaces have been added, removed, or changed since the last update,
#    increment current, and set revision to 0.
# 3. If any interfaces have been added since the last public release, then increment age.
# 4. If any interfaces have been removed or changed since the last public release,
#    then set age to 0.
# Needs bump
LIBCOMPAT = 1:0:0

PREFIX    ?= /usr/local
BINDIR     = $(PREFIX)/bin
LIBDIR     = $(PREFIX)/lib
INCLUDEDIR = $(PREFIX)/include/sha1dc

CC     ?= gcc
LD     ?= gcc
AR     ?= gcc-ar
CC_DEP ?= $(CC)

ifeq ($(shell uname),Darwin)
LIBTOOL ?= glibtool
INSTALL ?= install
else
LIBTOOL ?= libtool
INSTALL ?= install
endif

# libtool flatly does not understand partial linking: it cannot take a set of
# .lo files and produce another .lo file. `libtool --mode=link $CC -o out.lo`
# will cause libtool to run `ld -r -o out.lo`, which a) uses the wrong driver
# (plain `ld`, without an LTO plugin, preserves but does not act on LTO data)
# and b) produces a binary object file for `out.lo`, which means libtool cannot
# read it back in as a libtool object (since it isn't a libtool object).
# `libtool --mode=compile $CC in*.lo` also won't work, because libtool won't
# replace .lo files with their real .o files on a *compiler* command line.
#
# But the compiler driver (or at least, GCC) can directly turn multiple .c files
# into one .o file, with LTO, when -r is passed. This precludes incremental
# rebuilds, which is annoying, but it is the only thing that works with libtool.
#
# So: flag to $CC to produce "an .o file" (relocatable object). This can be -c
# (which only works when compiling one source file), or -r (which is general).
RELOC      = -c
RELOC.LTO  = -r
CFLAGS     = -O2 -flto -ffat-lto-objects
CFLAGS    += -std=c2y -Wall -Wextra -Wno-parentheses -pedantic
CPPFLAGS   = -Ilib
# no LDFLAGS

LT_CC      = $(LIBTOOL) --tag=CC --mode=compile $(CC)
LT_CC_DEP  = $(CC)
LT_LD      = $(LIBTOOL) --tag=CC --mode=link    $(CC)
LT_INSTALL = $(LIBTOOL) --tag=CC --mode=install $(INSTALL)

ENSUREDIR = @mkdir -p $(@D)
H_DEP := $(shell find . -type f -name "*.h")
FS_LIB = $(wildcard $(LIB_DIR)/*.c)
FS_SRC = $(wildcard $(SRC_DIR)/*.c)
FS_OBJ_LIB = $(FS_LIB:$(LIB_DIR)/%.c=$(LIB_OBJ_DIR)/%.o)
FS_OBJ_SRC = $(FS_SRC:$(SRC_DIR)/%.c=$(SRC_OBJ_DIR)/%.$(OBJ_EXT))
FS_DEP_LIB = $(FS_LIB:$(LIB_DIR)/%.c=$(LIB_DEP_DIR)/%.d)
FS_DEP_SRC = $(FS_SRC:$(SRC_DIR)/%.c=$(SRC_DEP_DIR)/%.d)

ifneq (, $(shell which $(LIBTOOL) 2>/dev/null ))
LIB_EXT  = la
OBJ_EXT  = lo
override LD := $(LT_LD)
INSTALL := $(LT_INSTALL)
else
LIB_EXT  = a
OBJ_EXT  = o
endif

CFLAGS  += $(TARGETCFLAGS)
LDFLAGS += $(TARGETLDFLAGS)

LIB_DIR     = lib
LIB_DEP_DIR = dep_lib
LIB_OBJ_DIR = obj_lib
SRC_DIR     = src
SRC_DEP_DIR = dep_src
SRC_OBJ_DIR = obj_src

.PHONY: all
all: library tools

.PHONY: install
install: all
	$(INSTALL) -d $(LIBDIR) $(BINDIR) $(INCLUDEDIR)
	$(INSTALL) bin/libsha1detectcoll.$(LIB_EXT) $(LIBDIR)/libsha1detectcoll.$(LIB_EXT)
	$(INSTALL) lib/sha1.h $(INCLUDEDIR)/sha1.h
	$(INSTALL) bin/sha1dcsum $(BINDIR)/sha1dcsum
	$(INSTALL) bin/sha1dcsum_partialcoll $(BINDIR)/sha1dcsum_partialcoll

.PHONY: uninstall
uninstall:
	-$(RM) $(BINDIR)/sha1dcsum
	-$(RM) $(BINDIR)/sha1dcsum_partialcoll
	-$(RM) $(INCLUDEDIR)/sha1.h
	-$(RM) $(LIBDIR)/libsha1detectcoll.$(LIB_EXT)

.PHONY: clean
clean:
	rm -rf obj_src dep_src obj_lib dep_lib bin

.PHONY: test
test: tools
	test e98a60b463a6868a6ce351ab0166c0af0c8c4721 != `bin/sha1dcsum test/sha1_reducedsha_coll.bin | cut -d' ' -f1` || (echo "\nError: Compiled for incorrect endianness" && false)
	test a56374e1cf4c3746499bc7c0acb39498ad2ee185 = `bin/sha1dcsum test/sha1_reducedsha_coll.bin | cut -d' ' -f1`
	test 16e96b70000dd1e7c85b8368ee197754400e58ec = `bin/sha1dcsum test/shattered-1.pdf | cut -d' ' -f1`
	test e1761773e6a35916d99f891b77663e6405313587 = `bin/sha1dcsum test/shattered-2.pdf | cut -d' ' -f1`
	test dd39885a2a5d8f59030b451e00cb45da9f9d3828 = `bin/sha1dcsum_partialcoll test/sha1_reducedsha_coll.bin | cut -d' ' -f1` 
	test d3a1d09969c3b57113fd17b23e01dd3de74a99bb = `bin/sha1dcsum_partialcoll test/shattered-1.pdf | cut -d' ' -f1`
	test 92246b0b718f4c704d37bb025717cbc66babf102 = `bin/sha1dcsum_partialcoll test/shattered-2.pdf | cut -d' ' -f1`
	bin/sha1dcsum test/*
	bin/sha1dcsum_partialcoll test/*
	
.PHONY: check
check: test

.PHONY: tools
tools: sha1dcsum sha1dcsum_partialcoll

.PHONY: sha1dcsum
sha1dcsum: bin/sha1dcsum

.PHONY: sha1dcsum_partialcoll
sha1dcsum_partialcoll: bin/sha1dcsum_partialcoll

.PHONY: library
library: bin/libsha1detectcoll.$(LIB_EXT)

bin/sha1dcsum: $(FS_OBJ_SRC) bin/libsha1detectcoll.$(LIB_EXT)
	$(LD) $(LDFLAGS) $(FS_OBJ_SRC) -Lbin -lsha1detectcoll -o $@

bin/sha1dcsum_partialcoll: $(FS_OBJ_SRC) bin/libsha1detectcoll.$(LIB_EXT)
	$(LD) $(LDFLAGS) $(FS_OBJ_SRC) -Lbin -lsha1detectcoll -o $@

COMPILE.c = $(CC) $(CFLAGS) $(CPPFLAGS) $(RELOC)     -o  $@ $(filter %.c,$^)
DEPS.c    = $(CC) $(CFLAGS) $(CPPFLAGS) -M           -MF $@ $(filter %.c,$^)
COMPILE.o = $(CC) $(CFLAGS)             $(RELOC.LTO) -o  $@ $(filter %.o,$^)

$(SRC_DEP_DIR)/%.d:  $(SRC_DIR)/%.c
	$(ENSUREDIR)
	$(DEPS.c)
$(SRC_OBJ_DIR)/%.lo: $(SRC_DIR)/%.c $(SRC_DEP_DIR)/%.d $(H_DEP)
	$(ENSUREDIR)
	$(let CC,$(LT_CC),$(COMPILE.c))
$(SRC_OBJ_DIR)/%.o:  $(SRC_DIR)/%.c $(SRC_DEP_DIR)/%.d $(H_DEP)
	$(ENSUREDIR)
	$(COMPILE.c)

$(LIB_DEP_DIR)/%.d: $(LIB_DIR)/%.c
	$(ENSUREDIR)
	$(DEPS.c)
$(LIB_OBJ_DIR)/%.o: $(LIB_DIR)/%.c $(LIB_DEP_DIR)/%.d $(H_DEP)
	$(ENSUREDIR)
	$(COMPILE.c)
# see note on libtool above: it does not understand a .lo -> .lo step, so we
# stick to a single (non-incremental) .c -> .lo step
bin/libsha1detectcoll.lo: $(FS_LIB) $(H_DEP)
	$(ENSUREDIR)
	$(let CC,$(LT_CC),$(let RELOC,$(RELOC.LTO),$(COMPILE.c)))
bin/libsha1detectcoll.o: $(FS_OBJ_LIB)
	$(ENSUREDIR)
	$(COMPILE.o)

bin/libsha1detectcoll.a: bin/libsha1detectcoll.o
	$(AR) $(ARFLAGS) $@ $^
bin/libsha1detectcoll.la: bin/libsha1detectcoll.lo
	$(LT_LD) $(LDFLAGS) $^ -rpath $(LIBDIR) -version-info $(LIBCOMPAT) -o $@

-include $(FS_DEP_SRC) $(FS_DEP_LIB)
