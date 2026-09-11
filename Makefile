##
## Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow (danshu@microsoft.com)
## Distributed under the MIT Software License.
## See accompanying file LICENSE.txt or copy at
## https://opensource.org/licenses/MIT
##

LIBCOMPAT = 1:0:0

PREFIX     ?= /usr/local
BINDIR      = $(PREFIX)/bin
LIBDIR      = $(PREFIX)/lib
INCLUDEDIR  = $(PREFIX)/include/sha1dc

DRIVER  ?= gcc
AR      ?= gcc-ar
LN      ?= ln
INSTALL ?= install

define DRIVE
$(DRIVER) -O2 -flto $(WAY) $(DRIVERFLAGS) \$ 
	  
endef
define COMPILE.c
$(DRIVE) -std=gnu2y -Iinclude -Wall -Wextra -Wno-parentheses \$ 
	  $(CFLAGS) $(CPPFLAGS) \$ 
	  -c
endef

LIB_DIR = lib
EXE_DIR = src

SRCS_LIB.c = $(wildcard $(LIB_DIR)/*.c)
SRCS_EXE.c = $(wildcard $(EXE_DIR)/*.c)
OBJS_LIB   = $(SRCS_LIB.c:%.c=obj/%.o)
OBJS_EXE   = $(SRCS_EXE.c:%.c=obj/%.o)

.PHONY: all
all: library tools

.PHONY: clean
clean:
	rm -rf bin obj deps

.PHONY: install
install: all
	$(INSTALL) -d $(LIBDIR) $(BINDIR) $(INCLUDEDIR)
	$(INSTALL) bin/libsha1detectcoll.so $(LIBDIR)/
	$(INSTALL) lib/sha1.h $(INCLUDEDIR)/
	$(INSTALL) bin/sha1dcsum $(BINDIR)/
	$(INSTALL) bin/sha1dcsum_partialcoll $(BINDIR)/

.PHONY: uninstall
uninstall:
	-$(RM) $(BINDIR)/sha1dcsum
	-$(RM) $(BINDIR)/sha1dcsum_partialcoll
	-$(RM) $(INCLUDEDIR)/sha1.h
	-$(RM) $(LIBDIR)/libsha1detectcoll.so

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
library: bin/libsha1detectcoll.a bin/libsha1detectcoll.so

bin/sha1dcsum: $(OBJS_EXE) bin/libsha1detectcoll.so
	$(DRIVE) $(LDFLAGS) $(OBJS_EXE) -Lbin -lsha1detectcoll -o $@
bin/sha1dcsum_partialcoll: bin/sha1dcsum
	$(LN) -f $< $@

obj/%.o: %.c
	@mkdir -p $(@D) deps/$(*D)
	$(COMPILE.c) $< -MMD -MT $@ -MF deps/$*.make -o $@
%.h: ;

bin/libsha1detectcoll.o: $(OBJS_LIB)
	@mkdir -p $(@D)
	$(DRIVE) -r -o $@ $^
bin/lib%.a: bin/lib%.o
	$(AR) $(ARFLAGS) $@ $^
bin/lib%.so: bin/lib%.o
	$(DRIVE) -shared $^ -o $@ -Wl,-soname,libsha1detectcoll.so.1

$(OBJS_LIB) bin/libsha1detectcoll.o bin/libsha1detectcoll.so: WAY = -fPIC
bin/libsha1detectcoll.o: WAY += -ffat-lto-objects

-include $(SRCS_LIB.c:%.c=deps/%.make) $(SRCS_EXE.c:%.c=deps/%.make)
