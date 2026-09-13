##
## Copyright 2017 Marc Stevens <marc@marc-stevens.nl>, Dan Shumow (danshu@microsoft.com)
## Distributed under the MIT Software License.
## See accompanying file LICENSE.txt or copy at
## https://opensource.org/licenses/MIT
##

LIBNAME               = sha1detectcoll
ABI_VERSION           = 2
ABI_VERSION_SUPPORTED = 2
REVISION              = 0

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
	  -Dunsequenced=gnu::__unsequenced__ $(CFLAGS) $(CPPFLAGS) \$ 
	  -c
endef
# -Dunsequenced=gnu::__unsequenced__ works around GCC #127361

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
	$(INSTALL) bin/lib$(LIBNAME).so                            $(LIBDIR)/
	$(INSTALL) bin/lib$(LIBNAME).so.$(ABI_VERSION).$(REVISION) $(LIBDIR)/
	$(INSTALL) $(ABIS:%=bin/lib$(LIBNAME).so.%)                $(LIBDIR)/
	$(INSTALL) bin/sha1dcsum             $(BINDIR)/
	$(INSTALL) bin/sha1dcsum_partialcoll $(BINDIR)/
	$(INSTALL) -m0644 include/* $(INCLUDEDIR)/

.PHONY: uninstall
uninstall:
	-$(RM) $(LIBDIR)/lib$(LIBNAME).so
	-$(RM) $(LIBDIR)/lib$(LIBNAME).so.$(ABI_VERSION).$(REVISION)
	-$(RM) $(ABIS:%=$(LIBDIR)/lib$(LIBNAME).so.%)
	-$(RM) $(BINDIR)/sha1dcsum
	-$(RM) $(BINDIR)/sha1dcsum_partialcoll
	-$(RM) $(patsubst include/%,$(INCLUDEDIR)/%,$(wildcard include/*))
	-$(RMDIR) $(INCLUDEDIR)

.PHONY: test
test: tools
	test e98a60b463a6868a6ce351ab0166c0af0c8c4721 != `./run sha1dcsum test/sha1_reducedsha_coll.bin | cut -d' ' -f1` || (echo "\nError: Compiled for incorrect endianness" && false)
	test a56374e1cf4c3746499bc7c0acb39498ad2ee185  = `./run sha1dcsum test/sha1_reducedsha_coll.bin | cut -d' ' -f1`
	test 16e96b70000dd1e7c85b8368ee197754400e58ec  = `./run sha1dcsum test/shattered-1.pdf | cut -d' ' -f1`
	test e1761773e6a35916d99f891b77663e6405313587  = `./run sha1dcsum test/shattered-2.pdf | cut -d' ' -f1`
	test dd39885a2a5d8f59030b451e00cb45da9f9d3828  = `./run sha1dcsum_partialcoll test/sha1_reducedsha_coll.bin | cut -d' ' -f1` 
	test d3a1d09969c3b57113fd17b23e01dd3de74a99bb  = `./run sha1dcsum_partialcoll test/shattered-1.pdf | cut -d' ' -f1`
	test 92246b0b718f4c704d37bb025717cbc66babf102  = `./run sha1dcsum_partialcoll test/shattered-2.pdf | cut -d' ' -f1`
	./run sha1dcsum             test/*
	./run sha1dcsum_partialcoll test/*
	
.PHONY: check
check: test

.PHONY: tools
tools: bin/sha1dcsum bin/sha1dcsum_static bin/sha1dcsum_partialcoll

.PHONY: library
library: bin/lib$(LIBNAME).a bin/lib$(LIBNAME).so.$(ABI_VERSION).$(REVISION)

bin/sha1dcsum: $(OBJS_EXE) bin/lib$(LIBNAME).so.$(ABI_VERSION).$(REVISION)
	$(DRIVE) -Wl,-rpath,$(LIBDIR) $(LDFLAGS) $(OBJS_EXE) -Lbin -lsha1detectcoll \
	  -o $@
bin/sha1dcsum_static: $(OBJS_EXE) bin/lib$(LIBNAME).a
	$(DRIVE) $(LDFLAGS) $(OBJS_EXE) \
	  -Lbin -Wl,--push-state,-Bstatic -lsha1detectcoll -Wl,--pop-state \
	  -o $@
bin/sha1dcsum_partialcoll: bin/sha1dcsum
	$(LN) -f $< $@

obj/%.o: %.c
	@mkdir -p $(@D) deps/$(*D)
	$(COMPILE.c) $< -MMD -MT $@ -MF deps/$*.make -o $@
%.h: ;

bin/lib$(LIBNAME).o: $(OBJS_LIB)
	@mkdir -p $(@D)
	$(DRIVE) -r -o $@ $^
bin/lib$(LIBNAME).a: bin/lib$(LIBNAME).o
	$(AR) $(ARFLAGS) $@ $^
bin/lib$(LIBNAME).so.$(ABI_VERSION).$(REVISION): bin/lib$(LIBNAME).o
	$(DRIVE) -shared $^ -o $@ -Wl,-soname,lib$(LIBNAME).so.$(ABI_VERSION)

ABIS     != seq $(ABI_VERSION_SUPPORTED) $(ABI_VERSION)
OLD_ABIS != seq $(ABI_VERSION_SUPPORTED) $$(($(ABI_VERSION)-1))
library: $(ABIS:%=bin/lib$(LIBNAME).so.%) bin/lib$(LIBNAME).so
bin/lib$(LIBNAME).so:
	@mkdir -p $(@D)
	ln -sf lib$(LIBNAME).so.$(ABI_VERSION) $@
bin/lib$(LIBNAME).so.$(ABI_VERSION):
	@mkdir -p $(@D)
	ln -sf lib$(LIBNAME).so.$(ABI_VERSION).$(REVISION) $@
$(OLD_ABIS:%=bin/lib$(LIBNAME).so.%):
	@mkdir -p $(@D)
	ln -sf lib$(LIBNAME).so.$(ABI_VERSION) $@

$(OBJS_LIB) bin/lib$(LIBNAME).o bin/lib$(LIBNAME).so: WAY = -fPIC
bin/lib$(LIBNAME).o: WAY += -ffat-lto-objects
obj/lib/sha1.o: WAY += --param large-function-growth=900

-include $(SRCS_LIB.c:%.c=deps/%.make) $(SRCS_EXE.c:%.c=deps/%.make)
