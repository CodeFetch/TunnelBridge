# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
DESTDIR ?=
SYSCONFDIR ?= /etc
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
MANDIR ?= $(PREFIX)/share/man
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
SYSTEMDUNITDIR ?= $(shell $(PKG_CONFIG) --variable=systemdsystemunitdir systemd 2>/dev/null || echo "$(PREFIX)/lib/systemd/system")
RUNSTATEDIR ?= /var/run
WITH_BASHCOMPLETION ?=
WITH_TBQUICK ?=
WITH_SYSTEMDUNITS ?=

ifeq ($(WITH_BASHCOMPLETION),)
ifneq ($(strip $(wildcard $(BASHCOMPDIR))),)
WITH_BASHCOMPLETION := yes
endif
endif
ifeq ($(WITH_TBQUICK),)
ifneq ($(strip $(wildcard $(BINDIR)/bash)),)
WITH_TBQUICK := yes
endif
ifneq ($(strip $(wildcard $(DESTDIR)/bin/bash)),)
WITH_TBQUICK := yes
endif
endif
ifeq ($(WITH_SYSTEMDUNITS),)
ifneq ($(strip $(wildcard $(SYSTEMDUNITDIR))),)
WITH_SYSTEMDUNITS := yes
endif
endif

PLATFORM ?= $(shell uname -s | tr '[:upper:]' '[:lower:]')

CFLAGS ?= -O3
CFLAGS += -std=gnu99 -D_GNU_SOURCE
CFLAGS += -Wall -Wextra
CFLAGS += -MMD -MP
CFLAGS += -DRUNSTATEDIR="\"$(RUNSTATEDIR)\""
ifeq ($(DEBUG_TOOLS),y)
CFLAGS += -g
endif
ifeq ($(PLATFORM),linux)
LIBMNL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libmnl 2>/dev/null)
LIBMNL_LDLIBS := $(shell $(PKG_CONFIG) --libs libmnl 2>/dev/null || echo -lmnl)
CFLAGS += $(LIBMNL_CFLAGS)
LDLIBS += $(LIBMNL_LDLIBS)
endif
ifeq ($(PLATFORM),haiku)
LDLIBS += -lnetwork -lbsd
endif
ifeq ($(PLATFORM),windows)
CC := x86_64-w64-mingw32-gcc
CFLAGS += -Iwincompat/include -include wincompat/compat.h
LDLIBS += -lws2_32
tb: wincompat/libc.o wincompat/init.o
endif

ifneq ($(V),1)
BUILT_IN_LINK.o := $(LINK.o)
LINK.o = @echo "  LD      $$(pwd)/$@";
LINK.o += $(BUILT_IN_LINK.o)
BUILT_IN_COMPILE.c := $(COMPILE.c)
COMPILE.c = @echo "  CC      $$(pwd)/$@";
COMPILE.c += $(BUILT_IN_COMPILE.c)
endif

tb: $(patsubst %.c,%.o,$(wildcard *.c))

ifneq ($(V),1)
clean:
	@echo "  CLEAN   $$(pwd)/{tb,*.o,*.d}"
	@$(RM) tb *.o *.d
else
clean:
	$(RM) tb *.o *.d
endif

install: tb
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 tb "$(DESTDIR)$(BINDIR)/tb"
	@install -v -d "$(DESTDIR)$(MANDIR)/man8" && install -v -m 0644 man/tb.8 "$(DESTDIR)$(MANDIR)/man8/tb.8"
	@[ "$(WITH_BASHCOMPLETION)" = "yes" ] || exit 0; \
	install -v -d "$(DESTDIR)$(BASHCOMPDIR)" && install -v -m 0644 completion/tb.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/tb"
	@[ "$(WITH_TBQUICK)" = "yes" ] || exit 0; \
	install -v -m 0755 tb-quick/$(PLATFORM).bash "$(DESTDIR)$(BINDIR)/tb-quick" && install -v -m 0700 -d "$(DESTDIR)$(SYSCONFDIR)/tunnelbridge"
	@[ "$(WITH_TBQUICK)" = "yes" ] || exit 0; \
	install -v -m 0644 man/tb-quick.8 "$(DESTDIR)$(MANDIR)/man8/tb-quick.8"
	@[ "$(WITH_TBQUICK)" = "yes" -a "$(WITH_BASHCOMPLETION)" = "yes" ] || exit 0; \
	install -v -m 0644 completion/tb-quick.bash-completion "$(DESTDIR)$(BASHCOMPDIR)/tb-quick"
	@[ "$(WITH_TBQUICK)" = "yes" -a "$(WITH_SYSTEMDUNITS)" = "yes" ] || exit 0; \
	install -v -d "$(DESTDIR)$(SYSTEMDUNITDIR)" && install -v -m 0644 systemd/tb-quick@.service "$(DESTDIR)$(SYSTEMDUNITDIR)/tb-quick@.service"

help:
	@cat INSTALL

.PHONY: clean install help

-include *.d
