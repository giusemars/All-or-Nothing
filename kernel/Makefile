# Makefile for the All-or-Nothing (AoN) kernel module.
#
#   make          build the module (aon_mod.ko)
#   make load     insmod the module            (uses sudo)
#   make unload   rmmod the module             (uses sudo)
#   make reload   unload + load
#   make clean    remove build outputs

CC   := gcc
KVER := $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
PWD  := $(CURDIR)

.PHONY: all module load unload reload clean

all: module

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

load: module
	sudo insmod aon_mod.ko
	@echo "loaded:"; lsmod | grep aon_mod

unload:
	-sudo rmmod aon_mod

reload: unload load

# Note: kbuild's `clean` deletes compile_commands.json, so save/restore it.
clean:
	@cp -f compile_commands.json .compile_commands.json.bak 2>/dev/null || true
	-$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true
	@if [ -f .compile_commands.json.bak ]; then \
		mv -f .compile_commands.json.bak compile_commands.json; \
	fi
