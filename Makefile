# Top-level convenience targets.
#
#   make / make all  build the PoC scenarios (baseline + defended), the cost
#                    benchmark and the AoN kernel module
#   make clean       run `make clean` in every subproject
#
# The hardened syscall library (aonlibc/) has no build of its own: the scenario
# compiles its sources directly (see user_aonlibc_cat/Makefile).

SUBDIRS := user_aonlibc_cat user_aonlibc_signal user_aonlibc_bench kernel

.PHONY: all clean
all:
	$(MAKE) -C user_aonlibc_cat cat cat_defended
	$(MAKE) -C user_aonlibc_signal sig sig_defended
	$(MAKE) -C user_aonlibc_bench all
	$(MAKE) -C kernel

clean:
	@for d in $(SUBDIRS); do $(MAKE) -C $$d clean || exit 1; done
