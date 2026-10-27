#!/bin/sh
# verify_aon.sh - build-time check on a linked defended PoC binary.
#
# Reads the AoN region [__start_aon_text,__stop_aon_text) -- the bounds ld
# generates around the `aon_text` output section that gathers the linked AoN
# blocks (see aonlibc/aon_syscalls.S) -- and the ingress gate addresses of the
# __aon_* blocks from the ELF symbol table, then runs verify_ud2 to prove the
# AoN region contains no stray `ud2` (0f 0b) besides those ingress gates.
# (Argument marshaling stubs and nolibc's errno translation live OUTSIDE the
# AoN region and carry no gate.)
#
# The ingress gate set is discovered from the symbol table (every __aon_*
# symbol), so this works unchanged for any program: only the wrappers of its
# required system calls survive --gc-sections -z start-stop-gc, and only their
# ingress gates are expected.
#
#   verify_aon.sh <binary>
set -eu

bin="$1"
verify="$(dirname "$0")/verify_ud2"

sym() {
  addr="$(nm "$bin" | awk -v s="$1" '$3==s{print "0x"$1}')"
  [ -n "$addr" ] || { echo "verify_aon: symbol $1 not found in $bin" >&2; exit 1; }
  echo "$addr"
}

lo="$(sym __start_aon_text)"
hi="$(sym __stop_aon_text)"
# Every __aon_* symbol is the ingress gate of a linked AoN block.
gates="$(nm "$bin" | awk '$3 ~ /^__aon_/ { print "0x"$1 }')"
[ -n "$gates" ] || { echo "verify_aon: no __aon_* gate symbols found in $bin" >&2; exit 1; }

echo "### verify: no stray ud2 in the AoN region [__start_aon_text,__stop_aon_text) of $bin ###"
echo "  region=[$lo,$hi) ingress gates=$gates"
# shellcheck disable=SC2086
exec "$verify" --region "$lo" "$hi" "$bin" $gates
