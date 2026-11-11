#!/usr/bin/env bash
#
# mayhem/build.sh — build the iPXE fuzz targets (AFL, ASan+UBSan) and the project's own test suite.
#
# iPXE is not a library: its Linux platform links a harness *inside* the iPXE build as a "binary" made of
# the selected object files (see mayhem/harness/fuzz_input.h). Each target is built from a throw-away copy
# of src/ with gcc (iPXE does not build with clang) through afl-gcc, with $SANITIZER_FLAGS on every iPXE
# object, so the fuzzed code itself is instrumented.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS MAYHEM_JOBS

SRC="${SRC:-/mayhem}"
cd "$SRC"
WORK="$SRC/mayhem/work"
OUT="$SRC/mayhem/out"
B=bin-x86_64-linux
TARGETS="fuzz_png fuzz_pnm fuzz_x509 fuzz_cms fuzz_deflate fuzz_uri fuzz_dhcp fuzz_fdt fuzz_netrx fuzz_tls fuzz_http fuzz_dns fuzz_dhcprx"

rm -rf "$WORK" "$OUT"
mkdir -p "$WORK/fuzz" "$WORK/tests" "$OUT"

# --- 1) the project's own test suite, normal flags (test.sh only runs it) ---------------------------------
cp -a src "$WORK/tests/src"
rm -rf "$WORK"/tests/src/bin-*
make -C "$WORK/tests/src" -j"$MAYHEM_JOBS" "$B/tests.linux" CC=gcc NO_WERROR=1 >"$WORK/tests-build.log" 2>&1 \
  || { tail -50 "$WORK/tests-build.log" >&2; exit 1; }
cp "$WORK/tests/src/$B/tests.linux" "$WORK/tests.linux"

# --- 2) the fuzz targets ----------------------------------------------------------------------------------
cp -a src "$WORK/fuzz/src"
rm -rf "$WORK"/fuzz/src/bin-*
cd "$WORK/fuzz/src"
cp "$SRC"/mayhem/harness/*.c "$SRC"/mayhem/harness/*.h "$SRC/mayhem/asan_valgrind.h" tests/

# afl-as's forkserver payload calls read()/close(), which iPXE's own definitions of those symbols capture.
cat >"$WORK/afl-as-wrap.sh" <<'WRAP'
#!/bin/sh
for last; do :; done
sed -i -E 's/call[[:space:]]+(read|close)@PLT/call __\1@PLT/' "$last"
exec as "$@"
WRAP
chmod +x "$WORK/afl-as-wrap.sh"
export AFL_AS="$WORK/afl-as-wrap.sh"

# UBSan checks relaxed because iPXE is built on idioms that trip them on every input (see PR description):
# object-size/nonnull-attribute/null/alignment (casts of packed wire buffers, memcpy(NULL,_,0)),
# shift-base/pointer-overflow (hash/crypto code and list/ring arithmetic), vla-bound (tls_send_record() sizes
# an IV array by the cipher suite's IV length, which is 0 for the null suite every handshake starts with).
RELAX="-fno-sanitize=object-size,nonnull-attribute,null,shift-base,pointer-overflow,alignment,vla-bound"
make -j"$MAYHEM_JOBS" $(for t in $TARGETS; do echo "$B/$t.linux.tmp"; done) CC=afl-gcc NO_WERROR=1 \
  EXTRA_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -Wno-error -include $PWD/tests/asan_valgrind.h $RELAX" \
  >"$WORK/fuzz-build.log" 2>&1 || { tail -50 "$WORK/fuzz-build.log" >&2; exit 1; }

# The Linux platform needs its host-side shim (main + the _ipxe__ aliases) as a second link stage.
afl-gcc $SANITIZER_FLAGS $DEBUG_FLAGS -Os -idirafter include -DSYMBOL_PREFIX=_ipxe__ \
  -c interface/linux/linux_api.c -o "$B/linux_api.o"
gcc $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
# gcc's libasan_preinit.o carries a DWARF-5 CU; hand the link a debug-stripped copy (found first via -B) so
# every CU in the binaries is DWARF < 4.
LINKB=""
PREINIT="$(gcc -print-file-name=libasan_preinit.o)"
if [ -f "$PREINIT" ]; then
  mkdir -p "$WORK/preinit"
  objcopy --strip-debug "$PREINIT" "$WORK/preinit/libasan_preinit.o"
  LINKB="-B$WORK/preinit/"
fi
nm --defined-only "$B/linux_api.o" | awk '{print $3}' | sort -u >"$WORK/defined.txt"
for t in $TARGETS; do
  nm "$B/$t.linux.tmp" | awk '$1=="U"{print $2}' | sort -u >"$WORK/undef.txt"
  comm -23 "$WORK/undef.txt" "$WORK/defined.txt" \
    | awk '{s=$1; sub(/^_ipxe__/,"",s); print $1" "s}' >"$WORK/redef.txt"
  objcopy --redefine-syms="$WORK/redef.txt" "$B/$t.linux.tmp" "$B/$t.re.o"
  gcc $LINKB $SANITIZER_FLAGS -Wl,--gc-sections -o "$OUT/$t" "$B/$t.re.o" "$B/linux_api.o" "$B/lsan_off.o"
done
