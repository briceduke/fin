#!/usr/bin/env bash
# Build tshark 4.6.9 from the official source tarball into $TSHARK_PREFIX.
set -euo pipefail

: "${TSHARK_PREFIX:?}"
: "${TSHARK_SHA256:?}"
: "${TSHARK_URL:?}"

src_root="${RUNNER_TEMP:-/tmp}/wireshark-src"
mkdir -p "$src_root" "$TSHARK_PREFIX"
tarball="$src_root/wireshark-4.6.9.tar.xz"

if [[ -n "${TSHARK_TARBALL:-}" ]]; then
  cp "$TSHARK_TARBALL" "$tarball"
else
  curl -fsSL "$TSHARK_URL" -o "$tarball"
fi

echo "${TSHARK_SHA256}  ${tarball}" | sha256sum -c -
tar -xJf "$tarball" -C "$src_root"

src="$src_root/wireshark-4.6.9"
build="$src_root/build"

cmake -S "$src" -B "$build" -G Ninja \
  -DCMAKE_C_COMPILER=gcc \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$TSHARK_PREFIX" \
  -DCMAKE_INSTALL_RPATH='$ORIGIN/../lib' \
  -DCMAKE_BUILD_WITH_INSTALL_RPATH=ON \
  -DBUILD_wireshark=OFF \
  -DBUILD_tshark=ON \
  -DBUILD_rawshark=OFF \
  -DBUILD_dumpcap=OFF \
  -DBUILD_text2pcap=OFF \
  -DBUILD_mergecap=OFF \
  -DBUILD_reordercap=OFF \
  -DBUILD_editcap=OFF \
  -DBUILD_capinfos=OFF \
  -DBUILD_captype=OFF \
  -DBUILD_randpkt=OFF \
  -DBUILD_dftest=OFF \
  -DBUILD_dcerpcidl2wrs=OFF \
  -DBUILD_androiddump=OFF \
  -DBUILD_sshdump=OFF \
  -DBUILD_ciscodump=OFF \
  -DBUILD_dpauxmon=OFF \
  -DBUILD_randpktdump=OFF \
  -DBUILD_wifidump=OFF \
  -DBUILD_sdjournal=OFF \
  -DBUILD_udpdump=OFF \
  -DBUILD_sharkd=OFF \
  -DBUILD_mmdbresolve=OFF \
  -DENABLE_WERROR=OFF \
  -DENABLE_PLUGINS=OFF \
  -DENABLE_LUA=OFF \
  -DENABLE_GNUTLS=OFF \
  -DENABLE_SMI=OFF \
  -DENABLE_KERBEROS=OFF \
  -DENABLE_BROTLI=OFF \
  -DENABLE_SNAPPY=OFF \
  -DENABLE_NGHTTP2=OFF \
  -DENABLE_NGHTTP3=OFF \
  -DENABLE_MINIZIP=OFF \
  -DENABLE_MINIZIPNG=OFF \
  -DENABLE_XXHASH=OFF \
  -DENABLE_ZLIBNG=OFF \
  -DENABLE_SINSP=OFF \
  -DENABLE_SBC=OFF \
  -DENABLE_SPANDSP=OFF \
  -DENABLE_BCG729=OFF \
  -DENABLE_AMRNB=OFF \
  -DENABLE_ILBC=OFF \
  -DENABLE_OPUS=OFF \
  -DENABLE_CAP=OFF \
  -DENABLE_NETLINK=OFF \
  -DENABLE_PCAP=ON \
  -DENABLE_ZLIB=ON \
  -DENABLE_LZ4=ON \
  -DENABLE_ZSTD=ON

cmake --build "$build"
cmake --install "$build"
test -x "$TSHARK_PREFIX/bin/tshark"
