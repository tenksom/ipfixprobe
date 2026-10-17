#!/bin/bash
# Builds tshark with parquet support and flowpipeline with the ipfixstdin
# segment into <prefix>. Both features are not upstream yet; once they are,
# install the released versions instead and delete this script.
#
#   ./build-tools.sh /opt/quic-flow-compare-tools
#
# The CI caches <prefix> keyed on the hash of this file, so changing a ref
# below triggers a rebuild.
set -euo pipefail

WIRESHARK_REPO=https://github.com/jmuecke/wireshark-parquet.git
WIRESHARK_REF=865a53da4aa559ab96daaa36d7a4403ea2e9bb33
FLOWPIPELINE_REPO=https://codeberg.org/tenksom/flowpipeline.git
FLOWPIPELINE_REF=db6d4f8859de5f4947c29bbb33482d715bb7da20

PREFIX="$(realpath -m "${1:?usage: $0 <prefix>}")"
SRC=$(mktemp -d)
trap 'rm -rf "$SRC"' EXIT

fetch() {  # <repo> <commit> <dir>
  git init -q "$3"
  git -C "$3" fetch -q --depth 1 "$1" "$2"
  git -C "$3" checkout -q FETCH_HEAD
}

fetch "$WIRESHARK_REPO" "$WIRESHARK_REF" "$SRC/wireshark"
# Only tshark (and its parquet-helper); every other program is switched off.
NO_PROGRAMS=()
for p in wireshark stratoshark sharkd dumpcap rawshark text2pcap mergecap reordercap \
         editcap capinfos captype randpkt dftest mmdbresolve androiddump sshdump sshdig \
         ciscodump dpauxmon randpktdump wifidump udpdump falcodump; do
  NO_PROGRAMS+=("-DBUILD_$p=OFF")
done
cmake -S "$SRC/wireshark" -B "$SRC/wireshark/build" \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  "${NO_PROGRAMS[@]}" -DENABLE_PLUGINS=OFF -DENABLE_PARQUET=ON
cmake --build "$SRC/wireshark/build" -j "$(nproc)"
cmake --install "$SRC/wireshark/build"

fetch "$FLOWPIPELINE_REPO" "$FLOWPIPELINE_REF" "$SRC/flowpipeline"
(cd "$SRC/flowpipeline" && go build -o "$PREFIX/bin/flowpipeline" .)

"$PREFIX/bin/tshark" -T '?' 2>&1 | grep -q parquet
echo "tools installed to $PREFIX/bin"
