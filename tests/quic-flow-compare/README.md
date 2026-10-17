# QUIC flow compare

Checks the flow records exported by ipfixprobe's QUIC plugin against tshark as
the reference. For every pcap, both tools export the flows, and
`compare_flows.py` compares them field by field (timestamps, packet/byte
counts, SNI, connection IDs, version, token length, TLS extensions, Retry,
multiplexing).

```
pcap ─► ipfixprobe ─(IPFIX/UDP on lo)─► tcpdump ─► flowpipeline ─► parquet ┐
pcap ─► tshark ─────────────────────────────────────────────────► parquet ┴► compare_flows.py ─► results/*.json
```

ipfixprobe can only export IPFIX over the network, so `pipeline.sh` captures
the export on loopback with tcpdump and hands it to flowpipeline (segment
`ipfixstdin`), which turns it into parquet.

## Test data

- `pcaps/`: regression cases. Each one triggered a bug that was fixed in the
  QUIC plugin; the commit message of the fix names the file. These must pass.
- [QUIC interop runner](https://interop.seemann.io) traces, downloaded with
  `get_new_data.sh`. Informational only, see [Known limitations](#known-limitations).

To add a regression case, put the (ideally small, see `editcap`) pcap into
`pcaps/` and mention its name in the commit message of the fix.

## Running locally

Requirements (see `install-deps.sh` for the exact packages on Oracle Linux 10):

- ipfixprobe with pcap input (`-DENABLE_INPUT_PCAP=ON`)
- tcpdump, run via sudo (or `sudo setcap cap_net_raw=eip $(which tcpdump)` and `SUDO=`)
- tshark with `-T parquet` and flowpipeline with the `ipfixstdin` segment:
  neither is upstream yet, `build-tools.sh <prefix>` builds both from the forks
- Python 3 with `pip install -r requirements.txt`

```sh
cd tests/quic-flow-compare
make check-tools
make -j$(nproc) check                     # regression pcaps, fails on any failure
make summary                              # pass rates of the last run

# ipfixprobe from a build tree instead of $PATH:
make -j$(nproc) check IPFIXPROBE=../../build/src/core/ipfixprobe PLUGIN_DIR=../../build/src/plugins

# interop runner data (TESTCASES optional, a full run is >20 GB):
TESTCASES="handshake retry" ./get_new_data.sh latest interop
make -j$(nproc) compare PCAP_DIR=interop OUT_DIR=interop_processed RESULT_DIR=interop_results
python3 summarize.py interop interop_results
```

All Makefile variables (`PCAP_DIR`, `IPFIXPROBE`, `PLUGIN_DIR`, `TSHARK`,
`FLOWPIPELINE`, `SUDO`, ...) can be overridden on the command line or via the
environment. `PCAP_DIR` must not contain spaces or `:`. `make clean` removes
all generated files.

Each result JSON has one entry per check with `"result": "passed"` or
`"failed"`; failed checks include the mismatching flows.

## CI

`.github/workflows/quic-flow-compare.yml` runs on pull requests that touch the
QUIC plugin or this directory, and manually via *Run workflow*:

1. Builds tshark and flowpipeline with `build-tools.sh` and caches them,
   keyed on the hash of that script. Changing a ref there triggers a rebuild.
2. Builds ipfixprobe from the PR.
3. `make check` on `pcaps/`. **This step fails the job.**
4. Downloads the latest interop runner run (handshake-related test cases only)
   and compares it. Never fails the job.
5. Writes pass rates to the job summary and uploads the results as artifact.

## Known limitations

- **Interop runner availability:** the runner only keeps the logs of the last
  completed run until the next run starts, and `latest` is a dead link while a
  run is in progress. The interop step is then skipped.
  `WAIT_TIMEOUT=<seconds> ./get_new_data.sh` waits for the run to complete.
- **Forked tools:** `build-tools.sh` pins commits of the tshark and
  flowpipeline forks. Once parquet output and `ipfixstdin` are upstream,
  install the released versions in `install-deps.sh` and delete `build-tools.sh`.
- Regression pcaps must keep passing; interop results vary between runs, as
  the implementations under test change.
