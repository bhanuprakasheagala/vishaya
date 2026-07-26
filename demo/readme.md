# Demo directory

Sample captures and conference-talk material. Not part of the product; delete freely.

## Contents

- **`produce-samples.sh`** — automation script. Runs vishaya against 7 benign targets and produces `.vishaya` bundles. Idempotent.
- **`talk-script.md`** — timed walkthrough for a ~15-minute conference talk with all commands and expected output.
- **`demo/samples/`** — ephemeral working output of the script; **gitignored** (host-specific, and a big/noisy set).
- **`/samples/`** (repo root, **committed**) — a small curated subset kept in the repo as the *try-without-root* fixtures. See [`/samples/README.md`](../samples/README.md). Refresh with `sudo DEMO_DIR=samples ./demo/produce-samples.sh`.

## Quick start

From the project root, on a Linux host with `vishaya` and the BPF object built:

```bash
./scripts/linux.sh all              # build if you haven't already
sudo ./demo/produce-samples.sh      # produce all samples
```

Output:
- `demo/samples/01-ls-etc.vishaya` — simplest capture, process + file
- `demo/samples/02-shell-pipeline.vishaya` — process tree with children
- `demo/samples/03-dns-nslookup.vishaya` — pure DNS query
- `demo/samples/04-http-curl.vishaya` — DNS + plaintext HTTP (the marquee demo)
- `demo/samples/05-https-curl.vishaya` — DNS + HTTPS (connection metadata only)
- `demo/samples/06-file-lifecycle.vishaya` — file create/read/delete
- `demo/samples/07-file-rename.vishaya` — file write + rename + unlink

Each bundle is typically 1-10 KB.

## Customizing

Override output dir and binary path via env vars:

```bash
sudo DEMO_DIR=/tmp/vishaya-demo \
     VISHAYA=/opt/vishaya/bin/vishaya \
     ./demo/produce-samples.sh
```

Add your own samples by editing `produce-samples.sh` — each capture is one `capture <slug> <binary> [args...]` call.

## Using the samples in the talk

See `talk-script.md` for a full segment-by-segment walkthrough of a ~15-minute conference demo built around these bundles.
