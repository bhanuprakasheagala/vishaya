## Quick start

From the project root, on a Linux host with `vishaya` and the BPF object built:

```bash
./scripts/linux.sh all              # build if you haven't already
sudo ./demo/produce-samples.sh      # produce all samples
```

Output (written to `samples/` at the repo root — the committed try-without-root fixtures):
- `samples/01-ls-etc.vishaya` — simplest capture, process + file
- `samples/02-shell-pipeline.vishaya` — process tree with children
- `samples/03-dns-nslookup.vishaya` — pure DNS query
- `samples/04-http-curl.vishaya` — DNS + plaintext HTTP (the marquee demo)
- `samples/05-https-curl.vishaya` — DNS + HTTPS (connection metadata only)
- `samples/06-file-lifecycle.vishaya` — file create/read/delete
- `samples/07-file-rename.vishaya` — file write + rename + unlink

Each bundle is typically 1-10 KB.

## Customizing

Override output dir and binary path via env vars:

```bash
sudo DEMO_DIR=/tmp/vishaya-demo \
     VISHAYA=/opt/vishaya/bin/vishaya \
     ./demo/produce-samples.sh
```

Add your own samples by editing `produce-samples.sh` — each capture is one `capture <slug> <binary> [args...]` call.
