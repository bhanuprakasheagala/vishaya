# Sample `.vishaya` bundles

Ready-to-inspect captures of benign programs, **committed to the repo so you can try Vishaya
in ~2 minutes with no build and no root.** Inspection needs neither — only `capture` needs
root/eBPF.

```bash
# no build, no root — just read a real bundle:
vishaya tree     samples/02-shell-pipeline.vishaya
vishaya timeline samples/04-http-curl.vishaya
vishaya network  samples/04-http-curl.vishaya
vishaya verify   samples/04-http-curl.vishaya      # integrity + signature verdict
```

(If you haven't built the CLI, you can still read a bundle with standard tools —
`zstd -dc samples/02-shell-pipeline.vishaya | tar -xO events.ndjson | jq` — which is the whole
"open, tool-independent format" point.)

## What's here

| File | Program captured | Shows |
|---|---|---|
| `01-ls-etc.vishaya` | `ls -la /etc` | simplest: process + file events |
| `02-shell-pipeline.vishaya` | `sh -c 'echo … \| ls \| head …'` | a process tree with children |
| `03-dns-nslookup.vishaya` | `nslookup example.com` | a decoded DNS query/answer |
| `04-http-curl.vishaya` | `curl http://example.com` | DNS + plaintext HTTP request/response (the marquee) |
| `05-https-curl.vishaya` | `curl https://example.com` | HTTPS — connection metadata only, **no** plaintext (TLS is opaque in v0.1) |
| `06-file-lifecycle.vishaya` | create/read/delete a temp file | file events (openat/unlinkat) |
| `07-file-rename.vishaya` | write/rename/delete | `renameat2` |

Each bundle is ~1–10 KB.

## Honest notes about these fixtures

- They were captured on a real Linux host, so the manifest embeds that host's kernel/arch/
  hostname and real timestamps. That's expected for a capture — it's demo-host data, nothing
  sensitive.
- They're **signed with the generating host's self-generated key**, so `vishaya verify` will
  show a valid signature and a key fingerprint (a nice live demo of the verify path) — but that
  key is not a trust anchor. See the [spec §6 trust model](../docs/bundle-spec-v0.1.md).

## Regenerating / refreshing

Fixtures are produced by the demo script pointed at this committed directory (Linux + root +
a built CLI):

```bash
sudo DEMO_DIR=samples ./demo/produce-samples.sh
git add samples/*.vishaya          # commit the refreshed fixtures
```

Keep the set small and benign — these are a first impression, not a test corpus. The
larger/ephemeral working set lives in `demo/samples/` (gitignored).
