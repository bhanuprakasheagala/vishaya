# Talk Script

A ~15-minute demo built around the sample bundles in `samples/`. Time budget in `[brackets]` per segment.

## Before the talk starts

**Prep checklist:**

- [ ] Sample bundles produced: `sudo ./demo/produce-samples.sh`
- [ ] Terminal font size ≥ 18pt (readable from the back of the room)
- [ ] Terminal width set so `vishaya network` output doesn't wrap (usually 120+ cols)
- [ ] Prompt shortened to just `$ ` if possible — long paths eat screen space
- [ ] Working directory: project root
- [ ] `PATH` includes `./build/` (or use `./build/vishaya` explicitly)
- [ ] Have `zstd` and `jq` installed for the "look inside" segment
- [ ] Backup slide with pre-recorded output in case demo fails

**Optional but helpful:**

- Split terminal (tmux / iTerm2 split panes) so you can show two commands side by side
- One tab with the source open in an editor for the "brief architecture" segment
- Reveal.js / your slides in fullscreen browser, easy to alt-tab back

**If the live demo fails,** fall back to `cat` of pre-captured output. Never spend more than 20 seconds debugging on stage.

---

## Segment 1: The problem [90 sec]

**Say:** "Linux ransomware doubled in 2024-2025. ESXi ransomware demands averaged $5 million. But if you're a DFIR analyst who gets a suspicious Linux binary, your options are: aging tools like Cuckoo that were built for Windows, heavyweight Xen-based frameworks like DRAKVUF, or reading raw syscall traces from strace. There's no `.pcap`-equivalent for Linux host activity — no portable file format an analyst can capture, hand to a colleague, inspect a year later."

**Show slide with:**
- Cuckoo/CAPE/DRAKVUF (aging or heavy)
- Tracee/Falco (production monitoring, not case forensics)
- No portable format between them

**Segue:** "That's the gap Vishaya fills."

---

## Segment 2: What Vishaya is [60 sec]

**Say:** "One command. You run it against a suspicious binary. It captures everything that binary and its children do at the Linux kernel level — via eBPF, so essentially zero overhead — and packages it into a single portable `.vishaya` file. That file goes in an incident ticket, gets emailed, gets diffed with other captures. Analyst tooling reads it on any machine, no Vishaya running there needed."

**Show:** the one-slide diagram (system overview flowchart from `architecture.md` §2, rendered as an image).

**Segue:** "Let me show you."

---

## Segment 3: First capture — the trivial case [90 sec]

**Type:**
```bash
ls demo/samples/
```

**Expected output:** the seven `.vishaya` files with sizes.

**Say:** "These are all pre-captured. Each is a single file — a few kilobytes."

**Type:**
```bash
./build/vishaya tree demo/samples/01-ls-etc.vishaya
```

**Expected output:** header line showing target `/bin/ls`, then a single `└── ls (pid=… exec=/bin/ls exit=0)` node.

**Say:** "Simplest possible capture — just `ls /etc`. Single process, no children, exited cleanly."

**Type:**
```bash
./build/vishaya files demo/samples/01-ls-etc.vishaya | head -10
```

**Expected output:** table showing `openat` on `/etc`, plus follow-up opens for individual files. Return values shown.

**Say:** "Every file `ls` touched. Read as data. In a real investigation this is where you'd see suspicious paths — `~/.ssh/authorized_keys`, `/etc/sudoers`, whatever."

---

## Segment 4: Process tree — the killer view [2 min]

**Type:**
```bash
./build/vishaya tree demo/samples/02-shell-pipeline.vishaya
```

**Expected output:** something like:
```
target: pid=12345 exec=/bin/sh cmdline="sh -c echo ..."

└── sh (pid=12345 exec=/bin/sh exit=0)
    ├── echo (pid=12346 exec=/bin/echo exit=0)
    ├── ls (pid=12347 exec=/bin/ls exit=0)
    ├── head (pid=12348 exec=/usr/bin/head exit=0)
    ├── whoami (pid=12349 exec=/usr/bin/whoami exit=0)
    └── id (pid=12350 exec=/usr/bin/id exit=0)
```

**Say:** "This is the view that matters most in an investigation. If a suspicious binary spawned `bash -c 'curl badsite.com | bash'`, you see it here in seconds. Nobody wants to reconstruct process lineage by hand from strace logs."

**Type:**
```bash
./build/vishaya timeline demo/samples/02-shell-pipeline.vishaya | head -20
```

**Say:** "Same events, chronological instead of tree. Different question, same data."

---

## Segment 5: The marquee demo — DNS + HTTP [3 min]

**Say:** "Now the interesting one. Curl fetching an HTTP URL."

**Type:**
```bash
./build/vishaya network demo/samples/04-http-curl.vishaya
```

**Expected output:** a table with rows like:
```
PID    COMM       KIND           REMOTE                  DETAIL
12345  curl       socket
12345  curl       connect        1.1.1.1:53
12345  curl       sendto         1.1.1.1:53              32B
12345  curl       dns-query      1.1.1.1:53              A example.com
12345  curl       recvfrom       1.1.1.1:53              48B
12345  curl       dns-answer     1.1.1.1:53              A example.com -> 93.184.216.34
12345  curl       connect        93.184.216.34:80
12345  curl       write          93.184.216.34:80        76B
12345  curl       http-request   93.184.216.34:80        GET example.com/
12345  curl       read           93.184.216.34:80        1256B
12345  curl       http-response  93.184.216.34:80        200 OK
12345  curl       close          93.184.216.34:80
```

**Say:** "Look at this. You see the DNS resolution — curl asks Cloudflare's 1.1.1.1 for the A record of `example.com`, gets back `93.184.216.34`. Then TCP connect to port 80. Then the HTTP request: GET, Host: example.com. Then the 200 OK response. Every layer, correlated, decoded, in one view."

**Pause for effect.**

**Say:** "This is decoded from raw packet bytes captured in the kernel. The DNS wire format, the HTTP method line and Host header — parsed in userspace. Vishaya doesn't just record `sendto` and `recvfrom` events; it looks at the payload and emits `dns-query` and `http-request` events with the actual semantic content."

---

## Segment 6: HTTPS is honest about what it can't do [60 sec]

**Type:**
```bash
./build/vishaya network demo/samples/05-https-curl.vishaya
```

**Expected output:** same shape as HTTP but no `http-request` / `http-response` lines — just socket-level events with `443` as the port.

**Say:** "HTTPS. You see the DNS query, the TCP connection to 443, the byte counts, but no HTTP decoding — the payload is encrypted. Vishaya is honest about this: v0.5 will add TLS uprobes into OpenSSL to get plaintext there, but v0.1 shows what it can and doesn't fake what it can't."

---

## Segment 7: One file per case [90 sec]

**Say:** "Everything I just showed you is inside one file. Let me prove it."

**Type:**
```bash
zstd -d < demo/samples/04-http-curl.vishaya | tar -tv
```

**Expected output:**
```
-rw-r--r-- 0/0  1234 <date> manifest.json
-rw-r--r-- 0/0  5678 <date> events.ndjson
-rw-r--r-- 0/0   345 <date> process_tree.json
drwxr-xr-x 0/0     0 <date> artifacts/
```

**Say:** "Manifest, events, process tree, artifacts dir. That's it. Standard tar with zstd compression — every Linux machine can unpack it."

**Type:**
```bash
zstd -d < demo/samples/04-http-curl.vishaya | tar -xO manifest.json | jq
```

**Expected output:** the full manifest JSON with schema_version, tool, capture timing, host info, target sha256, isolation info, coverage, event counts, integrity hashes.

**Say:** "Manifest carries the schema version, the target binary's SHA-256, the exact commit that produced this bundle, and SHA-256 integrity hashes of the events and process tree. If someone hands you a `.vishaya` file and claims 'this is what X did last Tuesday,' you can verify."

---

## Segment 8: The architecture in 90 seconds [90 sec]

**Show slide** with the flow.md capture sequence diagram (or the architecture.md system overview).

**Say briefly:**
- "Kernel-side is eBPF. We attach probes to process, file, and network syscall tracepoints. When your target does anything interesting, our probes fire, filter by cgroup — we only see this target and its children — and push structured events into a kernel ring buffer."
- "Userspace polls that ring buffer, decodes into typed events, enriches process events with /proc data, serializes to JSON, and writes to a work-ahead log."
- "For network events, we grab the first 128 bytes of the payload. Userspace looks at that payload and if it's DNS or HTTP, emits synthetic decoded events."
- "When the target exits, we reconstruct the process tree from the events, hash everything, pack into tar.zst, atomically rename. Done."

**Don't get into more detail unless asked in Q&A.**

---

## Segment 9: What's next + how to help [60 sec]

**Say:**
- **v0.1** (what you just saw) — target-scoped capture, portable bundle, CLI-first
- **v0.5** — HTTPS plaintext via TLS uprobes, dropped-file artifact capture, bundle diffing
- **v1.0** — schema freeze, MITRE ATT&CK mapping, YARA integration
- **Future** — MCP server so you can chat with a capture in Claude; sandbox orchestrator adapters

**Say:** "Everything is open source. Zero dependencies on any commercial anything. Contributions welcome — repo link on the final slide."

---

## Segment 10: Q&A backstop answers

Anticipated questions and short answers:

**Q: How does this compare to Falco / Tetragon / Tracee?**
A: "Different job. Those are runtime security tools — designed to filter aggressively and alert on suspicious patterns in production. Vishaya is a forensic capture tool — designed to preserve everything one target does, in a portable file, for later analysis. Vishaya doesn't monitor a fleet; it observes one binary at a time. And it produces a file, not a stream."

**Q: Why not just use Sysdig / Stratoshark?**
A: "Stratoshark is great — Wireshark for host activity, reads Sysdig's `.scap` format. But it doesn't detonate binaries; you have to have a capture already. And `.scap` is events-only — no bundling of dropped artifacts, no target metadata, no case-oriented workflow. Vishaya complements Stratoshark: v2 might embed a `.scap` inside a `.vishaya` for interop."

**Q: What about HTTPS?**
A: "Deferred to v0.5. Requires uprobes into TLS libraries — OpenSSL, BoringSSL, GnuTLS. Version-fragile per-library work. Doing it right takes weeks; doing it half-right creates confusion. v0.5 does OpenSSL and BoringSSL first."

**Q: Does the target detect it's being observed?**
A: "It can if it looks. Namespaces + cgroups aren't invisible — process can read `/proc/self/cgroup` and see it's in a Vishaya cgroup. Same limitation as Docker containers. For adversarial malware that actively probes for sandbox artifacts, you need something like DRAKVUF's Xen-based approach. Vishaya's target audience is 'unknown but not necessarily anti-sandbox' binaries — most malware in the wild."

**Q: What if the target runs for hours?**
A: "Ring buffer is 16 MiB, drains continuously. WAL grows as you'd expect for the event volume. Bundle gets larger. There's no artificial time or size limit. Kill the target with Ctrl-C in the vishaya terminal to trigger clean finalization at any point."

**Q: Windows support?**
A: "Never. Permanent non-goal. Linux forensics has been under-served; Windows has plenty of tools. I'd rather do Linux well than both badly."

**Q: Where do I get it?**
A: [your repo URL]

---

## After the talk

- **Sample bundles are your souvenir.** People will ask to look at them. Have `demo/samples/` on a USB or a shareable link.
- **Repo star nag** — mention it once, don't beg.
- **Follow-up capture** — offer to run a capture on someone's suggested target during Q&A downtime. Great for engagement.
