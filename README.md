# dns-exfil-detector

# DNS Exfiltration Detector

Detects likely DNS tunneling / data exfiltration from DNS query logs by
extracting per-domain features, scoring them, and flagging domains whose
traffic has the shape of a tunnel rather than normal lookups.

## Why DNS tunneling is detectable

To move data out over DNS, a tunnel has to encode bytes into query names
and send them to a nameserver the attacker controls. That forces a
signature it can't hide: many **unique, long, high-entropy subdomains**
under a **single registered domain**, often with **TXT/NULL record abuse**
and **high query volume**. Normal DNS looks nothing like this — a handful
of short, repeated, low-entropy names per domain. This detector measures
that difference.

## How it works

A four-stage pipeline:

1. **Ingest** — read DNS queries from a PCAP capture.
2. **Feature extraction** — per query, then aggregated per *registered
   domain* (using the Public Suffix List, so `a1b2.evil.com` and
   `c3d4.evil.com` collapse to `evil.com` — tunneling only shows its shape
   once you aggregate at this level).
3. **Scoring** — normalize each feature to a 0–1 signal, combine them with
   weights into a suspicion score, apply a volume gate, and emit a verdict.
4. **Output** — a ranked list of domains with the evidence behind each score.

### Features

Per registered domain, over the capture:

- **Unique-subdomain ratio** — fraction of queries that are distinct
  subdomains. Near 1.0 for tunnels (every query carries different data),
  near 0 for normal traffic. Strongest single signal.
- **Mean subdomain entropy** — encoded data is near-random, so entropy is
  high; real hostnames are word-like and lower.
- **TXT ratio** — tunnels often abuse TXT/NULL records; benign traffic is
  overwhelmingly A/AAAA.
- **Max query-name length** — tunnels stuff labels toward the 63-char cap
  to move more data per query.

### Scoring and the corroboration principle

Signals are combined with weights (unique-ratio carries the most). The key
idea is **corroboration**: a benign domain may trip *one* signal (a CDN
sprays subdomains; a hash-named host looks high-entropy) but rarely trips
several at once. Requiring multiple indicators is what keeps false
positives down.

### Design decision: the volume gate

During tuning against benign traffic, hash-named CDN hosts
(`<hash>.images.contentcache.com`) triggered a **false positive**: high
entropy + all-unique subdomains pushed the score to 0.78. Diagnosis: two
strong signals fired, but the host had **no TXT abuse and only 12 queries**
— it wasn't moving data.

Fix (chosen from three options): a **minimum-volume gate**. A domain must
clear both the score threshold *and* a minimum query count to be flagged,
because real exfiltration moves data and that takes many queries. This
suppressed the false positive while still catching the tunnel.

**Known blind spot:** a *low-and-slow* tunnel that trickles data stays
under the volume gate and evades detection. The next step would be a
time-windowed rate check (queries per hour) rather than a raw count.
This trade-off — simplicity and low false positives now, at the cost of a
named evasion path — is deliberate and documented rather than hidden.

## Test data

The detector is validated against **labeled synthetic traffic** generated
locally (no live network):

- `generate_tunnel.py` — encodes a file into base32 subdomain labels and
  writes a tunnel-shaped PCAP. Used to confirm the detector catches a tunnel.
- `generate_benign.py` — crafts realistic benign DNS *including hard cases*
  (CDN-style long names, hash-named high-entropy hosts) to stress-test the
  scorer against the exact patterns that fool naive detectors.

All test traffic targets documentation/test IP ranges and is generated for
the sole purpose of validating this defensive detector.

## Example output

Running the scorer on a mixed capture (benign traffic + a synthetic tunnel):

```
verdict score domain evidence

SUSPICIOUS 0.88 example.com uniq=73 q=76 ent=4.25 txt=0.32 len=64
ok 0.79 contentcache.com uniq=12 q=12 ent=3.87 txt=0.0 len=40
ok 0.32 cloud-service.io uniq=5 q=25 ent=2.36 txt=0.0 len=26
ok 0.29 googleapis.com uniq=1 q=6 ent=2.32 txt=0.0 len=20
ok 0.13 cloudflare.com uniq=1 q=4 ent=0.0 txt=0.0 len=14
ok 0.09 fedoraproject.org uniq=1 q=8 ent=0.0 txt=0.0 len=17
```

The tunnel (`example.com`) is flagged. Note `contentcache.com` scores high
(0.79) on entropy and unique-subdomain ratio, but the **volume gate**
correctly keeps it unflagged: with only 12 queries it isn't moving data.
This is the false-positive case the gate was designed to catch.

## Usage

```bash
# set up
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# generate labeled test data
python src/generate_tunnel.py --infile data/sample.txt --domain tunnel.example.com
python src/generate_benign.py

# merge into a realistic mix and score it
mergecap -w data/pcaps/full_mix.pcap \
    data/pcaps/benign.pcap data/pcaps/benign_hard.pcap data/pcaps/tunnel.pcap
cd src && python score.py ../data/pcaps/full_mix.pcap && cd ..
```

## Roadmap

- Live capture / Zeek `dns.log` ingest (currently PCAP only)
- Time-windowed rate analysis to close the low-and-slow blind spot
- Validation against a real tunneling tool (iodine) in an isolated lab

## Disclaimer

A **defensive** monitoring tool. All malicious-shaped traffic is synthetic,
generated locally, and used only to validate detection.

