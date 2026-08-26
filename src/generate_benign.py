"""
Benign DNS traffic generator — hard cases for tuning the detector.

Crafts realistic BENIGN DNS that superficially resembles tunneling, to
stress-test the scorer's corroboration logic:

  - CDN-style hosts: long names, but low entropy and structured, few unique
  - hash-named hosts: high entropy, but FEW unique subs and no TXT skew
  - cloud/telemetry: moderate length, ordinary characters
  - plain domains: short, boring

The detector SHOULD keep all of these under threshold, because none trips
enough signals at once. If any crosses the line, that's your tuning signal.
"""

import argparse
import random
import string

from scapy.all import IP, UDP, DNS, DNSQR, wrpcap, RandShort


def rand_hex(n):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def rand_alnum(n):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def benign_names():
    """Return a realistic mix of benign FQDNs, some deliberately tricky."""
    names = []

    # 1. CDN-style: long, structured, LOW entropy, repeated base host.
    #    Many queries but only a handful of distinct subdomains.
    for _ in range(30):
        pop = random.choice(["iad", "lhr", "fra", "sjc", "nrt"])
        names.append(f"edge-{pop}.cdn-provider.net")
    for _ in range(20):
        names.append("static-assets.cdn-provider.net")

    # 2. Hash-named hosts: HIGH entropy, but each queried once or twice and
    #    NO TXT — high entropy alone must not be enough to flag.
    for _ in range(12):
        names.append(f"{rand_hex(16)}.images.contentcache.com")

    # 3. Cloud/telemetry: moderate length, ordinary words, low entropy.
    for _ in range(25):
        svc = random.choice(["telemetry", "metrics", "logs", "update", "sync"])
        names.append(f"{svc}.cloud-service.io")

    # 4. Plain everyday domains: short and boring.
    for host in ["www.example.org", "mail.example.org", "api.weather.com",
                 "cdn.jsdelivr.net", "fonts.googleapis.com"]:
        for _ in range(random.randint(2, 6)):
            names.append(host)

    random.shuffle(names)
    return names


def build_pcap(names, path):
    pkts = []
    for qname in names:
        # benign traffic is overwhelmingly A/AAAA — almost never TXT
        qtype = "AAAA" if random.random() < 0.2 else "A"
        pkt = (IP(dst="203.0.113.53", src="198.51.100.10") /
               UDP(sport=RandShort(), dport=53) /
               DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
        pkts.append(pkt)
    wrpcap(path, pkts)


def main():
    ap = argparse.ArgumentParser(description="Benign DNS generator (tuning data).")
    ap.add_argument("--pcap-out", default="data/pcaps/benign_hard.pcap")
    args = ap.parse_args()

    names = benign_names()
    build_pcap(names, args.pcap_out)
    print(f"[+] wrote {len(names)} benign queries "
          f"({len(set(names))} distinct) to {args.pcap_out}")


if __name__ == "__main__":
    main()


