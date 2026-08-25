"""
DNS exfiltration detector — stage 1.
Reads DNS queries from a PCAP, extracts per-query features,
aggregates them per registered domain, and prints the stats.
The tunnel domain should float to the top on unique_subs and entropy.
"""

import math
import sys
from collections import defaultdict

from scapy.all import rdpcap, DNSQR
import tldextract


def entropy(s):
    """Shannon entropy of a string, in bits per character."""
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def analyze(pcap_path):
    stats = defaultdict(lambda: {
        "unique_subs": set(),
        "count": 0,
        "txt": 0,
        "ent_sum": 0.0,
        "max_len": 0,
    })

    packets = rdpcap(pcap_path)
    for pkt in packets:
        if not pkt.haslayer(DNSQR):
            continue
        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        qtype = pkt[DNSQR].qtype

        ext = tldextract.extract(qname)
        reg = ext.top_domain_under_public_suffix or qname
        sub = ext.subdomain

        s = stats[reg]
        s["count"] += 1
        s["unique_subs"].add(sub)
        s["ent_sum"] += entropy(sub)
        s["max_len"] = max(s["max_len"], len(qname))
        if qtype == 16:  # TXT record
            s["txt"] += 1

    # Sort by number of unique subdomains — the strongest tunneling tell.
    ranked = sorted(stats.items(),
                    key=lambda kv: len(kv[1]["unique_subs"]),
                    reverse=True)

    print(f"{'registered_domain':30} {'queries':>8} {'uniq_subs':>10} "
          f"{'txt%':>6} {'mean_ent':>9} {'max_len':>8}")
    print("-" * 75)
    for reg, s in ranked:
        n = s["count"]
        print(f"{reg:30} {n:8} {len(s['unique_subs']):10} "
              f"{s['txt'] / n:6.2f} {s['ent_sum'] / n:9.2f} {s['max_len']:8}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: python {sys.argv[0]} <capture.pcap>")
        sys.exit(1)
    analyze(sys.argv[1])

