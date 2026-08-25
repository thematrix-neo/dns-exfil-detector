"""
DNS exfiltration detector — stage 5: scoring.

Reuses the per-domain features from detector.py, normalizes each into a
0-1 signal, combines them into a weighted suspicion score, and prints a
ranked verdict list with the evidence that triggered each flag.

The combination is the point: a benign domain may trip ONE signal (a CDN
sprays subdomains; a hash-named host looks high-entropy) but rarely trips
several at once. Requiring corroboration is what keeps false positives down.
"""

import sys
from collections import defaultdict

from scapy.all import rdpcap, DNSQR
import tldextract

from detector import entropy  # reuse the entropy function you already wrote


# --- feature extraction (per registered domain) ---------------------------

def extract_features(pcap_path):
    stats = defaultdict(lambda: {
        "unique_subs": set(),
        "count": 0,
        "txt": 0,
        "ent_sum": 0.0,
        "max_len": 0,
    })

    for pkt in rdpcap(pcap_path):
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
        if qtype == 16:  # TXT
            s["txt"] += 1

    return stats


# --- scoring --------------------------------------------------------------

# Weights sum to 1.0. Unique-sub count carries the most because it's the
# strongest single tunneling tell; entropy and TXT corroborate.
WEIGHTS = {
    "unique_ratio": 0.40,   # fraction of queries that are unique subdomains
    "entropy":      0.30,   # mean subdomain entropy, normalized
    "txt_ratio":    0.15,   # share of TXT queries
    "length":       0.15,   # longest qname, normalized toward the 63/253 caps
}

FLAG_THRESHOLD = 0.55       # tune this against benign traffic later
MIN_QUERIES_TO_FLAG = 30    # volume gate:real exfil moves data,so it takes
			    # many queries. Below this, don't flag regardless
			    # of score. KNOWN BLIND SPOT:a low-and-slow tunnel
			    # that trickles data stays under this evades -
			    # a time-windowed rate check would be the next step.

def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))


def score_domain(s):
    n = s["count"]
    if n == 0:
        return 0.0, {}

    unique_ratio = len(s["unique_subs"]) / n           # ~1.0 for tunnels
    mean_ent = s["ent_sum"] / n
    entropy_norm = clamp(mean_ent / 4.0)                # base32 ~ 4+ bits/char
    txt_ratio = s["txt"] / n
    length_norm = clamp(s["max_len"] / 63.0)            # labels cap at 63

    signals = {
        "unique_ratio": unique_ratio,
        "entropy": entropy_norm,
        "txt_ratio": txt_ratio,
        "length": length_norm,
    }
    score = sum(WEIGHTS[k] * signals[k] for k in WEIGHTS)
    return score, {
        "uniq_subs": len(s["unique_subs"]),
        "queries": n,
        "mean_ent": round(mean_ent, 2),
        "txt%": round(txt_ratio, 2),
        "max_len": s["max_len"],
    }


def main():
    if len(sys.argv) != 2:
        print(f"usage: python {sys.argv[0]} <capture.pcap>")
        sys.exit(1)

    stats = extract_features(sys.argv[1])
    results = []
    for reg, s in stats.items():
        score, evidence = score_domain(s)
        results.append((score, reg, evidence))

    results.sort(reverse=True)

    print(f"{'verdict':12} {'score':>6}  {'domain':28} evidence")
    print("-" * 90)
    for score, reg, ev in results:
        # Volume gate (Option 1): a domain must clear both the score threshold
        # AND a minimum query count to be flagged. This suppresses benign
        # high-entropy hosts (e.g. hash-named CDN content) that trip the score
        # but never carry real data volume.
        flagged = score >= FLAG_THRESHOLD and ev["queries"] >= MIN_QUERIES_TO_FLAG
        verdict = "SUSPICIOUS" if flagged else "ok"
        ev_str = (f"uniq={ev['uniq_subs']} q={ev['queries']} "
                  f"ent={ev['mean_ent']} txt={ev['txt%']} len={ev['max_len']}")
        print(f"{verdict:12} {score:6.2f}  {reg:28} {ev_str}")


if __name__ == "__main__":
    main()
