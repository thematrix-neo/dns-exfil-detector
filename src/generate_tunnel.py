"""
Synthetic DNS-tunnel traffic generator — lab test data for the detector.

Reads an input file, base32-encodes it, splits the encoded stream into
subdomain-length labels, and emits tunnel-shaped DNS queries under a
domain you control. Purpose: produce LABELED malicious-shaped traffic to
validate the defensive detector against a known baseline.

Runs entirely in your own lab. Point --domain at a domain/sink you own.
By default it does NOT send anything over the network — it writes the
crafted query names to a text file and (optionally) builds a PCAP you can
feed straight into detector.py. Use --send only against your own sink.
"""

import argparse
import base64
import os
import random


def encode_payload(data: bytes) -> str:
    """Base32-encode bytes into DNS-safe lowercase label characters."""
    return base64.b32encode(data).decode("ascii").lower().rstrip("=")


def chunk(s: str, size: int):
    for i in range(0, len(s), size):
        yield s[i:i + size]


def build_query_names(payload: str, domain: str, label_len: int):
    """
    Turn the encoded payload into a list of tunnel-shaped FQDNs:
    <seq>.<data-label>.<domain>
    Each carries a slice of the payload, like a real tunnel's upstream.
    """
    names = []
    for seq, data_label in enumerate(chunk(payload, label_len)):
        # sequence label keeps every subdomain unique, like real tunnels
        qname = f"{seq:04x}.{data_label}.{domain}"
        names.append(qname)
    return names


def write_names(names, path):
    with open(path, "w") as f:
        f.write("\n".join(names) + "\n")


def build_pcap(names, path, domain):
    """Craft a PCAP of A/TXT DNS queries for the generated names."""
    from scapy.all import IP, UDP, DNS, DNSQR, wrpcap, RandShort

    pkts = []
    for qname in names:
        # mix in some TXT queries — a common tunneling tell
        qtype = "TXT" if random.random() < 0.3 else "A"
        pkt = (IP(dst="203.0.113.53", src="198.51.100.10") /
               UDP(sport=RandShort(), dport=53) /
               DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype)))
        pkts.append(pkt)
    wrpcap(path, pkts)


def main():
    ap = argparse.ArgumentParser(description="Synthetic DNS tunnel generator (lab use).")
    ap.add_argument("--infile", required=True, help="file to encode into the tunnel")
    ap.add_argument("--domain", required=True, help="domain you control, e.g. tunnel.example.com")
    ap.add_argument("--label-len", type=int, default=40, help="chars per data label (max 63)")
    ap.add_argument("--names-out", default="data/pcaps/tunnel_names.txt")
    ap.add_argument("--pcap-out", default="data/pcaps/tunnel.pcap")
    ap.add_argument("--no-pcap", action="store_true", help="skip PCAP, just write names")
    args = ap.parse_args()

    if args.label_len > 63:
        raise SystemExit("DNS labels max out at 63 chars; pick --label-len <= 63")

    with open(args.infile, "rb") as f:
        data = f.read()

    payload = encode_payload(data)
    names = build_query_names(payload, args.domain, args.label_len)

    write_names(names, args.names_out)
    print(f"[+] {len(data)} bytes -> {len(names)} tunnel queries")
    print(f"[+] wrote query names to {args.names_out}")

    if not args.no_pcap:
        build_pcap(names, args.pcap_out, args.domain)
        print(f"[+] wrote PCAP to {args.pcap_out}")
        print(f"[+] now run: python src/detector.py {args.pcap_out}")


if __name__ == "__main__":
    main()


