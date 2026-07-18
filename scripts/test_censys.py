"""Test Censys client standalone.

Usage:
  python scripts/test_censys.py --ip 8.8.8.8
  python scripts/test_censys.py --cidr 203.113.128.0/28
  python scripts/test_censys.py --asn 149069   # will report "not available"
"""
import argparse
import asyncio
import sys

from ati_evn.external.censys_client import search_asn, search_cidr, search_ip


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip")
    ap.add_argument("--asn")
    ap.add_argument("--cidr")
    args = ap.parse_args()

    if args.ip:
        data = await search_ip(args.ip)
    elif args.asn:
        data = await search_asn(args.asn)
    elif args.cidr:
        data = await search_cidr(args.cidr)
    else:
        ap.error("Need --ip, --asn, or --cidr")
        return 2

    print(f"Exposures ({len(data)}):")
    for i, e in enumerate(data[:20], 1):
        print(
            f"[{i}] {e['ip']}:{e['port']} "
            f"{e['service_name']} "
            f"{e['product'] or ''}/{e['version'] or ''} "
            f"ASN {e['asn']} {e['country']}"
        )
        if e.get("capabilities"):
            print(f"    caps: {e['capabilities']}")
    if len(data) > 20:
        print(f"... {len(data) - 20} nữa")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
