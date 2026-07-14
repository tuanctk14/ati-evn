"""One-time setup: download ATT&CK-BERT (or MiniLM fallback), embed all 697
techniques, cache to disk. Rerunning is idempotent (cache hit → no-op).

Usage:
    python scripts/setup_embeddings.py                              # default
    python scripts/setup_embeddings.py --model basel/ATTACK-BERT    # explicit
    python scripts/setup_embeddings.py --model sentence-transformers/all-MiniLM-L6-v2
    python scripts/setup_embeddings.py --force                      # rebuild cache
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
    )

    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="basel/ATTACK-BERT",
                    help="Sentence-transformers model to use.")
    ap.add_argument("--device", default="cpu", help="cpu or cuda")
    ap.add_argument("--force", action="store_true",
                    help="Delete cache and rebuild")
    args = ap.parse_args()

    cache_path = Path("./src/ati_evn/data/technique_embeddings.npz")
    if args.force and cache_path.exists():
        cache_path.unlink()
        print(f"Deleted existing cache: {cache_path}")

    from ati_evn.enrichment.attack_bert import load_mapper_or_none

    print(f"\n=== ATT&CK embedding setup ===")
    print(f"Model : {args.model}")
    print(f"Device: {args.device}")
    print(f"Cache : {cache_path}")
    print()

    start = time.monotonic()
    mapper = load_mapper_or_none(args.model, cache_path, args.device)
    elapsed = time.monotonic() - start

    if mapper is None:
        # Try MiniLM fallback
        print("\nPrimary model failed — trying MiniLM fallback...")
        mapper = load_mapper_or_none(
            "sentence-transformers/all-MiniLM-L6-v2", cache_path, args.device,
        )
        if mapper is None:
            print("ERROR: no model could be loaded. Check torch install and network.")
            return 2

    print(f"\n[OK] Mapper loaded in {elapsed:.1f}s.")
    print(f"     Techniques embedded: {len(mapper.technique_ids)}")
    print(f"     Cache size: {cache_path.stat().st_size / 1e6:.2f} MB")

    # Sanity ping
    print("\nSanity map: 'Log4j remote code execution via JNDI lookup'")
    preds = mapper.map(
        "A vulnerability in Apache Log4j 2.14.1 allows remote code execution "
        "via JNDI LDAP lookup on user-controlled input.",
        top_k=3, min_similarity=0.30,
    )
    for p in preds:
        print(f"  {p.technique_id:12s} {p.name[:50]:50s} conf={p.confidence}")
    if not preds:
        print("  (no matches above threshold — model may be poorly aligned; "
              "still functional for enrichment though)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
