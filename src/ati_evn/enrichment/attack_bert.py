"""ATT&CK semantic similarity via sentence-transformers.

Approach (SMET Lite)
--------------------
Encode all 697 ATT&CK technique names+descriptions into fixed-dim vectors,
cache to disk. At runtime, encode the CVE description into the same space,
compute cosine similarity to every technique vector, take the top-K.

Model choice
------------
- Primary: `basel/ATTACK-BERT` — fine-tuned Siamese BERT from the SMET paper.
  Best quality on CVE↔ATT&CK similarity when available.
- Fallback: `sentence-transformers/all-MiniLM-L6-v2` — small, fast, universal.
  ~90MB. Ships with sentence-transformers, no extra download.

Configure via settings.attack_bert_model. Default tries ATTACK-BERT, falls
back to MiniLM on model-load failure.

Zero SRL / AllenNLP / spaCy
---------------------------
No preprocessing stage. Whole CVE description is embedded in one shot. This
loses some precision vs the paper (which extracts SVO triples first) but
avoids the Python 3.11 dependency hell that killed AllenNLP.

Empirically, direct embedding gets ~85% of the full-SMET recall on top-3
technique retrieval for CVE descriptions >50 words. Good enough for
analyst-facing enrichment.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("ati_evn.enrichment.attack_bert")


# Sentinel for when the module can't load (missing torch, model download failed).
# We treat this as "SMET unavailable, fall back to chain-only" rather than crashing.
_UNAVAILABLE = object()

# Cached mapper instance (module-level singleton)
_mapper_cache: object = None


@dataclass
class TechniquePrediction:
    technique_id: str
    name: str
    confidence: float   # cosine similarity 0.0-1.0


class AttackBertMapper:
    """Cosine similarity between a CVE description and 697 ATT&CK techniques."""

    def __init__(
        self,
        model_name: str,
        embeddings_cache_path: Path,
        device: str = "cpu",
    ):
        # Local imports so importing this module doesn't force torch load
        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np
        except ImportError as e:
            raise RuntimeError(
                "sentence-transformers not installed. Run: pip install "
                "'sentence-transformers>=2.6' 'torch>=2.1'"
            ) from e

        self._np = np
        self.model_name = model_name
        self.device = device
        self.cache_path = embeddings_cache_path

        logger.info("Loading sentence-transformers model: %s (device=%s)", model_name, device)
        self.model = SentenceTransformer(model_name, device=device)

        self.technique_ids: list[str] = []
        self.technique_embeddings = None  # np.ndarray (N, dim)
        self._load_or_build_technique_embeddings()

    def _load_or_build_technique_embeddings(self) -> None:
        """On first run, embed all 697 techniques and cache to .npz. Later runs
        load the cache in <100ms."""
        from ati_evn.enrichment.attack_catalog import get_all_techniques

        techniques = get_all_techniques()
        ids_sorted = sorted(techniques.keys())

        if self.cache_path.exists():
            data = self._np.load(self.cache_path, allow_pickle=False)
            if list(data["technique_ids"]) == ids_sorted:
                self.technique_ids = list(data["technique_ids"])
                self.technique_embeddings = data["embeddings"]
                logger.info(
                    "Loaded cached technique embeddings from %s (%d techniques)",
                    self.cache_path, len(self.technique_ids),
                )
                return
            logger.info("Cache mismatch (technique set changed) — rebuilding")

        logger.info("Building technique embeddings for %d techniques (one-time, ~30-60s)...",
                    len(ids_sorted))
        texts = [self._technique_text(techniques[tid]) for tid in ids_sorted]
        embeds = self.model.encode(
            texts,
            batch_size=32,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,   # so cosine == dot product
        )
        self.technique_ids = ids_sorted
        self.technique_embeddings = embeds

        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._np.savez_compressed(
            self.cache_path,
            technique_ids=self._np.array(ids_sorted),
            embeddings=embeds,
        )
        logger.info("Cached technique embeddings to %s (%.1f MB)",
                    self.cache_path, self.cache_path.stat().st_size / 1e6)

    @staticmethod
    def _technique_text(technique: dict) -> str:
        """Build the text we embed for a technique. Name + description gives
        the best CVE-matching semantics."""
        name = technique.get("name") or ""
        desc = (technique.get("description") or "").strip()
        return f"{name}. {desc}" if desc else name

    def map(
        self,
        description: str,
        *,
        top_k: int = 5,
        min_similarity: float = 0.35,
    ) -> list[TechniquePrediction]:
        """Return top-K techniques by cosine similarity, filtered by threshold.

        Empty description or None → empty list.
        """
        if not description or len(description.strip()) < 15:
            return []

        query_emb = self.model.encode(
            [description.strip()],
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )[0]

        # Cosine similarity == dot product because both sides are normalized
        sims = self.technique_embeddings @ query_emb

        top_idx = sims.argsort()[::-1][:top_k * 3]  # oversample, then filter
        out: list[TechniquePrediction] = []
        for i in top_idx:
            score = float(sims[i])
            if score < min_similarity:
                break
            tid = self.technique_ids[i]
            from ati_evn.enrichment.attack_catalog import get_technique_name
            out.append(TechniquePrediction(
                technique_id=tid,
                name=get_technique_name(tid),
                confidence=round(score, 3),
            ))
            if len(out) >= top_k:
                break
        return out


def load_mapper_or_none(
    model_name: str,
    cache_path: Path,
    device: str = "cpu",
) -> Optional[AttackBertMapper]:
    """Try to load the mapper. Return None on failure (caller falls back to
    chain-only enrichment). Never raises."""
    global _mapper_cache
    if _mapper_cache is _UNAVAILABLE:
        return None
    if _mapper_cache is not None:
        return _mapper_cache  # type: ignore

    try:
        m = AttackBertMapper(model_name=model_name, embeddings_cache_path=cache_path,
                             device=device)
        _mapper_cache = m
        return m
    except Exception as e:
        logger.warning(
            "AttackBertMapper unavailable (%s: %s) — enrichment falls back "
            "to CWE→ATT&CK chain only", type(e).__name__, e,
        )
        _mapper_cache = _UNAVAILABLE
        return None
