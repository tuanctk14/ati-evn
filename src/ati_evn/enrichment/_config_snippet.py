"""Settings additions for slice 4.5 (attack context enrichment).

To integrate into your existing config.py, add these fields to your Settings
class. They are optional (all have safe defaults) so existing installations
keep working without changes.
"""
# Add these fields inside your `class Settings(BaseSettings)` in config.py:
#
#     # ── ATT&CK enrichment (slice 4.5) ────────────────────────────────────
#     attack_bert_model: str = "basel/ATTACK-BERT"
#         # Fallback: "sentence-transformers/all-MiniLM-L6-v2"
#     attack_bert_device: str = "cpu"
#         # Set to "cuda" if you have a working torch+CUDA install
#     smet_embeddings_cache: str = "./src/ati_evn/data/technique_embeddings.npz"
#         # Auto-created on first run; ~2MB. Safe to delete to force rebuild.
