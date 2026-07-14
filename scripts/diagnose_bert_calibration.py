"""Diagnostic — feed 4 real CVE descriptions with known correct
technique, check if ATTACK-BERT ranks the correct one in top-3."""
from ati_evn.enrichment.orchestrator import load_smet_lazy

CASES = [
    {
        "name": "Log4Shell CVE-2021-44228",
        "description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security "
            "releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in "
            "configuration, log messages, and parameters do not protect "
            "against attacker controlled LDAP and other JNDI related "
            "endpoints. An attacker who can control log messages or log "
            "message parameters can execute arbitrary code loaded from "
            "LDAP servers when message lookup substitution is enabled."
        ),
        "expected_any_of": ["T1190", "T1203", "T1210", "T1059"],
    },
    {
        "name": "EternalBlue CVE-2017-0144",
        "description": (
            "The SMBv1 server in Microsoft Windows Vista SP2, Windows "
            "Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8.1, "
            "Windows Server 2012 Gold and R2, Windows RT 8.1, Windows 10 "
            "Gold, 1511, and 1607, and Windows Server 2016 allows remote "
            "attackers to execute arbitrary code via crafted packets."
        ),
        "expected_any_of": ["T1210", "T1190", "T1068"],
    },
    {
        "name": "SQL Injection generic",
        "description": (
            "SQL injection vulnerability in the login page allows remote "
            "attackers to execute arbitrary SQL commands via specially "
            "crafted input in the username parameter, potentially leading "
            "to authentication bypass and data exfiltration from the "
            "application database."
        ),
        "expected_any_of": ["T1190", "T1059", "T1213"],
    },
    {
        "name": "Fortinet SSL-VPN CVE-2022-42475",
        "description": (
            "A heap-based buffer overflow vulnerability in FortiOS SSL-VPN "
            "may allow a remote unauthenticated attacker to execute "
            "arbitrary code or commands via specifically crafted requests."
        ),
        "expected_any_of": ["T1190", "T1203", "T1210"],
    },
]

mapper = load_smet_lazy()
if not mapper:
    print("[FAIL] Mapper not loaded")
    raise SystemExit(1)

hits = 0
print(f"\n{'Case':40s} {'Top-3 (id / conf)':50s} {'Expected':30s} {'Hit'}")
print("-" * 130)
for c in CASES:
    preds = mapper.map(c["description"], top_k=3, min_similarity=0.0)
    top_ids = [p.technique_id for p in preds]
    top_display = " / ".join(f"{p.technique_id}({p.confidence:.2f})" for p in preds)
    hit = any(t in c["expected_any_of"] for t in top_ids)
    if hit:
        hits += 1
    print(f"{c['name'][:40]:40s} {top_display:50s} "
          f"{','.join(c['expected_any_of']):30s} {'YES' if hit else 'NO'}")

print("-" * 130)
print(f"Score: {hits}/{len(CASES)} cases hit expected technique in top-3")
print()
if hits >= 3:
    print("[OK] Model calibration acceptable — proceed with backfill")
elif hits >= 2:
    print("[WARN] Model calibration marginal — enrichment quality mixed")
else:
    print("[FAIL] Model may be systematically biased — investigate before backfill")
