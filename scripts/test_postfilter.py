"""Quick verification of postfilter cases."""
from ati_evn.agent.loop.postfilter import postfilter_answer

cases = [
    # (input, expected_contains, expected_not_contains)
    ("Dung /campaign_detail 5 de xem chi tiet",
     "/campaign 5", "/campaign_detail"),
    ("Chay /campaign_confirm 5 de confirm",
     "/confirm_campaign 5", "/campaign_confirm"),
    ("Xem /list_campaign de list",
     "/list_campaigns", None),
    ("Real command /campaign 5 giu nguyen",
     "/campaign 5", None),
    # URL -- must NOT touch
    ("Xem tai lieu https://example.com/campaign_detail",
     "https://example.com/campaign_detail", None),
    # Multiple in one
    ("Dung /campaign_detail 5 hoac /show_campaign 5",
     "/campaign 5", "/campaign_detail"),
    # Unknown fake -- strip
    ("Chay /nonexistent_cmd 5 nhe",
     "5", "/nonexistent_cmd"),
]
fail = 0
for i, (inp, must_have, must_not_have) in enumerate(cases, 1):
    out, stats = postfilter_answer(inp)
    ok = must_have in out
    if must_not_have:
        ok = ok and (must_not_have not in out)
    status = "OK" if ok else "FAIL"
    print(f"[{i}] {status}")
    if not ok:
        fail += 1
        print(f"  Input : {inp}")
        print(f"  Output: {out}")
        print(f"  Expect contains: {must_have!r}, not contain: {must_not_have!r}")
print(f"\n{len(cases)-fail}/{len(cases)} passed")
