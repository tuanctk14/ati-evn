from ati_evn.brand_rules.typosquat import is_typosquat, levenshtein


def test_exact_match_not_typosquat():
    # Real EVN domain itself must never be flagged as its own typosquat.
    assert is_typosquat("evn.com.vn", ["evn.com.vn"], max_distance=2) == (False, None)


def test_one_char_substitution_is_typosquat():
    # evn.com.vn -> evm.com.vn (n -> m), distance 1
    hit, dist = is_typosquat("evm.com.vn", ["evn.com.vn"], max_distance=2)
    assert hit is True
    assert dist == 1


def test_distance_at_threshold_is_typosquat():
    # evn.com.vn -> evnn.comvn (insert + delete), distance 2
    hit, dist = is_typosquat("evnn.comvn", ["evn.com.vn"], max_distance=2)
    assert hit is True
    assert dist == 2


def test_distance_over_threshold_not_typosquat():
    # evngov.cc is a plausible brand-impersonation domain but far from
    # evn.com.vn in edit distance -- should NOT be flagged as typosquat
    # (it's caught by the rule engine's title-match instead).
    hit, dist = is_typosquat("evngov.cc", ["evn.com.vn"], max_distance=2)
    assert hit is False
    assert dist is not None and dist > 2


def test_unrelated_domain_not_typosquat():
    hit, dist = is_typosquat("google.com", ["evn.com.vn"], max_distance=2)
    assert hit is False
    assert dist is not None and dist > 2


def test_levenshtein_basic():
    assert levenshtein("evn", "evn") == 0
    assert levenshtein("evn", "evm") == 1
    assert levenshtein("", "abc") == 3
    assert levenshtein("abc", "") == 3
