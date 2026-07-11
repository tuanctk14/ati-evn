from ati_evn.match.domain_utils import domain_matches, extract_host_from_url


def test_exact_domain():
    assert domain_matches("evn.com.vn", "evn.com.vn") == (True, "exact_domain")


def test_subdomain():
    assert domain_matches("npc.evn.com.vn", "evn.com.vn") == (True, "subdomain")


def test_substring_regression():
    # arguswatch bug: "evncrooks.com" must NOT match "evn.com"
    assert domain_matches("evncrooks.com", "evn.com") == (False, "no_match")


def test_reverse_direction_no_match():
    # IOC domain broader than customer asset — must not match
    assert domain_matches("evn.com", "npc.evn.com") == (False, "no_match")


def test_extract_host_from_url():
    assert extract_host_from_url("https://npc.evn.com.vn:8443/path?q=1") == "npc.evn.com.vn"


def test_extract_host_from_url_invalid():
    assert extract_host_from_url("not a url \x00") is None
