from ati_evn.llm.cve_filter import (
    cve_description_mentions_vendor,
    cve_reference_url_mentions_vendor,
    should_run_llm,
)


def test_description_mentions_vendor():
    assert cve_description_mentions_vendor(
        "A flaw in Cisco IOS allows remote attackers...", {"cisco", "fortinet"},
    ) == "cisco"


def test_description_word_boundary():
    # "Franciscoated" must NOT match "cisco" as a substring.
    assert cve_description_mentions_vendor("Franciscoated bug in a widget", {"cisco"}) is None


def test_reference_url_mentions_vendor():
    assert cve_reference_url_mentions_vendor(
        [{"url": "https://siemens.com/psirt"}], {"siemens"},
    ) == ("siemens", "https://siemens.com/psirt")


def test_reference_url_substring_excluded():
    # host parts split: ["securitysiemens", "tk"] — "siemens" is not a whole part.
    assert cve_reference_url_mentions_vendor(
        [{"url": "https://securitysiemens.tk"}], {"siemens"},
    ) is None


def test_should_run_llm_skips_when_both_present():
    should, reason = should_run_llm(
        has_cpe=True, has_cwe=True,
        description="A flaw in Cisco IOS allows remote attackers...",
        references=[{"url": "https://siemens.com/psirt"}],
        evn_vendors={"cisco", "siemens"},
    )
    assert should is False
    assert reason == "cpe+cwe already present"
