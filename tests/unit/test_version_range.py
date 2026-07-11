from ati_evn.match.version_range import version_in_range


def test_match_range():
    assert version_in_range("1.4.3", ">= 1.0, < 2.0") == (True, "match_range")


def test_out_of_range():
    assert version_in_range("1.4.3", "<= 1.4.2") == (False, "out_of_range")


def test_no_version():
    assert version_in_range(None, ">= 1.0, < 2.0") == (False, "no_version")


def test_no_range():
    assert version_in_range("1.4.3", "") == (True, "no_range")


def test_unparseable():
    assert version_in_range("1.2.3-rc.4-patch5", ">= 1.0, < 2.0") == (False, "unparseable")


def test_match_exact():
    assert version_in_range("1.4.3", "= 1.4.3") == (True, "match_exact")
