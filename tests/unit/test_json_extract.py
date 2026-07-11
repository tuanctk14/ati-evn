import pytest

from ati_evn.llm.json_extract import JSONExtractError, extract_json_dict, extract_json_list


def test_clean_json_dict():
    assert extract_json_dict('{"a": 1, "b": "x"}') == {"a": 1, "b": "x"}


def test_json_dict_in_markdown_fences():
    text = '```json\n{"a": 1}\n```'
    assert extract_json_dict(text) == {"a": 1}


def test_json_dict_with_leading_prose():
    text = 'Sure, here is the result:\n{"a": 1, "b": 2}'
    assert extract_json_dict(text) == {"a": 1, "b": 2}


def test_malformed_raises():
    with pytest.raises(JSONExtractError):
        extract_json_dict('{"a": 1, "b": ')


def test_list_instead_of_dict():
    text = '[{"a": 1}, {"b": 2}]'
    with pytest.raises(JSONExtractError):
        extract_json_dict(text)
    assert extract_json_list(text) == [{"a": 1}, {"b": 2}]
