from theseus.orchestrator import _extract_json


def test_extract_fenced_json() -> None:
    text = "Here is the result:\n```json\n{\"a\": 1, \"b\": [1,2,3]}\n```\nthat's it"
    assert _extract_json(text) == {"a": 1, "b": [1, 2, 3]}


def test_extract_bare_object() -> None:
    text = "stuff before {\"x\": \"y\"} stuff after"
    assert _extract_json(text) == {"x": "y"}


def test_extract_bare_array() -> None:
    text = "wrap [1, 2, 3] end"
    assert _extract_json(text) == [1, 2, 3]
