from utils.query import Query

DICT_CONFIG = {
    "general": {
        "service_name": "test_service_name",
        "result_dir": "/results/",
        "local_proxy": {
            "http": "http://127.0.0.1:8090",
            "https": "http://127.0.0.1:8090",
        },
    },
    "list_value": ["item0", "item1", ["nested_item0", "nested_item1"]],
    "list_one_item": ["one_item_value"],
    "list_empty": [],
    "urls_list": [
        "http://127.0.0.1",
        {
            "url": "127.0.0.1",
            "protocol": "http",
        },
    ],
}

LIST_CONFIG = ["item0", "item1", ["nested_item0", "nested_item1"]]


class SampleClass(Query):
    def __init__(self, data):
        self.q = self._build_query(data)


def test_query_dict():
    sample = SampleClass(DICT_CONFIG)

    assert sample.q.general.service_name.value == "test_service_name"
    assert sample.q["general"]["service_name"].value == "test_service_name"

    assert sample.q.list_value.value == ["item0", "item1", ["nested_item0", "nested_item1"]]
    assert sample.q["list_value"].value == ["item0", "item1", ["nested_item0", "nested_item1"]]

    assert sample.q.urls_list[1].protocol.value == "http"
    assert sample.q["urls_list"][1]["protocol"].value == "http"

    assert sample.q.list_one_item.value == ["one_item_value"]
    assert sample.q["list_one_item"].value == ["one_item_value"]
    
    assert sample.q.list_empty.value == []
    assert sample.q["list_empty"].value == []


def test_query_list():
    sample = SampleClass(LIST_CONFIG)

    assert sample.q.value == ["item0", "item1", ["nested_item0", "nested_item1"]]
    assert sample.q[0].value == "item0"
    assert sample.q[1].value == "item1"


def test_query_wrong_key():
    sample = SampleClass(DICT_CONFIG)

    assert sample.q.general.wrong_key.service_name.value is None
    assert sample.q["general"]["wrong_key"]["service_name"].value is None

    assert sample.q.urls_list[0].protocol.value is None
    assert sample.q["urls_list"][0]["protocol"].value is None

    assert sample.q.wrong_key[0].protocol.value is None
    assert sample.q["wrong_key"][0]["protocol"].value is None
