import pytest
from dacite import Config
from dacite import from_dict
from dacite import WrongTypeError

from configmodel.models.scanners.zap import ReplacerParameters
from configmodel.models.scanners.zap import ZapReplacer

DACITE_TEST_CONFIG = Config(check_types=True, strict=True)


class TestReplacerParameters:
    def test_default_delete_all_rules(self):
        """
        Test that deleteAllRules defaults to True when not provided in the input data
        """
        data = {}
        instance = from_dict(data_class=ReplacerParameters, data=data, config=DACITE_TEST_CONFIG)
        assert instance.deleteAllRules is True

    def test_invalid_type_for_delete_all_rules_raises_error(self):
        invalid_data_str = {"deleteAllRules": "not_a_boolean"}
        with pytest.raises(WrongTypeError):
            from_dict(data_class=ReplacerParameters, data=invalid_data_str, config=DACITE_TEST_CONFIG)


class TestZapReplacer:
    def test_empty_rules_raises_value_error(self):
        data = {"rules": []}
        with pytest.raises(ValueError):
            from_dict(data_class=ZapReplacer, data=data, config=DACITE_TEST_CONFIG)

        data = {}
        with pytest.raises(ValueError):
            from_dict(data_class=ZapReplacer, data=data, config=DACITE_TEST_CONFIG)

    def test_to_rules_dict_list_excludes_none(self):
        data = {
            "rules": [
                {"matchRegex": True, "tokenProcessing": False},
                {"tokenProcessing": True},
                {"matchRegex": False},
            ]
        }
        instance = from_dict(data_class=ZapReplacer, data=data, config=DACITE_TEST_CONFIG)

        rules_as_dicts = instance.to_rules_dict_list()

        assert isinstance(rules_as_dicts, list)
        assert len(rules_as_dicts) == 3

        assert isinstance(rules_as_dicts[0], dict)
        assert rules_as_dicts[0] == {"matchRegex": True, "tokenProcessing": False}

        assert isinstance(rules_as_dicts[1], dict)
        assert "matchRegex" not in rules_as_dicts[1]
        assert rules_as_dicts[1]["tokenProcessing"] is True
        assert rules_as_dicts[1] == {"tokenProcessing": True}

        assert isinstance(rules_as_dicts[2], dict)
        assert rules_as_dicts[2]["matchRegex"] is False
        assert "tokenProcessing" not in rules_as_dicts[2]
        assert rules_as_dicts[2] == {"matchRegex": False}
