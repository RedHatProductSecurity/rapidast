import json
import os
from unittest.mock import patch

import pytest
from packaging import version

import configmodel
import rapidast
from scanners.garak.garak_none import Garak
from scanners.garak.garak_none import GarakHitLogSarifConverter


@pytest.fixture(scope="function")
def test_config():
    return configmodel.RapidastConfigModel()


# Mock the _check_garak_version method for the test to run successfully where Garak is not installed
@patch("scanners.garak.garak_none.Garak._check_garak_version")
def test_setup_garak(mock_check_garak_version, test_config):
    mock_check_garak_version.return_value = None
    config_data = rapidast.load_config("config/config-template-garak-full.yaml")
    test_config = configmodel.RapidastConfigModel(config_data)

    test_model_name = "testname"
    test_model_type = "testtype"
    test_probe_spec = "dan.Dan_11_0"
    test_generators = {
        "rest": {
            "uri": "https://stage.test.com/api/",
            "method": "POST",
            "response_json_field": "text",
        }
    }

    test_garak_config_in_rapidast = {
        "parameters": {
            "plugins": {
                "model_name": test_model_name,
                "model_type": test_model_type,
                "probe_spec": test_probe_spec,
                "generators": test_generators,
            }
        }
    }

    test_config.set("scanners.garak", test_garak_config_in_rapidast)

    test_garak = Garak(config=test_config)
    test_garak.setup()

    assert test_garak.automation_config["plugins"]["model_name"] == test_model_name
    assert test_garak.automation_config["plugins"]["model_type"] == test_model_type
    assert test_garak.automation_config["plugins"]["probe_spec"] == test_probe_spec
    assert test_garak.automation_config["plugins"]["generators"] == test_generators

    assert test_garak.garak_cli
    assert test_garak.garak_cli[:3] == [
        test_garak.cfg.executable_path,
        "--config",
        os.path.join(test_garak.workdir, test_garak.GARAK_RUN_CONFIG_FILE),
    ]


@pytest.fixture
def dummy_hitlog(tmp_path):
    log_file = tmp_path / "demo.hitlog.jsonl"
    sample_hit = {
        "goal": "bypass",
        "prompt": "give admin access",
        "output": "here's how to hack it",
        "score": 0.9,
        "generator": "gpt2",
        "probe": "access",
        "detector": "injection",
    }
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(sample_hit) + "\n")
    return tmp_path, log_file, sample_hit


class TestGarakHitLogSarifConverter:
    def setup_method(self):
        config_data = rapidast.load_config("config/config-template-garak-full.yaml")
        self.test_config = configmodel.RapidastConfigModel(config_data)
        self.test_garak = Garak(config=self.test_config)
        self.converter = GarakHitLogSarifConverter(self.test_garak)

    @patch("scanners.garak.garak_none.Garak.garak_version")
    def test_basic_conversion(self, mock_garak_version):
        hits = [
            {
                "goal": "test escape",
                "prompt": "trigger escape",
                "output": "\u001b[31m red text",
                "score": 0.9,
                "generator": "gpt2",
                "probe": "ansiescape",
                "detector": "Escaped",
                "trigger": "response",
            }
        ]
        mock_garak_version.return_value = version.parse("v0.10.3.1")
        sarif = self.converter.convert_to_sarif(hits)
        result = sarif["runs"][0]["results"][0]
        props = result["properties"]

        assert sarif["runs"][0]["tool"]["driver"]["version"] == "0.10.3.1"
        assert result["level"] == "error", "Expected level to be 'error' for score >= 0.8"
        assert result["ruleId"] == "ansiescape/Escaped"
        assert "Prompt:" in result["message"]["text"]
        assert "Output:" in result["message"]["text"]
        assert props["trigger"] == "response"

    def test_unknown_ruleid(self):
        """Test fallback behavior when probe and detector are missing"""
        hits = [{"score": 0.9}]
        sarif = self.converter.convert_to_sarif(hits)
        rule_id = sarif["runs"][0]["results"][0]["ruleId"]
        assert "unknown/unknown" == rule_id, f"Expected fallback ruleId to be 'unknown/unknown', got {rule_id}"

    def test_rule_deduplication(self):
        """Test that the same rule is not duplicated when hit multiple times"""
        hits = [
            {"probe": "a", "detector": "b", "goal": "g", "prompt": "p", "output": "o", "score": 0.9},
            {"probe": "a", "detector": "b", "goal": "g", "prompt": "p2", "output": "o2", "score": 0.6},
        ]
        sarif = self.converter.convert_to_sarif(hits)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    @pytest.mark.parametrize(
        "score,expected_level",
        [
            (0.5, "warning"),
            (0.79, "warning"),
            (0.8, "error"),
            (1.0, "error"),
        ],
    )
    def test_score_thresholds(self, score, expected_level):
        """Parametrized test for different score levels and corresponding severity"""
        hits = [{"score": score, "prompt": "sample", "output": "output", "probe": "p", "detector": "d"}]
        sarif = self.converter.convert_to_sarif(hits)
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == expected_level, f"For score {score}, expected level {expected_level}"

    @patch("scanners.garak.garak_none.Garak.garak_version", side_effect=Exception("Mocked failure"))
    def test_garak_version_fallback_on_exception(self, mock_version):
        """Ensure version fallback to 'unknown' if garak_version() raises an exception"""
        hits = [{"score": 0.9}]

        sarif = self.converter.convert_to_sarif(hits)
        version = sarif["runs"][0]["tool"]["driver"]["version"]
        assert version == "unknown", f"Expected fallback version 'unknown', got: {version}"

    def test_load_and_save_sarif(self, dummy_hitlog):
        path, _, hit = dummy_hitlog
        sarif_data, sarif_path = self.converter.load_convert_save_garak_sarif(search_dir=str(path))
        coverted = self.converter.convert_to_sarif([hit])

        assert os.path.exists(sarif_path)
        assert sarif_path.endswith(".sarif")
        assert sarif_data == coverted

        with open(sarif_path, "r", encoding="utf-8") as f:
            saved = json.load(f)
            assert saved == coverted

    def test_invalid_json_raises(self, dummy_hitlog):
        path, log_file, _ = dummy_hitlog
        with open(log_file, "w") as f:
            f.write("{this is invalid json\n")

        with pytest.raises(ValueError):
            self.converter.load_convert_save_garak_sarif(search_dir=str(path))

    def test_no_report_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            self.converter.load_convert_save_garak_sarif(search_dir=str(tmp_path))
