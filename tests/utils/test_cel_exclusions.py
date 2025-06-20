import pytest

from configmodel.models.exclusions import Exclusions
from configmodel.models.exclusions import Rule
from utils.cel_exclusions import CELExclusions


@pytest.fixture
def sample_sarif_data():
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "MyDASTScanner"}},
                "results": [
                    {
                        "ruleId": "CWE-79",
                        "level": "error",
                        "message": {"text": "Cross-site scripting."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://www.example.com/app/index.html"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "DAST-1234-KnownFP",
                        "level": "note",
                        "message": {"text": "A known false positive issue"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://www.example.com/app/styles.css"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "CWE-200",
                        "level": "error",
                        "message": {"text": "Information exposure"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://admin.example.com/dashboard.html"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "CWE-319",
                        "level": "warning",
                        "message": {"text": "Cleartext communication."},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "https://thirdparty.cdn.com/script.js"}}}
                        ],
                    },
                    {
                        "ruleId": "CWE-501",
                        "level": "note",
                        "message": {"text": "Minor style issue."},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "https://www.example.com/css/main.css"}}}
                        ],
                    },
                    {
                        "ruleId": "CWE-502",
                        "level": "note",
                        "message": {"text": "Minor JS issue."},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "https://www.example.com/js/utility.js"}}}
                        ],
                    },
                    {
                        "ruleId": "DAST-1234-KnownFP",
                        "level": "error",
                        "message": {"text": "Another known FP on admin path."},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://admin.example.com/settings.html"}
                                }
                            }
                        ],
                    },
                    {
                        "level": "none",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://www.example.com/api/v1/me/"},
                                    "region": {
                                        "startLine": 1,
                                        "properties": {
                                            "startLineFailure": "Resolved invalid start line: 0 - used fallback value instead."
                                        },
                                        "snippet": {"text": "5555493a9bc4a6dc8784af232a42c883"},
                                    },
                                },
                                "properties": {"attack": ""},
                            }
                        ],
                        "message": {"text": "\ncookie:r_s_session"},
                        "ruleId": "10112",
                        "webRequest": {
                            "protocol": "HTTP",
                            "version": "1.1",
                            "target": "https://www.example.com/api/v1/me/",
                            "method": "GET",
                            "headers": {
                                "accept": "application/json",
                                "cache-control": "no-cache",
                                "content-length": "0",
                                "host": "stage.ai.ansible.redhat.com",
                                "pragma": "no-cache",
                                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                            },
                            "body": {},
                        },
                        "webResponse": {
                            "statusCode": 401,
                            "reasonPhrase": "Unauthorized",
                            "protocol": "HTTP",
                            "version": "1.1",
                            "headers": {
                                "Connection": "keep-alive",
                                "Content-Length": "98",
                                "Content-Type": "application/json",
                                "Server": "CloudFront",
                                "Strict-Transport-Security": "max-age=31536000",
                                "Vary": "Origin",
                                "x-frame-options": "DENY",
                                "x-robots-tag": "noindex, nofollow",
                            },
                            "body": {
                                "text": '{"code":"not_authenticated","message":"Authentication credentials were not provided.","detail":{}}'
                            },
                            "noResponseReceived": False,
                        },
                    },
                ],
            }
        ],
    }


@pytest.fixture
def multi_run_sarif_data():
    """SARIF data with multiple runs for testing."""
    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ScannerA"}},
                "results": [
                    {
                        "ruleId": "CWE-79",
                        "level": "error",
                        "message": {"text": "RunA kept error."},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "https://hosta.example.com/a1"}}}
                        ],
                    },
                    {
                        "level": "none",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://www.example.com/api/v1/me/"},
                                    "region": {
                                        "startLine": 1,
                                        "properties": {
                                            "startLineFailure": "Resolved invalid start line: 0 - used fallback value instead."
                                        },
                                        "snippet": {"text": "5555493a9bc4a6dc8784af232a42c883"},
                                    },
                                },
                                "properties": {"attack": ""},
                            }
                        ],
                        "message": {"text": "\ncookie:r_s_session"},
                        "ruleId": "10112",
                        "webRequest": {
                            "protocol": "HTTP",
                            "version": "1.1",
                            "target": "https://www.example.com/api/v1/me/",
                            "method": "GET",
                            "headers": {
                                "accept": "application/json",
                                "cache-control": "no-cache",
                                "content-length": "0",
                                "host": "stage.ai.ansible.redhat.com",
                                "pragma": "no-cache",
                                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                            },
                            "body": {},
                        },
                        "webResponse": {
                            "statusCode": 401,
                            "reasonPhrase": "Unauthorized",
                            "protocol": "HTTP",
                            "version": "1.1",
                            "headers": {
                                "Connection": "keep-alive",
                                "Content-Length": "98",
                                "Content-Type": "application/json",
                                "Server": "CloudFront",
                                "Strict-Transport-Security": "max-age=31536000",
                                "Vary": "Origin",
                                "x-frame-options": "DENY",
                                "x-robots-tag": "noindex, nofollow",
                            },
                            "body": {
                                "text": '{"code":"not_authenticated","message":"Authentication credentials were not provided.","detail":{}}'
                            },
                            "noResponseReceived": False,
                        },
                    },
                ],
            },
            {
                "tool": {"driver": {"name": "ScannerB"}},
                "results": [
                    {
                        "ruleId": "CWE-123",
                        "level": "error",
                        "message": {"text": "RunB kept error1."},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "https://hostb.example.com/b1"}}}
                        ],
                    },
                    {
                        "ruleId": "DAST-1234-KnownFP",
                        "level": "note",
                        "message": {"text": "A known false positive issue"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "https://www.example.com/app/styles.css"}
                                }
                            }
                        ],
                    },
                    {
                        "ruleId": "CWE-456",
                        "level": "warning",
                        "message": {"text": "RunB kept warning"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "https://hostb.example.com/b3"}}}
                        ],
                    },
                ],
            },
            {"tool": {"driver": {"name": "ScannerC"}}, "results": []},
        ],
    }


@pytest.fixture
def default_config():
    """A default Exclusions config."""
    return Exclusions(enabled=True, rules=[])


@pytest.fixture
def basic_fp_rules():
    """Config with basic FP rules"""
    return Exclusions(
        enabled=True,
        rules=[
            Rule(
                name="Exclude admin paths",
                cel_expression='.result.locations.exists(loc, loc.physicalLocation.artifactLocation.uri.startsWith("https://admin.example.com"))',
            ),
            Rule(
                name="Exclude known FP ruleId with specific response code",
                cel_expression='.result.ruleId == "10112" && .result.webResponse.statusCode == 401',
            ),
            Rule(
                name="Exclude specific ruleId and level note on static assets",
                cel_expression='.result.ruleId == "DAST-1234-KnownFP" && .result.level == "note" && .result.locations.exists(loc, loc.physicalLocation.artifactLocation.uri.endsWith(".css") || loc.physicalLocation.artifactLocation.uri.endsWith(".html"))',
            ),
        ],
    )


@pytest.fixture
def malformed_cel_rule():
    """Config with a malformed CEL expression."""
    return Exclusions(enabled=True, rules=[Rule(name="Malformed rule", cel_expression='.result.level == "error" && (')])


@pytest.fixture
def empty_rules_config():
    """Config with no rules"""
    return Exclusions(enabled=True, rules=[])


@pytest.fixture
def disabled_config():
    """Config with filtering disabled"""
    return Exclusions(enabled=False, rules=[Rule(name="Some rule", cel_expression="true")])  # Rule exists but disabled


class TestCELExclusions:
    def test_init_enabled_and_compiled(self, basic_fp_rules):
        """Test that filter is enabled and program compiles on init"""
        filter_instance = CELExclusions(basic_fp_rules)
        assert filter_instance.config.enabled is True
        assert filter_instance.compiled_cel_program is not None

    def test_init_disabled(self, disabled_config):
        """Test that filter is disabled on init if config says so"""
        filter_instance = CELExclusions(disabled_config)
        assert filter_instance.config.enabled is False
        assert filter_instance.compiled_cel_program is None

    def test_init_compilation_failure(self, malformed_cel_rule, caplog):
        """Test that compilation failure disables filtering and prints warning"""
        filter_instance = CELExclusions(malformed_cel_rule)
        assert filter_instance.config.enabled is False
        assert filter_instance.compiled_cel_program is None
        assert any(record.levelname == "WARNING" for record in caplog.records)

    def test_init_no_rules(self, empty_rules_config):
        """Test that filter is disabled if no rules are provided"""
        filter_instance = CELExclusions(empty_rules_config)
        assert filter_instance.config.enabled is True
        assert filter_instance.compiled_cel_program is None

    @pytest.mark.parametrize(
        "result_index, expected_is_fp",
        [(0, False), (1, True), (2, True), (3, False), (4, False), (5, False), (6, True), (7, True)],
    )
    def test_is_excluded(self, basic_fp_rules, sample_sarif_data, result_index, expected_is_fp):
        """Test is_excluded"""
        filter_instance = CELExclusions(basic_fp_rules)
        sarif_result = sample_sarif_data["runs"][0]["results"][result_index]

        assert filter_instance.is_excluded(sarif_result) == expected_is_fp

    def test_is_excluded_malformed_expression_error(self, malformed_cel_rule, sample_sarif_data, caplog):
        """Test that errors during CEL evaluation result in not filtering"""
        filter_instance = CELExclusions(malformed_cel_rule)
        sarif_result = sample_sarif_data["runs"][0]["results"][0]

        assert filter_instance.is_excluded(sarif_result) is False

        assert any(record.levelname == "WARNING" for record in caplog.records)

    def test_filter_sarif_results_enabled(self, basic_fp_rules, sample_sarif_data):
        """Test filtering"""
        filter_instance = CELExclusions(basic_fp_rules)
        filtered_sarif = filter_instance.filter_sarif_results(sample_sarif_data)

        assert len(filtered_sarif["runs"][0]["results"]) == 4

        kept_rule_ids = [r["ruleId"] for r in filtered_sarif["runs"][0]["results"]]
        assert "CWE-79" in kept_rule_ids
        assert "CWE-319" in kept_rule_ids
        assert "CWE-501" in kept_rule_ids
        assert "CWE-502" in kept_rule_ids

        assert "DAST-1234-KnownFP" not in kept_rule_ids
        assert "CWE-200" not in kept_rule_ids
        assert "10112" not in kept_rule_ids

    def test_filter_sarif_results_disabled(self, disabled_config, sample_sarif_data):
        """Test that no filtering occurs when filtering is disabled"""
        filter_instance = CELExclusions(disabled_config)
        filtered_sarif = filter_instance.filter_sarif_results(sample_sarif_data)

        assert len(filtered_sarif["runs"][0]["results"]) == len(sample_sarif_data["runs"][0]["results"])
        assert filtered_sarif == sample_sarif_data

    def test_filter_sarif_results_no_rules(self, empty_rules_config, sample_sarif_data):
        """Test that no filtering occurs when no rules are configured."""
        filter_instance = CELExclusions(empty_rules_config)
        filtered_sarif = filter_instance.filter_sarif_results(sample_sarif_data)

        assert len(filtered_sarif["runs"][0]["results"]) == len(sample_sarif_data["runs"][0]["results"])
        assert filtered_sarif == sample_sarif_data

    def test_filter_sarif_results_empty_sarif(self, basic_fp_rules):
        """Test filtering with an empty SARIF results array."""
        empty_sarif = {
            "$schema": "...",
            "version": "...",
            "runs": [{"tool": {"driver": {"name": "Test"}}, "results": []}],
        }
        filter_instance = CELExclusions(basic_fp_rules)
        filtered_sarif = filter_instance.filter_sarif_results(empty_sarif)
        assert len(filtered_sarif["runs"][0]["results"]) == 0

    def test_filter_sarif_results_no_runs_in_sarif(self, basic_fp_rules):
        """Test filtering with SARIF data missing the 'runs' key"""
        sarif_no_runs = {"$schema": "...", "version": "..."}
        filter_instance = CELExclusions(basic_fp_rules)
        filtered_sarif = filter_instance.filter_sarif_results(sarif_no_runs)
        assert filtered_sarif == sarif_no_runs

    def test_filter_sarif_results_no_results_in_run(self, basic_fp_rules):
        """Test filtering with SARIF data having 'runs' but no 'results' in the first run"""
        sarif_no_results = {"$schema": "...", "version": "...", "runs": [{"tool": {"driver": {"name": "Test"}}}]}
        filter_instance = CELExclusions(basic_fp_rules)
        filtered_sarif = filter_instance.filter_sarif_results(sarif_no_results)
        assert filtered_sarif["runs"][0]["results"] == []

    def test_filter_sarif_results_multi_run(self, basic_fp_rules, multi_run_sarif_data):
        """
        Test that filter_sarif_results correctly filters results across multiple runs
        """
        filter_instance = CELExclusions(basic_fp_rules)
        filtered_sarif = filter_instance.filter_sarif_results(multi_run_sarif_data)

        total_original_results = 0
        total_filtered_results = 0
        for run in multi_run_sarif_data["runs"]:
            total_original_results += len(run.get("results", []))
        for run in filtered_sarif["runs"]:
            total_filtered_results += len(run.get("results", []))

        assert total_original_results == (2 + 3 + 0)
        assert total_filtered_results == (1 + 2 + 0)

        assert len(filtered_sarif["runs"][0]["results"]) == 1
        assert filtered_sarif["runs"][0]["results"][0]["ruleId"] == "CWE-79"
        assert not any(r["ruleId"] == "DAST-1234-KnownFP" for r in filtered_sarif["runs"][0]["results"])

        assert len(filtered_sarif["runs"][1]["results"]) == 2
        assert filtered_sarif["runs"][1]["results"][0]["ruleId"] == "CWE-123"
        assert filtered_sarif["runs"][1]["results"][1]["ruleId"] == "CWE-456"
        assert not any(r["ruleId"] == "DAST-1234-KnownFP" for r in filtered_sarif["runs"][1]["results"])

        assert len(filtered_sarif["runs"][2]["results"]) == 0
