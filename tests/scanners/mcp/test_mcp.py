import json
import os
from unittest.mock import patch

import configmodel
import rapidast
from scanners.mcp.mcp_none import Mcp


def load_config(path: str):
    data = rapidast.load_config(path)
    return configmodel.RapidastConfigModel(data)


def test_mcp_cli_building(tmp_path):
    cfg_path = os.path.join(os.path.dirname(__file__), "../../../config/config-template-mcp.yaml")
    config = load_config(cfg_path)
    m = Mcp(config=config)
    m.setup()
    # Must contain executable, subcommand, and url
    assert m.cli[0].endswith("mcp-scan") or m.cli[0] == "mcp-scan"
    assert m.cli[1] == "scan"
    assert "--url" in m.cli


@patch("subprocess.run")
def test_mcp_run_and_postprocess(mock_run, tmp_path):
    mock_run.return_value.returncode = 0
    cfg_path = os.path.join(os.path.dirname(__file__), "../../../config/config-template-mcp.yaml")
    config = load_config(cfg_path)
    m = Mcp(config=config)
    m.setup()
    m.run()

    # create a fake json output to be copied in postprocess
    os.makedirs(m.workdir, exist_ok=True)
    with open(os.path.join(m.workdir, m.DEFAULT_OUTPUT_FILE), "w", encoding="utf-8") as f:
        json.dump({"runs": []}, f)

    m.postprocess()

    # Results dir should have the output
    outputs = [p for p in os.listdir(m.results_dir) if p.endswith(".json")]
    assert outputs, f"Expected output JSON in {m.results_dir}"

