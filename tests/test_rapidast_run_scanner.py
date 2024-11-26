from unittest.mock import MagicMock
from unittest.mock import patch

import rapidast
from rapidast import scanners


@patch("rapidast.scanners.str_to_scanner")
def test_run_scanner_setup_failure(mock_str_to_scanner):
    """
    Test that if an exception occurs during `scanner.setup`, the `run_scanner` method
    catches the exception, returns 1, and updates the scanner's state to 'ERROR'
    """

    mock_config = MagicMock()
    mock_args = MagicMock()
    mock_scan_exporter = MagicMock()

    mock_scanner = MagicMock()
    mock_str_to_scanner.return_value = lambda config, name: mock_scanner

    mock_scanner.setup.side_effect = Exception("Setup failed")

    result = rapidast.run_scanner("mock_name", mock_config, mock_args, mock_scan_exporter)

    assert result == 1
    mock_scanner.setup.assert_called_once()
    assert mock_scanner.state == scanners.State.ERROR


@patch("rapidast.scanners.str_to_scanner")
def test_run_scanner_setup_success(mock_str_to_scanner):
    """
    Test that if `scanner.setup` is successful, `run_scanner` continues as expected.
    Subsequent actions are mocked to focus on ensuring `run_scanner` returns a successful
    result (0)
    """
    def update_state(state):
        mock_scanner.state = state

    def update_state_ready():
        update_state(scanners.State.READY)

    def update_state_processed():
        update_state(scanners.State.PROCESSED)

    mock_config = MagicMock()
    mock_args = MagicMock()
    mock_scan_exporter = MagicMock()

    mock_scanner = MagicMock()
    mock_str_to_scanner.return_value = lambda config, name: mock_scanner

    mock_scanner.setup.side_effect = update_state_ready
    mock_scanner.postprocess.side_effect = update_state_processed

    result = rapidast.run_scanner("mock_name", mock_config, mock_args, mock_scan_exporter)

    assert result == 0
    mock_scanner.setup.assert_called_once()
