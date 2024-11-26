import rapidast
from rapidast import scanners

def test_run_scanner_setup_failure(mocker):
    mock_config = mocker.MagicMock()
    mock_args = mocker.MagicMock()
    mock_scan_exporter = mocker.MagicMock()

    mock_scanner = mocker.MagicMock()
    mocker.patch("rapidast.scanners.str_to_scanner", return_value=lambda config, name: mock_scanner)

    mock_scanner.setup.side_effect = Exception("Setup failed")

    result = rapidast.run_scanner("mock_name", mock_config, mock_args, mock_scan_exporter)

    assert result == 1
    mock_scanner.setup.assert_called_once()


def test_run_scanner_setup_success(mocker):
    def update_state(state):
        mock_scanner.state = state
    
    def update_state_ready():
        update_state(scanners.State.READY)

    def update_state_processed():
        update_state(scanners.State.PROCESSED)
        
    mock_config = mocker.MagicMock()
    mock_args = mocker.MagicMock()
    mock_scan_exporter = mocker.MagicMock()

    mock_scanner = mocker.MagicMock()
    mocker.patch("rapidast.scanners.str_to_scanner", return_value=lambda config, name: mock_scanner)
        
    mock_scanner.setup.side_effect = update_state_ready
    mock_scanner.postprocess.side_effect = update_state_processed

    result = rapidast.run_scanner("mock_name", mock_config, mock_args, mock_scan_exporter)

    assert result == 0
    mock_scanner.setup.assert_called_once()