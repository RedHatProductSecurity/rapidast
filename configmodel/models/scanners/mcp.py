from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict


@dataclass
class McpConfig:
    # Parameters passed to mcp-security-scanner CLI
    parameters: Dict[str, Any] = field(default_factory=dict)
    # Path to the mcp-scan executable (defaults to PATH lookup if just "mcp-scan")
    executable_path: str = field(default="mcp-scan")

from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict


@dataclass
class McpConfig:
    # Parameters passed to mcp-security-scanner CLI
    parameters: Dict[str, Any] = field(default_factory=dict)
    # Path to the mcp-scan executable (defaults to PATH lookup if just "mcp-scan")
    executable_path: str = field(default="mcp-scan")


