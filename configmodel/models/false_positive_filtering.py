from dataclasses import dataclass
from dataclasses import field
from typing import List
from typing import Optional


@dataclass
class FalsePositiveRule:
    name: str
    cel_expression: str
    description: Optional[str] = None


@dataclass
class FalsePositiveFiltering:
    enabled: bool = True
    rules: List[FalsePositiveRule] = field(default_factory=list)
