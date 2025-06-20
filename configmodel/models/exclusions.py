from dataclasses import dataclass
from dataclasses import field
from typing import List
from typing import Optional


@dataclass
class Rule:
    name: str
    cel_expression: str
    description: Optional[str] = None


@dataclass
class Exclusions:
    enabled: bool = True
    rules: List[Rule] = field(default_factory=list)
