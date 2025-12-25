from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CONSTANTS:
    ANSIBLE_DIR: str = str(Path(__file__).parent.parent)
    SERVER_TESTBEDS_FILE: str = '/var/run/sonic/testbeds.json'
