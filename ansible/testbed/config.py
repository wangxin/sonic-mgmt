from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CONSTANTS:
    ANSIBLE_DIR: str = str(Path(__file__).parent.parent)
    SERVER_TESTBEDS_FILE: str = '/var/run/sonic/testbeds.json'
    TESTBED_MANAGEMENT_NETWORK_BASE: str = '192.168.0.0/20'
    TESTBED_MANAGEMENT_NETWORK_BASE_V6: str = 'fd00::/64'
