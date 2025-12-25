import json
import logging
import contextlib
from functools import cached_property

from .ansible_hosts import AnsibleHost
from ..config import CONSTANTS as C

logger = logging.getLogger(__name__)


class TestServer(AnsibleHost):

    SONIC_APT_LOCK_FILE = "/var/run/sonic/lock"
    SONIC_TESTBED_FILE = C.SERVER_TESTBEDS_FILE

    def __init__(self, inventory, pattern, hostvars={}, options={}):
        super(TestServer, self).__init__(inventory, pattern, hostvars=hostvars, options=options)

    @cached_property
    def os_release(self):
        """
        Get OS release information from /etc/os-release.

        Returns a dict with keys like:
        - NAME: OS name
        - VERSION: Version string
        - ID: OS identifier
        - VERSION_ID: Version ID
        - PRETTY_NAME: Pretty name
        etc.

        The result is cached after the first call.
        """
        logger.debug(f"Reading /etc/os-release from {self.hostname}")
        result = self.command(
            "cat /etc/os-release",
            module_ignore_errors=True
        )

        os_release_dict = {}
        if not result.get("failed", False):
            # Parse the os-release file format (KEY=value or KEY="value")
            for line in result["stdout"].split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip().strip('"').strip("'")
                    os_release_dict[key] = value

            logger.debug(f"Cached os-release for {self.hostname}: {os_release_dict.get('PRETTY_NAME', 'unknown')}")
        else:
            logger.warning(f"Failed to read /etc/os-release from {self.hostname}")

        return os_release_dict

    def get_deployed_testbeds(self):
        """
        Read and parse testbeds.json to get testbeds deployed on server.

        Returns:
            dict: Dictionary containing deployed testbeds information,
                  or empty dict if file doesn't exist or cannot be parsed
        """
        logger.debug(f"Reading deployed testbeds from {self.hostname}")

        result = self.command(
            f"cat {self.SONIC_TESTBED_FILE}",
            task_directives={"become": True},
            module_ignore_errors=True
        )

        if result.get("failed", False):
            logger.debug(f"No testbeds file found on {self.hostname} or access denied")
            return {}

        try:
            testbeds = json.loads(result["stdout"])
            testbed_count = len(testbeds.get("testbeds", {}))
            logger.debug(f"Found {testbed_count} deployed testbed(s) on {self.hostname}")
            return testbeds
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in testbeds file on {self.hostname}: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error reading testbeds from {self.hostname}: {e}")
            return {}
