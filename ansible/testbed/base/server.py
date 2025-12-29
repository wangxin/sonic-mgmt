import json
import logging
import contextlib
from functools import cached_property

from .ansible_hosts import AnsibleHost
from ..config import CONSTANTS as C

logger = logging.getLogger(__name__)


class TestServer(AnsibleHost):
    """
    Represents a test server that hosts testbeds.
    """

    # Server file paths
    TESTBEDS_FILE = C.SERVER_TESTBEDS_FILE  # /var/run/sonic/testbeds.json
    SERVER_READY_FILE = "/var/run/sonic/server_ready"

    # Required packages for testbed server
    REQUIRED_PACKAGES = [
        "apt-transport-https",
        "bridge-utils",
        "ca-certificates",
        "curl",
        "cloud-image-utils",
        "ifupdown",
        "iproute2",
        "libvirt-clients",
        "libvirt-daemon-system",
        "net-tools",
        "openvswitch-switch",
        "python3-libvirt",
        "python3-pip",
        "qemu",
        "qemu-kvm",
        "qemu-system-x86",
        "qemu-utils",
        "software-properties-common",
        "util-linux",
        "virtinst",
        "vlan",
    ]

    def __init__(self, inventory, pattern, hostvars={}, options={}):
        super(TestServer, self).__init__(inventory, pattern, hostvars=hostvars, options=options)

    @property
    def server_ready(self):
        """
        Check if the server is ready for testbed deployment.

        Returns:
            bool: True if server ready marker file exists, False otherwise

        Note: This property is not cached and checks the file on every access.
        """
        logger.debug(f"Checking server ready status on {self.hostname}")

        result = self.stat(
            path=self.SERVER_READY_FILE,
            module_ignore_errors=True
        )

        is_ready = not result.get("failed", False) and result.get("stat", {}).get("exists", False)
        logger.debug(f"Server {self.hostname} ready status: {is_ready}")

        return is_ready

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
            f"cat {self.TESTBEDS_FILE}",
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

    def _check_ubuntu_version(self):
        """
        Check if the Ubuntu version meets the minimum requirement (22.04).

        Raises:
            Exception: If the OS is not Ubuntu or version is older than 22.04
        """
        logger.info(f"Checking Ubuntu version on {self.hostname}")

        os_info = self.os_release
        os_id = os_info.get("ID", "").lower()
        version_id = os_info.get("VERSION_ID", "")

        # Check if it's Ubuntu
        if os_id != "ubuntu":
            error_msg = f"Server {self.hostname} is not running Ubuntu (detected: {os_info.get('PRETTY_NAME', 'unknown')}). Ubuntu 22.04 or later is required."
            logger.error(error_msg)
            # Delete server ready file if it exists
            self._delete_server_ready_file()
            raise Exception(error_msg)

        # Parse version (e.g., "22.04" -> [22, 4])
        try:
            version_parts = [int(part) for part in version_id.split(".")]
            min_version_parts = [22, 4]

            # Compare version (22.04 minimum)
            if version_parts < min_version_parts:
                error_msg = f"Server {self.hostname} is running Ubuntu {version_id}, but Ubuntu 22.04 or later is required."
                logger.error(error_msg)
                # Delete server ready file if it exists
                self._delete_server_ready_file()
                raise Exception(error_msg)

            logger.info(f"Ubuntu version {version_id} meets minimum requirement (22.04) on {self.hostname}")

        except (ValueError, AttributeError) as e:
            error_msg = f"Unable to parse Ubuntu version on {self.hostname}: {version_id}"
            logger.error(error_msg)
            # Delete server ready file if it exists
            self._delete_server_ready_file()
            raise Exception(error_msg) from e

    def _delete_server_ready_file(self):
        """
        Delete the server ready marker file if it exists.

        This is called when server setup fails or requirements are not met.
        """
        logger.debug(f"Deleting server ready marker file at {self.SERVER_READY_FILE}")

        self.file(
            path=self.SERVER_READY_FILE,
            state="absent",
            task_directives={"become": True},
            module_ignore_errors=True
        )

    def _install_packages(self):
        """
        Install required packages using apt.

        This private method installs all packages listed in REQUIRED_PACKAGES
        using apt with a lock timeout.

        Raises:
            Exception: If package installation fails
        """
        logger.info(f"Installing {len(self.REQUIRED_PACKAGES)} required packages on {self.hostname}")

        self.apt(
            name=self.REQUIRED_PACKAGES,
            state="present",
            update_cache=True,
            lock_timeout=600,  # Wait up to 10 minutes for apt lock
            task_directives={"become": True}
        )

        logger.info(f"Successfully installed required packages on {self.hostname}")

    def _install_docker(self):
        """
        Install Docker on the server.

        This private method checks if Docker is properly installed and installs
        it if necessary.

        Raises:
            Exception: If Docker installation fails
        """
        logger.info(f"Checking Docker installation on {self.hostname}")

        # Check if Docker is already installed and working
        result = self.command(
            "docker --version && docker ps",
            module_ignore_errors=True,
            task_directives={"become": True}
        )

        if not result.get("failed", False):
            logger.info(f"Docker is already properly installed on {self.hostname}")
            return

        logger.info(f"Docker not found or not working properly, installing on {self.hostname}")

        # Add Docker's official GPG key and repository, then install Docker
        self.shell(
            "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg",
            task_directives={"become": True}
        )

        self.shell(
            'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null',
            task_directives={"become": True}
        )

        self.apt(
            name=["docker-ce", "docker-ce-cli", "containerd.io"],
            state="present",
            update_cache=True,
            lock_timeout=600,
            task_directives={"become": True}
        )

        logger.info(f"Successfully installed Docker on {self.hostname}")

    def setup_server(self):
        """
        Setup the server by installing required packages and marking it as ready.

        This method:
        1. Checks Ubuntu version (minimum 22.04)
        2. Installs all required packages using apt (with lock timeout)
        3. Installs Docker
        4. Creates a marker file to indicate server is ready

        Raises:
            Exception: If Ubuntu version check fails, package installation fails,
                      or file creation fails
        """
        logger.info(f"Setting up server {self.hostname}")

        # Check Ubuntu version first
        self._check_ubuntu_version()

        # Install required packages
        self._install_packages()

        # Install Docker
        self._install_docker()

        # Create server ready marker file
        logger.debug(f"Creating server ready marker file at {self.SERVER_READY_FILE}")

        # Ensure directory exists and write the marker file
        self.shell(
            f"mkdir -p $(dirname {self.SERVER_READY_FILE}) && echo '1' > {self.SERVER_READY_FILE}",
            task_directives={"become": True}
        )

        logger.info(f"Server {self.hostname} setup completed successfully")
