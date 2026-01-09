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

    # Required packages for testbed server by Ubuntu version
    REQUIRED_PACKAGES = {
        "22.04": [
            "apt-transport-https",
            "bridge-utils",
            "ca-certificates",
            "curl",
            "ifupdown",
            "iproute2",
            "libvirt-clients",
            "libvirt-dev",
            "libvirt-daemon-system",
            "net-tools",
            "openvswitch-switch",
            "pkg-config",
            "python3",
            "python-is-python3",
            "python3-dev",
            "python3-pip",
            "python3-venv",
            "qemu-system-x86",
            "software-properties-common",
            "util-linux",
            "virtinst",
            "vlan",
        ],
        "24.04": [
            "apt-transport-https",
            "bridge-utils",
            "ca-certificates",
            "curl",
            "ifupdown",
            "iproute2",
            "libvirt-clients",
            "libvirt-dev",
            "libvirt-daemon-system",
            "net-tools",
            "openvswitch-switch",
            "pkg-config",
            "python3",
            "python-is-python3",
            "python3-dev",
            "python3-pip",
            "python3-venv",
            "qemu-system-x86",
            "software-properties-common",
            "util-linux",
            "virtinst",
            "vlan",
        ],
    }

    # Required Python pip packages by Ubuntu version
    REQUIRED_PIP_PACKAGES = {
        "22.04": [
            "libvirt-python",
            "docker",
            "lxml",
        ],
        "24.04": [
            "libvirt-python",
            "docker",
            "lxml",
        ],
    }

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
            list: List of deployed testbeds (each testbed is a dict),
                  or empty list if file doesn't exist or cannot be parsed
        """
        logger.debug(f"Reading deployed testbeds from {self.hostname}")

        result = self.server_testbeds(
            operation='get',
            testbeds_json_file=self.TESTBEDS_FILE,
            module_ignore_errors=True
        )

        if result.get("failed", False):
            logger.debug(f"No testbeds file found on {self.hostname} or access denied")
            return []

        # Extract testbeds list from the module result
        testbeds_list = result.get("testbeds", [])
        testbed_count = len(testbeds_list)
        logger.debug(f"Found {testbed_count} deployed testbed(s) on {self.hostname}")

        return testbeds_list

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
        for the detected Ubuntu version using apt with a lock timeout.

        Raises:
            Exception: If package installation fails or version not supported
        """
        version_id = self.os_release.get("VERSION_ID", "")
        packages = self.REQUIRED_PACKAGES.get(version_id)

        if not packages:
            raise Exception(f"Unsupported Ubuntu version: {version_id}. Supported versions: {list(self.REQUIRED_PACKAGES.keys())}")

        logger.info(f"Installing {len(packages)} required packages for Ubuntu {version_id} on {self.hostname}")

        self.apt(
            name=packages,
            state="present",
            update_cache=True,
            lock_timeout=600,  # Wait up to 10 minutes for apt lock
            task_directives={"become": True}
        )

        logger.info(f"Successfully installed required packages on {self.hostname}")

    def _install_pip_packages(self):
        """
        Install Python pip packages.

        For Ubuntu 24.04, installs packages in a virtual environment at /opt/venv.
        For Ubuntu 22.04, installs packages to the default location.
        Installs packages listed in REQUIRED_PIP_PACKAGES for the detected version.

        Raises:
            Exception: If pip package installation fails or version not supported
        """
        version_id = self.os_release.get("VERSION_ID", "")
        packages = self.REQUIRED_PIP_PACKAGES.get(version_id)

        if not packages:
            raise Exception(f"Unsupported Ubuntu version: {version_id}. Supported versions: {list(self.REQUIRED_PIP_PACKAGES.keys())}")

        logger.info(f"Installing {len(packages)} Python pip packages for Ubuntu {version_id} on {self.hostname}")

        if version_id == "24.04":
            logger.info(f"Ubuntu 24.04 detected, installing pip packages to /opt/venv")

            # Create virtual environment at /opt/venv
            self.shell(
                "python3 -m venv /opt/venv",
                task_directives={"become": True}
            )

            # Update PATH to use /opt/venv/bin globally for all users and sessions
            logger.info(f"Updating PATH to use /opt/venv/bin for Ubuntu 24.04")

            # Update /etc/environment for all sessions (SSH, cron, systemd services, login/non-login shells)
            self.lineinfile(
                path="/etc/environment",
                regexp="^PATH=",
                line='PATH="/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"',
                task_directives={"become": True}
            )

            # Update sudoers secure_path to include /opt/venv/bin for sudo commands
            self.lineinfile(
                path="/etc/sudoers.d/venv",
                regexp="^Defaults\\s+secure_path=",
                line='Defaults secure_path="/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"',
                create=True,
                mode="0440",
                validate="/usr/sbin/visudo -cf %s",
                task_directives={"become": True}
            )

            # Install packages in the virtual environment (after PATH is configured)
            packages_str = " ".join(packages)
            self.shell(
                f"/opt/venv/bin/pip install {packages_str}",
                task_directives={"become": True}
            )

            logger.info(f"Successfully installed pip packages to /opt/venv on {self.hostname}")
        else:
            logger.info(f"Ubuntu {version_id} detected, installing pip packages to default location")

            # Install packages using system pip
            self.pip(
                name=packages,
                state="present",
                executable="pip3",
                task_directives={"become": True}
            )

            logger.info(f"Successfully installed pip packages on {self.hostname}")

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

        # Add the current user to the docker group to allow docker commands without sudo
        logger.debug(f"Adding user to docker group on {self.hostname}")
        self.shell("usermod -aG docker $USER && newgrp docker", task_directives={"become": True})

        # Configure Docker daemon (enable IPv6 and overlay2 storage driver)
        logger.info(f"Configuring Docker daemon on {self.hostname}")
        daemon_config = {
            "ipv6": True,
            "fixed-cidr-v6": "fd00::/80",
            "storage-driver": "overlay2"
        }

        self.copy(
            content=json.dumps(daemon_config, indent=2),
            dest="/etc/docker/daemon.json",
            mode="0644",
            task_directives={"become": True}
        )

        # Restart Docker to apply configuration
        logger.debug(f"Restarting Docker service to apply configuration")
        self.systemd(
            name="docker",
            state="restarted",
            task_directives={"become": True}
        )

        logger.info(f"Successfully installed and configured Docker on {self.hostname}")

    def setup_server(self, force=False):
        """
        Setup the server by installing required packages and marking it as ready.

        Args:
            force (bool): If True, force setup even if server is already marked as ready.
                         Defaults to False.

        This method:
        1. Checks if server is already ready (returns early if yes, unless force=True)
        2. Checks Ubuntu version (minimum 22.04)
        3. Installs all required packages using apt (with lock timeout)
        4. Installs pip packages
        5. Installs Docker
        6. Creates a marker file to indicate server is ready

        Raises:
            Exception: If Ubuntu version check fails, package installation fails,
                      or file creation fails
        """
        logger.info(f"Setting up server {self.hostname}")

        # Check if server is already ready
        if self.server_ready and not force:
            logger.info(f"Server {self.hostname} is already ready, skipping setup")
            return

        if force:
            logger.info(f"Force setup enabled, proceeding with setup even if server is ready")

        # Check Ubuntu version first
        self._check_ubuntu_version()

        # Install required packages
        self._install_packages()

        # Install pip packages
        self._install_pip_packages()

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
