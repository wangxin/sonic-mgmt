import json
import logging

from .base import AnsibleHost, AnsibleHosts
from .config import CONSTANTS as C
from .testbed import Testbed, get_testbed
from .inventory import generate_group_inventory_file


logger = logging.getLogger(__name__)


def get_all_deployed_testbeds(servers) -> dict[str, dict]:
    """
    Get all deployed testbeds on the given servers.

    Args:
        servers: AnsibleHosts object representing the servers

    Returns:
        Dictionary mapping server names to their deployed testbeds
    """
    logger.debug(f"Querying deployed testbeds from {len(servers)} server(s)")

    raw_all_deployed_testbeds = servers.shell(
        f'cat {C.SERVER_TESTBEDS_FILE}',
        module_ignore_errors=True,
        task_directives={'become': True}
    )

    deployed_testbeds = {}
    for server_name, result in raw_all_deployed_testbeds.items():
        if result['rc'] != 0:
            # Could not read the testbeds file on this server
            logger.debug(f"Server '{server_name}' has no testbeds file or is not accessible")
            continue

        try:
            deployed_testbeds[server_name] = json.loads(result['stdout'])
            testbed_count = len(deployed_testbeds[server_name].get('testbeds', {}))
            logger.debug(f"Server '{server_name}' has {testbed_count} deployed testbed(s)")
        except json.JSONDecodeError:
            # Invalid JSON content
            logger.warning(f"Server '{server_name}' has invalid testbeds file format")
            continue

    logger.info(f"Found {len(deployed_testbeds)} server(s) with deployed testbeds")
    return deployed_testbeds


def pick_server_for_deployment(
        servers: AnsibleHosts,
    ) -> str | None:
    """
    Pick the server with the least load for deployment.

    Args:
        servers: AnsibleHosts object representing the candidate servers

    Returns:
        The name of the selected server, or None if no suitable server found

    Algorithm:
        Default algorithm calculates a weighted load score for each server:
        - CPU usage: 40% weight
        - Memory usage: 30% weight
        - 1-minute load average (normalized by CPU cores): 20% weight
        - Running processes (normalized by total processes): 10% weight

        The server with the lowest total score is selected.
    """
    logger.info(f"Evaluating load on {len(servers)} server(s) to select deployment target")

    # Collect server load facts from all servers
    load_results = servers.server_load_facts(
        module_ignore_errors=True
    )

    # Parse load data for each server
    load_data = {}
    for server_name, result in load_results.items():
        if result.get('failed', False) or 'server_load' not in result:
            # Skip servers where we couldn't get load info
            logger.warning(f"Could not get load info from server '{server_name}'")
            continue

        load_data[server_name] = result['server_load']

    # If no servers have valid load data, return None
    if not load_data:
        logger.error("No servers provided valid load data")
        return None

    # Algorithm: Calculate weighted load score for each server
    server_scores = {}

    for server_name, load_info in load_data.items():
        # Extract metrics with safe defaults
        cpu_usage = load_info.get('cpu', {}).get('usage_percent', 0)
        memory_usage = load_info.get('memory', {}).get('used_percent', 0)

        # Normalize load average by number of CPU cores
        load_avg_1min = load_info.get('load_average', {}).get('one_min', 0)
        cpu_cores = load_info.get('cpu', {}).get('cores', 1)
        normalized_load = (load_avg_1min / cpu_cores * 100) if cpu_cores > 0 else 0

        # Normalize running processes
        processes = load_info.get('processes', {})
        total_procs = processes.get('total', 1)
        running_procs = processes.get('running', 0)
        proc_ratio = (running_procs / total_procs * 100) if total_procs > 0 else 0

        # Calculate weighted score (lower is better)
        # Weights: CPU=40%, Memory=30%, Load=20%, Processes=10%
        score = (
            cpu_usage * 0.4 +
            memory_usage * 0.3 +
            normalized_load * 0.2 +
            proc_ratio * 0.1
        )

        server_scores[server_name] = score
        logger.debug(
            f"Server '{server_name}': score={score:.2f} "
            f"(CPU={cpu_usage:.1f}%, Mem={memory_usage:.1f}%, "
            f"Load={load_avg_1min:.2f}/{cpu_cores}cores, Procs={running_procs}/{total_procs})"
        )

    # Return the server with the lowest score
    if server_scores:
        selected = min(server_scores, key=server_scores.get)
        logger.info(f"Selected server '{selected}' with load score {server_scores[selected]:.2f}")
        return selected

    logger.error("No servers available for deployment")
    return None


def deploy_testbed(
        testbed_file: str,
        testbed_name: str,
        neighbor_type: str = "ceos",
        server: str | None = None,
    ):
    """
    Deploy a testbed to a server.

    Args:
        testbed_file: Path to testbed configuration file
        testbed_name: Name of the testbed to deploy
        neighbor_type: Type of neighbor devices (default: "ceos")
        server: Target server name (optional, will auto-select if not provided)
    """
    logger.info(f"Starting deployment of testbed '{testbed_name}' from '{testbed_file}'")

    # Is this testbed deployed on any server?
    # If yes, check deployment status
        # If status OK, just return
        # If status not OK, ask user to undeploy firstly
    # If no, select a server to deploy
        # Check if the server meets requirements, like have all dependencies installed
        # Allocate testbed index on this server, allocate PTF of the testbed to this server
        #

    # Initialize the testbed object
    testbed: Testbed = get_testbed(testbed_file, testbed_name)
    if testbed is None:
        raise ValueError(f"Testbed '{testbed_name}' not found in file '{testbed_file}'")

    logger.debug(f"Loaded testbed configuration: group={testbed.group}, type={testbed.topology}")

    # Prepare the group inventory file
    logger.debug(f"Generating group inventory file for group '{testbed.group}'")
    group_inventory_file = generate_group_inventory_file(testbed.group, refresh=True)

    # Check if the testbed is deployed on any server
    if server is None:
        # Server is not specified. Need to find out if the testbed is already deployed on any server
        logger.info("No server specified, checking existing deployments and selecting optimal server")
        servers = AnsibleHosts(group_inventory_file, 'server')  # All hosts under children 'server' in the generated inventory file
        deploy_testbeds = get_all_deployed_testbeds(servers)

        # If the testbed is already deployed on any server, raise error
        for server_name, deployed_testbeds in deploy_testbeds.items():
            testbeds_on_server = deployed_testbeds.get('testbeds', {})
            if testbed.name in testbeds_on_server:
                raise RuntimeError(f"Testbed '{testbed.name}' is already deployed on server '{server_name}'. Please undeploy it first before deploying again.")

        # If the testbed is not deployed on any server, select a server to deploy
        selected_server = pick_server_for_deployment(servers)

        if selected_server is None:
            raise RuntimeError("Failed to select a suitable server for deployment")

        logger.info(f"Auto-selected server '{selected_server}' for deployment")
    else:
        logger.info(f"Using specified server '{server}' for deployment")
        selected_server = server

    # Prepare the server AnsibleHost object
    server = AnsibleHost(group_inventory_file, selected_server)

