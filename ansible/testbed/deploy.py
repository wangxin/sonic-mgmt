import json
import logging

from .base import AnsibleHosts
from .base import AnsibleLocalhost
from .base import TestServer
from .config import CONSTANTS as C
from .testbed import Testbed, get_testbed
from .inventory import generate_group_inventory_file, generate_testbed_inventory_file
from .topology import get_topology_definition
from .allocate import allocate_testbed_resources


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

    raw_all_deployed_testbeds = servers.server_testbeds(
        operation='get',
        testbeds_json_file=C.SERVER_TESTBEDS_FILE,
        module_ignore_errors=True
    )

    deployed_testbeds = {}
    for server_name, result in raw_all_deployed_testbeds.items():
        if result.get('failed', False):
            # Could not read the testbeds file on this server
            if not result.get('reachable', True):
                logger.warning(f"Server '{server_name}' is not reachable")
            else:
                logger.debug(f"Server '{server_name}' has no testbeds file or module error")
            continue

        # Extract testbeds list from the module result
        testbeds_list = result.get('testbeds', [])
        deployed_testbeds[server_name] = {'testbeds': testbeds_list}
        testbed_count = len(testbeds_list)
        logger.debug(f"Server '{server_name}' has {testbed_count} deployed testbed(s)")

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


def check_testbed_deployment_status(
        testbed_name: str,
        deployed_testbeds: dict[str, dict]
    ) -> str | None:
    """
    Check if a testbed is already deployed or being deployed on any server.

    Args:
        testbed_name: Name of the testbed to check
        deployed_testbeds: Dictionary mapping server names to their deployed testbeds

    Returns:
        Server name if testbed is currently being deployed (status='deploying'), None otherwise

    Raises:
        RuntimeError: If testbed is already fully deployed or in an error state
    """
    currently_deploying_on_server = None

    for server_name, deployed_testbeds_info in deployed_testbeds.items():
        for _deployed_testbed in deployed_testbeds_info.get('testbeds', []):
            if _deployed_testbed.get('testbed_name') == testbed_name:
                _deployed_testbed_status = _deployed_testbed.get('status', 'unknown')
                if _deployed_testbed_status == 'deployed':
                    raise RuntimeError(
                        f"Testbed '{testbed_name}' is already deployed on server '{server_name}'."
                    )
                elif _deployed_testbed_status == 'deploying':
                    currently_deploying_on_server = server_name
                    logger.warning(
                        f"Testbed '{testbed_name}' is currently being deployed on server '{server_name}'."
                    )
                else:
                    raise RuntimeError(
                        f"Testbed '{testbed_name}' is already present on server '{server_name}' "
                        f"with status '{_deployed_testbed_status}'. Please undeploy it first."
                    )

    return currently_deploying_on_server


def resolve_deployment_server(
        testbed_name: str,
        server_from_cli: str | None,
        server_from_testbed: str | None,
        currently_deploying_on_server: str | None
    ) -> str | None:
    """
    Resolve which server to use for testbed deployment.

    Args:
        testbed_name: Name of the testbed being deployed
        server_from_cli: Server specified from command line argument
        server_from_testbed: Server specified in testbed definition
        currently_deploying_on_server: Server where testbed is currently being deployed (if any)

    Returns:
        The resolved server name, or None if no server could be determined

    Raises:
        RuntimeError: If there's a conflict between specified server and ongoing deployment
    """
    # Start with command line argument, fall back to testbed definition
    server = server_from_cli if server_from_cli is not None else server_from_testbed

    if server is None:
        # No server specified in command line or testbed definition
        logger.info('No server specified in command line or testbed definition')
        if currently_deploying_on_server is not None:
            logger.info(
                f'Testbed {testbed_name} is currently being deployed on server {currently_deploying_on_server}.'
                f' Will try to continue deployment on the same server.'
            )
            return currently_deploying_on_server
        return None
    else:
        # Server is specified, check for conflicts with ongoing deployment
        if currently_deploying_on_server is not None and server != currently_deploying_on_server:
            raise RuntimeError(
                f"Testbed '{testbed_name}' is currently being deployed on server '{currently_deploying_on_server}'. "
                f"Cannot deploy to a different server '{server}' at the same time."
            )
        elif currently_deploying_on_server is not None and server == currently_deploying_on_server:
            logger.info(
                f'Testbed {testbed_name} is currently being deployed on server {currently_deploying_on_server}.'
                f' Will try to continue deployment on the same server.'
            )
        return server


def deploy_sonic_vm(
        testbed: Testbed,
        testbed_resources: dict,
        server_host: TestServer
    ):
    """
    Deploy SONiC VMs for the testbed.

    Args:
        testbed: Testbed object
        testbed_resources: Allocated resources for the testbed
        server_host: Server where VMs will be deployed

    Raises:
        RuntimeError: If VMs are already running or defined
    """
    logger.info(f"Deploying SONiC VMs for testbed '{testbed.name}'")

    # Get DUT information from allocated resources
    duts = testbed_resources.get('duts', {})
    if not duts:
        logger.warning(f"No DUTs found in testbed resources for '{testbed.name}'")
        return

    # Clean up any existing DUT VMs (destroy and undefine if they exist)
    with server_host:
        for dut_name in duts.keys():
            logger.debug(f"Cleaning up VM '{dut_name}' if it exists")

            # Destroy VM if running (ignore errors if not running)
            server_host.shell(
                f"virsh destroy '{dut_name}'",
                module_ignore_errors=True,
                task_directives={"become": True}
            )

            # Undefine VM if defined (ignore errors if not defined)
            server_host.shell(
                f"virsh undefine '{dut_name}'",
                module_ignore_errors=True,
                task_directives={"become": True}
            )

    logger.debug(f"VM '{dut_name}' cleanup completed, ready for deployment")

    for dut_name in duts.keys():
        server_host.virt(
            name=dut_name,
            xml="{{ lookup('template', '../roles/vm_set/templates/sonic.xml.j2') }}",
            command="define",
            uri="qemu:///system",
            task_directives={"become": True}
        )
        server_host.virt(
            name=dut_name,
            state="running",
            uri="qemu:///system",
            task_directives={"become": True}
        )


def deploy_ceos_neighbors():
    pass


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

    # Check if the testbed is already deployed on any server in the group
    servers = AnsibleHosts(group_inventory_file, 'server')
    deploy_testbeds = get_all_deployed_testbeds(servers)

    # Check deployment status and get server if testbed is currently being deployed
    currently_deploying_on_server = check_testbed_deployment_status(testbed.name, deploy_testbeds)

    if currently_deploying_on_server is None:
        logger.info(f"Testbed '{testbed.name}' is not currently deployed on any server, continuing deployment")
    else:
        logger.info(f"Testbed '{testbed.name}' has incomplete deployment on server '{currently_deploying_on_server}'")

    # Resolve which server to use for deployment
    resolved_server = resolve_deployment_server(
        testbed.name,
        server,
        testbed.server,
        currently_deploying_on_server
    )

    if resolved_server is None:
        # Server is not specified anywhere. No previous unfinished deployment. Pick a server automatically.
        logger.info("No server specified. No previous unfinished deployment. Pick a server automatically.")
        selected_server = pick_server_for_deployment(servers)

        if selected_server is None:
            raise RuntimeError("Failed to select a suitable server for deployment")

        logger.info(f"Auto-selected server '{selected_server}' for deployment")
    else:
        logger.info(f"Using server '{resolved_server}' for deployment")
        selected_server = resolved_server

    # Prepare objects and gather facts for deployment
    server_host = TestServer(group_inventory_file, selected_server)
    localhost = AnsibleLocalhost(group_inventory_file)

    # Setup the server (check Ubuntu version, install packages, install Docker, etc.)
    logger.info(f"Setting up server '{selected_server}' before deployment")
    server_host.setup_server()

    # Allocate testbed index on the server
    # Testbed name is not stored in the server testbeds file yet, only testbed index is stored for now.
    # After testbed is fully deployed, we will update the testbeds file with full info, including testbed name.
    logger.info(f"Allocating testbed index for '{testbed.name}' on server '{selected_server}'")
    testbed_index = server_host.server_testbeds(
        operation='allocate',
        testbeds_json_file=C.SERVER_TESTBEDS_FILE,
        testbed_name=testbed.name,
        task_directives={'become': True}
    ).get('testbed_index')

    topology_definition = get_topology_definition(testbed.topology)

    testbed_resources = allocate_testbed_resources(
        testbed,
        testbed_index,
        topology_definition
    )
    logger.info(f"Successfully allocated testbed resources: {json.dumps(testbed_resources, indent=2)}")

    # Generate testbed inventory file
    logger.info(f"Generating testbed inventory file for '{testbed.name}'")
    testbed_inventory_file = generate_testbed_inventory_file(
        testbed=testbed,
        testbed_resources=testbed_resources,
        selected_server=selected_server,
        refresh=True
    )
    logger.info(f"Testbed inventory file generated: {testbed_inventory_file}")

    # If KVM testbed, bring up the SONiC VM
    if testbed.type == "kvm":
        deploy_sonic_vm(testbed, testbed_resources, server_host)

    # if remote type is "ceos", deploy ceos neighbors
    if neighbor_type == "ceos":
        deploy_ceos_neighbors()

    # Deploy PTF container

    # Deploy the
