import json
import logging
import ipaddress
import yaml

from pathlib import Path
from natsort import natsorted
from jinja2 import Environment, FileSystemLoader
from ansible.plugins.filter.core import FilterModule as CoreFilterModule
try:
    # Import all filter modules from ansible.utils collection
    from ansible_collections.ansible.utils.plugins.filter.ipaddr import FilterModule as IpaddrFilterModule
    from ansible_collections.ansible.utils.plugins.filter.ipv4 import FilterModule as Ipv4FilterModule
    from ansible_collections.ansible.utils.plugins.filter.ipv6 import FilterModule as Ipv6FilterModule
except ImportError:
    IpaddrFilterModule = None
    Ipv4FilterModule = None
    Ipv6FilterModule = None

from .base import AnsibleHosts
from .base import AnsibleLocalhost
from .base import TestServer
from .settings import CONSTANTS as C
from .testbed import Testbed, get_testbed
from .inventory import generate_group_inventory_file
from .inventory import generate_testbed_inventory_file
from .inventory import get_ansible_var
from .topology import get_topology_definition
from .allocate import allocate_testbed_resources


logger = logging.getLogger(__name__)

# Network base container image for cEOS neighbors
NET_IMAGE = "alpine:latest"


def _get_all_deployed_testbeds(servers) -> dict[str, dict]:
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


def _pick_server_for_deployment(
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


def _check_testbed_deployment_status(
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


def _resolve_deployment_server(
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


def _deploy_sonic_vm(
        testbed: Testbed,
        testbed_resources: dict,
        server_host: TestServer,
        dut_hosts: AnsibleHosts,
        localhost: AnsibleLocalhost
    ) -> dict[str, str]:
    """
    Deploy SONiC VMs for the testbed.

    Args:
        testbed: Testbed object
        testbed_resources: Allocated resources for the testbed
        server_host: Server where VMs will be deployed
        localhost: Ansible localhost object

    Returns:
        Dictionary mapping DUT names to their sonic_kickstart async job IDs

    Raises:
        RuntimeError: If VMs are already running or defined
    """
    logger.info(f"Deploying SONiC VMs for testbed '{testbed.name}'")

    # Get DUT information from allocated resources
    duts = testbed_resources.get('duts', {})
    if not duts:
        logger.warning(f"No DUTs found in testbed resources for '{testbed.name}'")
        return {}

    # Dictionary to store async job IDs for sonic_kickstart tasks
    kickstart_jids = {}

    # Clean up any existing DUT VMs (destroy and undefine if they exist)
    with server_host:
        for dut_host in testbed.duts:
            logger.debug(f"Cleaning up VM '{dut_host}' if it exists")

            # Destroy VM if running (ignore errors if not running)
            server_host.shell(
                f"virsh destroy '{dut_host}'",
                module_ignore_errors=True,
                task_directives={"become": True}
            )

            # Undefine VM if defined (ignore errors if not defined)
            server_host.shell(
                f"virsh undefine '{dut_host}'",
                module_ignore_errors=True,
                task_directives={"become": True}
            )

    logger.debug(f"VM '{dut_host}' cleanup completed, ready for deployment")

    server_home_folder = Path(server_host.shell("echo $HOME")['stdout'].strip())
    disk_folder = server_home_folder / 'sonic-vm' / 'disks'
    image_folder = server_home_folder / 'sonic-vm' / 'images'

    # Ensure disk folder exists
    with server_host:
        server_host.file(
            path=str(disk_folder),
            state="directory",
            mode="0755",
        )
        server_host.file(
            path=str(image_folder),
            state="directory",
            mode="0755",
        )

    for dut_host in dut_hosts:

        dut_hwsku = dut_host.visible_vars.get('hwsku', '')
        dut_asic_type = dut_host.visible_vars.get('asic_type', '')
        dut_num_asics = dut_host.visible_vars.get('num_asics', 1)

        dut_disk_image = Path(server_home_folder) / 'sonic-vm' / 'disks'/ f'sonic_{dut_host}.img'
        if dut_asic_type == 'vpp':
            src_disk_image = Path(image_folder) / 'sonic-vpp.img'
        else:
            src_disk_image = Path(image_folder) / 'sonic-vs.img'

        # Check if DUT disk image exists on server
        disk_stat = server_host.stat(path=str(dut_disk_image))
        if not disk_stat.get('stat', {}).get('exists', False):
            logger.info(f"DUT disk image '{dut_disk_image}' does not exist, copying from '{src_disk_image}'")
            server_host.copy(
                src=str(src_disk_image),
                dest=str(dut_disk_image),
                remote_src=True,
            )
        else:
            logger.debug(f"DUT disk image '{dut_disk_image}' already exists, skipping copy")

        port_alias = localhost.port_alias(
            hwsku=dut_hwsku,
            num_asic=dut_num_asics
        ).get('ansible_facts', {}).get('port_alias', [])

        # Start sonic kvm vm
        logger.info(f"Defining and starting SONiC VM '{dut_host}' on server '{server_host.hostname}'")
        sonic_vm_vars = {
            "dut_name": dut_host,
            "hwsku": dut_hwsku,
            "asic_type": dut_asic_type,
            "disk_image": dut_disk_image,
            "serial_port": testbed_resources['duts'][dut_host]['serial_port'],
            "port_alias": port_alias,
            "fp_mtu_size": 9216,
            "dedicated_mgmt_port": True
        }
        server_host.update_extra_vars(sonic_vm_vars)
        server_host.virt(
            name=dut_host,
            xml="{{ lookup('template', '../roles/vm_set/templates/sonic.xml.j2') }}",
            command="define",
            uri="qemu:///system",
            task_directives={"become": True}
        )
        server_host.virt(
            name=dut_host,
            state="running",
            uri="qemu:///system",
            task_directives={"become": True}
        )

        # Store front panel ports info
        num_ports = len(port_alias)
        fp_ports = [f"{dut_host}-{i}" for i in range(num_ports)]
        testbed_resources['duts'][dut_host]['fp_ports'] = fp_ports
        logger.debug(f"Stored {num_ports} front panel ports for '{dut_host}': {fp_ports}")

        # Calculate management gateway (first IP in subnet)
        dut_mgmt_ip = testbed_resources['duts'][dut_host]['ipv4']
        mgmt_network = ipaddress.ip_network(dut_mgmt_ip, strict=False)
        mgmt_gw = str(next(mgmt_network.hosts()))

        # Start sonic_kickstart in async mode to configure SONiC VM in background
        logger.info(f"Starting async sonic_kickstart for '{dut_host}'")
        kickstart_result = server_host.sonic_kickstart(
            telnet_port=testbed_resources['duts'][dut_host]['serial_port'],
            login="{{ sonic_login }}",
            passwords="{{ sonic_default_passwords }}",
            hostname=dut_host,
            mgmt_ip=dut_mgmt_ip,
            mgmt_gw=mgmt_gw,
            new_password="{{ sonic_password }}",
            num_asic=dut_num_asics,
            task_directives={"async": 600, "poll": 0}
        )

        # Store the async job ID for later status checking
        jid = kickstart_result.get('ansible_job_id')
        if jid:
            kickstart_jids[dut_host] = jid
            logger.debug(f"sonic_kickstart for '{dut_host}' started with job ID: {jid}")
        else:
            logger.warning(f"No job ID returned for sonic_kickstart on '{dut_host}'")

    logger.info(f"All {len(duts)} SONiC VM(s) deployed and kickstart running in background")
    return kickstart_jids


def _deploy_ptf(
        server_host: TestServer,
        testbed_resources: dict,
        ptf_image: str = "docker-ptf:latest",
        memory: str = "32G",
        memory_swap: str = "64G",
    ):
    """
    Deploy PTF container on the server.

    Args:
        server_host: Server where PTF will be deployed
        testbed_resources: Allocated resources for the testbed
        ptf_image: PTF image name with tag (e.g., "docker-ptf:latest")
        memory: Memory limit for container
        memory_swap: Memory swap limit for container
    """
    ptf_name = next(iter(testbed_resources.get('ptf', {})), None)
    if ptf_name is None:
        logger.warning("No PTF found in testbed resources, skipping PTF deployment")
        return

    logger.info(f"Deploying PTF container '{ptf_name}' on server '{server_host.hostname}'")

    # Clean up any existing PTF container (stop and remove if it exists)
    logger.debug(f"Cleaning up existing PTF container '{ptf_name}' if it exists")
    with server_host:
        # Stop container if running (ignore errors if not running)
        server_host.docker_container(
            name=ptf_name,
            state="stopped",
            task_directives={"become": True, "ignore_errors": True}
        )

        # Remove container if it exists (ignore errors if not exists)
        server_host.docker_container(
            name=ptf_name,
            state="absent",
            task_directives={"become": True, "ignore_errors": True}
        )

    logger.debug(f"PTF container '{ptf_name}' cleanup completed, ready for deployment")

    # Get PTF docker registry from ansible variables
    ptf_docker_registry = server_host.get_visible_var('ptf_docker_registry', default='')

    # Construct full image path with registry if provided
    if ptf_docker_registry:
        full_ptf_image = f"{ptf_docker_registry}/{ptf_image}"
    else:
        full_ptf_image = ptf_image

    # Deploy PTF container
    logger.info(f"Starting PTF container '{ptf_name}' using image '{full_ptf_image}'")
    server_host.docker_container(
        name=ptf_name,
        image=full_ptf_image,
        pull="missing",
        state="started",
        restart="no",
        network_mode="none",
        detach=True,
        capabilities=["NET_ADMIN"],
        privileged=True,
        memory=memory,
        memory_swap=memory_swap,
        task_directives={"become": True}
    )

    # Post deployment configuration
    # Configure sysctl settings for PTF container
    logger.info(f"Configuring sysctl settings for PTF container '{ptf_name}'")
    sysctl_settings = {
        "net.ipv6.conf.all.disable_ipv6": "0",
        "net.ipv6.route.max_size": "168000",
        "net.ipv6.conf.default.accept_ra": "0"
    }

    with server_host:
        for key, value in sysctl_settings.items():
            server_host.shell(
                f"docker exec {ptf_name} sysctl -w {key}={value}",
                task_directives={"become": True}
            )

        # Ensure /sonic folder exists on PTF container
        server_host.shell(
            f"docker exec {ptf_name} mkdir -p /sonic",
            task_directives={"become": True}
        )

        # Store DUT type and asic type to PTF container. Some PTF scripts need this information.
        # For details, please refer to: https://github.com/sonic-net/sonic-mgmt/pull/12588
        for dut_name in testbed_resources.get('duts', {}).keys():
            dut_type = get_ansible_var(server_host.inventory, dut_name, 'type', default='')
            if dut_type:
                server_host.shell(
                    f"docker exec {ptf_name} sh -c 'echo {dut_type} > /sonic/dut_type.txt'",
                    task_directives={"become": True}
                )
            asic_type = get_ansible_var(server_host.inventory, dut_name, 'asic_type', default='')
            if asic_type:
                server_host.shell(
                    f"docker exec {ptf_name} sh -c 'echo {asic_type} > /sonic/asic_type.txt'",
                    task_directives={"become": True}
                )
            break  # Only need to check the first DUT

    logger.info(f"PTF container '{ptf_name}' deployed and configured successfully")


def _build_net_containers_compose_config(
        neighbors: dict,
        docker_registry: str
    ) -> dict:
    """
    Build Docker Compose configuration for network base containers.

    Args:
        neighbors: Dictionary of neighbor configurations
        docker_registry: Docker registry URL

    Returns:
        Docker Compose configuration dictionary
    """
    compose_config = {
        'version': '3.8',
        'services': {}
    }

    for neighbor_name in neighbors.keys():
        net_container_name = f"net_{neighbor_name}"

        compose_config['services'][net_container_name] = {
            'image': f"{docker_registry}/{NET_IMAGE}",
            'container_name': net_container_name,
            'network_mode': 'none',
            'privileged': True,
            'cap_add': ['NET_ADMIN'],
            'restart': 'no',
            'command': 'sleep infinity',
            'mem_limit': '16M'
        }

    return compose_config


def _deploy_ceos_network_containers(
        server_host: TestServer,
        testbed_resources: dict,
        testbed_name: str,
        docker_registry: str
    ):
    """
    Deploy network base containers for cEOS neighbors using Docker Compose.

    These containers provide network namespaces that cEOS containers will use.
    This approach allows setting up veth pairs before cEOS starts, avoiding hot-plug issues.

    Uses Docker Compose for parallel deployment - much faster than sequential container creation.

    Args:
        server_host: Server where network containers will be deployed
        testbed_resources: Allocated resources for the testbed
        testbed_name: Name of the testbed
        docker_registry: Docker registry URL
    """
    neighbors = testbed_resources.get('neighbors', {})
    if not neighbors:
        logger.info("No neighbors found in testbed resources, skipping network container deployment")
        return

    logger.info(f"Deploying network base containers for {len(neighbors)} neighbor(s) using Docker Compose")

    # Build docker-compose configuration
    compose_config = _build_net_containers_compose_config(neighbors, docker_registry)

    # Convert to YAML and write to server
    compose_yaml = yaml.dump(compose_config, default_flow_style=False, sort_keys=False)
    compose_file_path = f"/tmp/docker-compose-net-{testbed_name}.yml"

    logger.debug(f"Writing Docker Compose configuration to '{compose_file_path}'")
    server_host.copy(
        content=compose_yaml,
        dest=compose_file_path,
        mode='0644',
        task_directives={"become": True}
    )

    # Stop and remove existing containers using docker compose down
    logger.debug(f"Cleaning up existing network containers for testbed '{testbed_name}'")
    server_host.shell(
        f"docker compose -f {compose_file_path} down",
        task_directives={"become": True, "ignore_errors": True}
    )

    # Start all network containers in parallel using docker-compose up
    logger.info(f"Starting {len(neighbors)} network container(s) in parallel")
    server_host.shell(
        f"docker compose -f {compose_file_path} up -d",
        task_directives={"become": True}
    )

    logger.info(f"All {len(neighbors)} network base container(s) deployed successfully using Docker Compose")


def _build_ceos_image_from_orig(
        server_host: TestServer,
        ceos_image_orig: str,
        ceos_image: str
    ):
    """
    Build final cEOS image from the original image using Dockerfile template.

    Args:
        server_host: Server where the image will be built
        ceos_image_orig: Name of the original/base cEOS image
        ceos_image: Name of the final cEOS image to build
    """
    logger.info(f"Building Docker image '{ceos_image}' from '{ceos_image_orig}' using Dockerfile")

    # Create a temporary directory for the build context
    build_context_dir = f"/tmp/ceos_build_{ceos_image.replace(':', '_').replace('/', '_')}"
    server_host.file(
        path=build_context_dir,
        state="directory",
        mode="0755",
        task_directives={"become": True}
    )

    # Generate Dockerfile from template
    dockerfile_path = f"{build_context_dir}/Dockerfile"
    dockerfile_vars = {
        "ceos_image_orig": ceos_image_orig
    }
    server_host.update_extra_vars(dockerfile_vars)
    server_host.template(
        src="../roles/vm_set/templates/ceos_dockerfile.j2",
        dest=dockerfile_path,
        mode="0644",
        task_directives={"become": True}
    )

    # Build the Docker image
    server_host.docker_image(
        name=ceos_image,
        source="build",
        build={
            "path": build_context_dir,
            "pull": False
        },
        task_directives={"become": True}
    )

    # Clean up build context
    server_host.file(
        path=build_context_dir,
        state="absent",
        task_directives={"become": True}
    )

    logger.info(f"Successfully built Docker image '{ceos_image}' from '{ceos_image_orig}'")


def _prepare_ceos_image(server_host: TestServer):
    """
    Prepare cEOS image on the server.

    Downloads the cEOS image from specified URLs if it doesn't exist locally,
    and imports it into Docker.

    Args:
        server_host: Server where cEOS image will be prepared
    """
    logger.info(f"Preparing cEOS image on server '{server_host.hostname}'")

    # Get cEOS image related variables from ansible group vars
    ceos_image_filename = server_host.get_visible_var('ceos_image_filename')
    ceos_image_orig = server_host.get_visible_var('ceos_image_orig')
    ceos_image = server_host.get_visible_var('ceos_image')
    ceos_image_url = server_host.get_visible_var('ceos_image_url')
    skip_ceos_image_downloading = server_host.get_visible_var('skip_ceos_image_downloading', default=False)

    # Validate required variables
    required_vars = {
        'ceos_image_filename': ceos_image_filename,
        'ceos_image_orig': ceos_image_orig,
        'ceos_image': ceos_image,
        'ceos_image_url': ceos_image_url
    }

    missing_vars = [var_name for var_name, var_value in required_vars.items() if var_value is None]
    if missing_vars:
        raise ValueError(
            f"Missing required cEOS image variables: {', '.join(missing_vars)}. "
            f"Please check the 'ansible/group_vars/vm_host/ceos.yml' file."
        )

    logger.debug(f"cEOS image configuration: filename={ceos_image_filename}, orig={ceos_image_orig}, "
                 f"image={ceos_image}, urls={ceos_image_url}, skip_downloading={skip_ceos_image_downloading}")

    # Check if the final tagged docker image exists
    logger.debug(f"Checking if Docker image '{ceos_image}' exists on server")
    result = server_host.docker_image_info(
        name=ceos_image,
        task_directives={"become": True}
    )

    if result.get('images'):
        logger.info(f"Docker image '{ceos_image}' already exists, skipping preparation")
        return

    logger.debug(f"Docker image '{ceos_image}' not found")

    # Check if the original docker image exists
    logger.debug(f"Checking if Docker image '{ceos_image_orig}' exists on server")
    result = server_host.docker_image_info(
        name=ceos_image_orig,
        task_directives={"become": True}
    )

    if result.get('images'):
        logger.info(f"Docker image '{ceos_image_orig}' found, building '{ceos_image}' from it")
        _build_ceos_image_from_orig(server_host, ceos_image_orig, ceos_image)
        return
    else:
        logger.debug(f"Docker image '{ceos_image_orig}' not found")

        # Check if the cEOS image file exists on server
        server_home_folder = Path(server_host.shell("echo $HOME")['stdout'].strip())
        ceos_image_file_path = server_home_folder / 'images' / ceos_image_filename

        logger.debug(f"Checking if cEOS image file '{ceos_image_file_path}' exists on server")
        file_stat = server_host.stat(path=str(ceos_image_file_path))

        if file_stat.get('stat', {}).get('exists', False):
            logger.info(f"cEOS image file '{ceos_image_file_path}' found")
        else:
            logger.debug(f"cEOS image file '{ceos_image_file_path}' not found")
            if skip_ceos_image_downloading:
                raise RuntimeError(
                    f"cEOS image file '{ceos_image_file_path}' not found on server. "
                    f"Please manually download the cEOS image and place it at '{ceos_image_file_path}'. "
                    f"Alternatively, set 'skip_ceos_image_downloading: false' in 'ansible/group_vars/vm_host/ceos.yml' "
                    f"to enable automatic downloading."
                )

            # Automatic downloading is enabled, probe URLs to find working one
            logger.info(f"Probing {len(ceos_image_url)} URL(s) to find working download link")
            working_url = None

            for url in ceos_image_url:
                logger.debug(f"Probing URL: {url}")
                probe_result = server_host.uri(
                    url=url,
                    method="HEAD",
                    status_code=[200, 301, 302],
                    follow_redirects="safe",
                    task_directives={"ignore_errors": True}
                )

                if probe_result.get('status') == 200:
                    logger.info(f"Found working URL: {url}")
                    working_url = url
                    break
                else:
                    logger.debug(f"URL {url} returned status {probe_result.get('status', 'unknown')}, skipping")

            if working_url is None:
                raise RuntimeError(
                    f"No working download URL found for cEOS image. Tried {len(ceos_image_url)} URL(s). "
                    f"Please check the URLs defined in 'ansible/group_vars/vm_host/ceos.yml' or "
                    f"manually download the cEOS image and place it at '{ceos_image_file_path}'."
                )

            # Ensure images directory exists
            images_dir = ceos_image_file_path.parent
            server_host.file(
                path=str(images_dir),
                state="directory",
                mode="0755"
            )

            # Download the image file from working URL
            logger.info(f"Downloading cEOS image from {working_url} to {ceos_image_file_path}")
            server_host.get_url(
                url=working_url,
                dest=str(ceos_image_file_path),
                mode="0644",
                timeout=1800,  # 30 minutes timeout for large files
                task_directives={"become": True}
            )
            logger.info(f"Successfully downloaded cEOS image to {ceos_image_file_path}")

        # Import the image file into Docker as ceos_image_orig
        logger.info(f"Importing cEOS image file into Docker as '{ceos_image_orig}'")
        server_host.docker_image(
            name=ceos_image_orig,
            path=str(ceos_image_file_path),
            source="import",
            task_directives={"become": True}
        )
        logger.info(f"Successfully imported Docker image as '{ceos_image_orig}'")

    # At this point, ceos_image_orig exists but ceos_image does not
    # Build ceos_image from ceos_image_orig using Dockerfile template
    _build_ceos_image_from_orig(server_host, ceos_image_orig, ceos_image)


def _generate_ceos_startup_configs(
        server_host: TestServer,
        testbed: Testbed,
        testbed_resources: dict,
        topology_definition: dict,
        neighbor_type: str = "ceos"
    ):
    """
    Generate startup configuration files for cEOS neighbors.

    Args:
        server_host: Server where configuration files will be generated
        testbed: Testbed object
        testbed_resources: Allocated resources for the testbed
        topology_definition: Topology definition loaded from vars/topo_*.yml
        neighbor_type: Type of neighbor devices (default: "ceos")
    """
    neighbors = testbed_resources.get('neighbors', {})
    if not neighbors:
        logger.info("No neighbors found in testbed resources, skipping cEOS startup config generation")
        return

    logger.info(f"Generating startup configuration files for {len(neighbors)} cEOS neighbor(s)")

    # Parse base topology from testbed topology name (part before "_")
    base_topo = testbed.topology.split('_')[0] if '_' in testbed.topology else testbed.topology
    logger.debug(f"Base topology: {base_topo} (from testbed topology: {testbed.topology})")

    # Get swrole from topology definition
    swrole = topology_definition.get('configuration_properties', {}).get('common', {}).get('swrole')
    if swrole:
        logger.debug(f"Switch role for neighbors: {swrole}")
    else:
        logger.warning("No swrole found in topology definition")

    # Determine template file name and path
    template_name = f"{base_topo}-{swrole}.j2"
    template_dir = Path(__file__).parent.parent / 'roles' / 'eos' / 'templates'
    template_path = template_dir / template_name

    if not template_path.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")

    logger.debug(f"Using template: {template_path}")

    # Setup Jinja2 environment with Ansible filters
    jinja_env = Environment(loader=FileSystemLoader(str(template_dir)))

    # Add Ansible core filters
    core_filters = CoreFilterModule()
    jinja_env.filters.update(core_filters.filters())

    # Add ansible.utils filters with namespaced names
    utils_filter_modules = [
        IpaddrFilterModule,
        Ipv4FilterModule,
        Ipv6FilterModule
    ]

    for filter_module_class in utils_filter_modules:
        if filter_module_class:
            filter_module = filter_module_class()
            for filter_name, filter_func in filter_module.filters().items():
                # Register with both the short name and the full namespaced name
                jinja_env.filters[filter_name] = filter_func
                jinja_env.filters[f'ansible.utils.{filter_name}'] = filter_func

    # Load the template
    startup_config_template = jinja_env.get_template(template_name)

    # Build mapping between testbed_resources neighbor names and topology_definition neighbor hostnames
    # Both lists are natsorted to create 1-to-1 mapping
    neighbor_name_to_hostname = {}

    if topology_definition.get('configuration'):
        # Get neighbor hostnames from topology definition configurations
        topo_hostnames = natsorted(topology_definition['configuration'].keys())

        # Get neighbor names from testbed resources
        neighbor_names = natsorted(neighbors.keys())

        # Create mapping from neighbor name to hostname
        for neighbor_name, hostname in zip(neighbor_names, topo_hostnames):
            neighbor_name_to_hostname[neighbor_name] = hostname
            logger.debug(f"Mapped neighbor '{neighbor_name}' to hostname '{hostname}'")

    # Generate startup config for each neighbor
    for neighbor_name in neighbors.keys():
        config_file_path = f"{C.CEOS_IMAGE_MOUNT_DIR}/{neighbor_name}/startup-config"

        # Ensure the mount directory exists
        mount_dir = f"{C.CEOS_IMAGE_MOUNT_DIR}/{neighbor_name}"
        server_host.file(
            path=mount_dir,
            state="directory",
            mode="0755",
            task_directives={"become": True}
        )

        # Get hostname for this neighbor
        hostname = neighbor_name_to_hostname.get(neighbor_name)
        if not hostname:
            logger.warning(f"No hostname mapping found for neighbor '{neighbor_name}', skipping")
            continue

        # Parse neighbor management IP (CIDR format)
        neighbor_mgmt_ip = neighbors[neighbor_name]['ipv4']
        mgmt_interface = ipaddress.ip_interface(neighbor_mgmt_ip)

        # Calculate management gateway (first IP in subnet)
        mgmt_network = ipaddress.ip_network(neighbor_mgmt_ip, strict=False)
        vm_mgmt_gw = str(next(mgmt_network.hosts()))
        host_config = topology_definition.get('configuration', {}).get(hostname, {})

        # Calculate backplane interface name
        host_interfaces = host_config.get('interfaces', {})
        fp_interfaces = [intf for intf in host_interfaces.keys() if intf.startswith('Ethernet')]
        max_interface_num = len(fp_interfaces)
        bp_ifname = f"Ethernet{max_interface_num + 1}"

        topo_properties = topology_definition.get('properties', {})

        # Prepare template variables (isolated dict, won't affect server_host)
        template_vars = {
            'hostname': hostname,
            'ansible_host': str(mgmt_interface.ip),
            'mgmt_prefixlen': mgmt_interface.network.prefixlen,
            'vm_type': neighbor_type,
            'vm_mgmt_gw': vm_mgmt_gw,
            'bp_ifname': bp_ifname,
            'snmp_rocommunity': 'public',
            'configuration': topology_definition.get('configuration', {}),
            'props': topo_properties.get('common', {})
        }

        # Render template locally using Jinja2
        logger.debug(f"Rendering startup config for '{neighbor_name}' (hostname: {hostname})")
        config_content = startup_config_template.render(**template_vars)

        # Write rendered config to server
        logger.debug(f"Writing startup config to {config_file_path}")
        server_host.copy(
            content=config_content,
            dest=config_file_path,
            mode="0644",
            task_directives={"become": True}
        )

    logger.info(f"Successfully generated startup configs for {len(neighbors)} neighbor(s)")


def _build_ceos_containers_compose_config(
        neighbors: dict,
        ceos_image: str,
        memory: str = "2G",
        memory_swap: str = "4G"
    ) -> dict:
    """
    Build Docker Compose configuration for cEOS containers.

    Args:
        neighbors: Dictionary of neighbor configurations
        ceos_image: cEOS Docker image name with tag
        memory: Memory limit for container (default: "2G")
        memory_swap: Memory swap limit for container (default: "4G")

    Returns:
        Docker Compose configuration dictionary
    """
    compose_config = {
        'version': '3.8',
        'services': {}
    }

    for neighbor_name in neighbors.keys():
        ceos_container_name = f"ceos_{neighbor_name}"
        net_container_name = f"net_{neighbor_name}"

        compose_config['services'][ceos_container_name] = {
            'image': ceos_image,
            'container_name': ceos_container_name,
            'network_mode': f"container:{net_container_name}",
            'privileged': True,
            'cap_add': ['NET_ADMIN'],
            'restart': 'no',
            'command': '/sbin/init systemd.setenv=INTFTYPE=eth systemd.setenv=ETBA=1 systemd.setenv=SKIP_ZEROTOUCH_BARRIER_IN_SYSDBINIT=1 systemd.setenv=CEOS=1 systemd.setenv=EOS_PLATFORM=ceoslab systemd.setenv=container=docker systemd.setenv=MGMT_INTF=eth0',
            'environment': {
                'CEOS': '1',
                'EOS_PLATFORM': 'ceoslab',
                'container': 'docker',
                'ETBA': '1',
                'SKIP_ZEROTOUCH_BARRIER_IN_SYSDBINIT': '1',
                'INTFTYPE': 'eth',
                'MGMT_INTF': 'eth0'
            },
            'volumes': [
                f"{C.CEOS_IMAGE_MOUNT_DIR}/{neighbor_name}:/mnt/flash"
            ],
            'mem_limit': memory,
            'memswap_limit': memory_swap
        }

    return compose_config


def _deploy_ceos_containers(
        server_host: TestServer,
        testbed_resources: dict,
        testbed_name: str,
        memory: str = "2G",
        memory_swap: str = "4G"
    ):
    """
    Deploy cEOS neighbor containers using Docker Compose.

    These containers use the network namespace from the net base containers deployed earlier.
    Uses Docker Compose for parallel deployment.

    Args:
        server_host: Server where cEOS containers will be deployed
        testbed_resources: Allocated resources for the testbed
        testbed_name: Name of the testbed
        memory: Memory limit for container (default: "2G")
        memory_swap: Memory swap limit for container (default: "4G")
    """
    neighbors = testbed_resources.get('neighbors', {})
    if not neighbors:
        logger.info("No neighbors found in testbed resources, skipping cEOS container deployment")
        return

    # Get cEOS image from ansible variables
    ceos_image = server_host.get_visible_var('ceos_image')
    if ceos_image is None:
        raise ValueError(
            "Missing required variable 'ceos_image'. "
            "Please check the 'ansible/group_vars/vm_host/ceos.yml' file."
        )

    logger.info(f"Deploying cEOS containers for {len(neighbors)} neighbor(s) using Docker Compose with image '{ceos_image}'")

    # Build docker-compose configuration
    compose_config = _build_ceos_containers_compose_config(neighbors, ceos_image, memory, memory_swap)

    # Convert to YAML and write to server
    compose_yaml = yaml.dump(compose_config, default_flow_style=False, sort_keys=False)
    compose_file_path = f"/tmp/docker-compose-ceos-{testbed_name}.yml"

    logger.debug(f"Writing Docker Compose configuration to '{compose_file_path}'")
    server_host.copy(
        content=compose_yaml,
        dest=compose_file_path,
        mode='0644',
        task_directives={"become": True}
    )

    # Stop and remove existing containers using docker compose down
    logger.debug(f"Cleaning up existing cEOS containers for testbed '{testbed_name}'")
    server_host.shell(
        f"docker compose -f {compose_file_path} down",
        task_directives={"become": True, "ignore_errors": True}
    )

    # Start all cEOS containers in parallel using docker-compose up
    logger.info(f"Starting {len(neighbors)} cEOS container(s) in parallel")
    server_host.shell(
        f"docker compose -f {compose_file_path} up -d",
        task_directives={"become": True}
    )

    logger.info(f"All {len(neighbors)} cEOS container(s) deployed successfully using Docker Compose")


def _bind_topology_ceos(
        server_host: TestServer,
        testbed_resources: dict,
        topology_definition: dict,
        neighbor_type: str = "ceos"
):
    """
    Bind topology connections for cEOS neighbor type.

    Creates veth pairs, OVS bridges, and connects all components:
    - PTF container interfaces
    - Neighbor (cEOS) container interfaces
    - KVM DUT interfaces (if applicable)

    Args:
        server_host: TestServer object representing the target server
        testbed_resources: Allocated testbed resources dictionary
        topology_definition: Topology definition loaded from vars/topo_*.yml
        neighbor_type: Type of neighbor devices (default: "ceos")
    """
    logger.info("Binding topology connections for cEOS neighbors")

    result = server_host.testbed_topology(
        operation='deploy',
        topology_definition=topology_definition,
        testbed_resources=testbed_resources,
        neighbor_type=neighbor_type,
        task_directives={'become': True}
    )

    if result.get('failed', False):
        raise RuntimeError(f"Failed to bind topology: {result.get('msg', 'Unknown error')}")

    logger.info("Topology binding completed successfully")


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
    deployed_testbeds = _get_all_deployed_testbeds(servers)

    # Check deployment status and get server if testbed is currently being deployed
    currently_deploying_on_server = _check_testbed_deployment_status(testbed.name, deployed_testbeds)

    if currently_deploying_on_server is None:
        logger.info(f"Testbed '{testbed.name}' is not currently deployed on any server, continuing deployment")
    else:
        logger.info(f"Testbed '{testbed.name}' has incomplete deployment on server '{currently_deploying_on_server}'")

    # Resolve which server to use for deployment
    resolved_server = _resolve_deployment_server(
        testbed.name,
        server,
        testbed.server,
        currently_deploying_on_server
    )

    if resolved_server is None:
        # Server is not specified anywhere. No previous unfinished deployment. Pick a server automatically.
        logger.info("No server specified. No previous unfinished deployment. Pick a server automatically.")
        selected_server = _pick_server_for_deployment(servers)

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

    # Replace server_host with new inventory including testbed DUTs and PTF
    server_host = TestServer(testbed_inventory_file, selected_server)
    dut_hosts = AnsibleHosts(testbed_inventory_file, 'dut')

    # If KVM testbed, bring up the SONiC VM
    if testbed.type == "kvm":
        _deploy_sonic_vm(testbed, testbed_resources, server_host, dut_hosts, localhost)

    # Deploy PTF container
    _deploy_ptf(
        server_host,
        testbed_resources,
        ptf_image=testbed.ptf_image
    )

    # Get the server for deploying neighbor devices
    logger.info(f"Deploying neighbor devices of type '{neighbor_type}' for testbed '{testbed.name}'")
    # TODO: Add code to prepare server host for neighbor deployment, could be remote server.

    # if neighbor type is "ceos", deploy base net containers for neighbors firstly
    if neighbor_type == "ceos":
        _deploy_ceos_network_containers(
            server_host=server_host,
            testbed_resources=testbed_resources,
            testbed_name=testbed.name,
            docker_registry=server_host.get_visible_var('docker_registry', default='')
        )

    # Bind topology connections between DUTs, PTF, and neighbors
    if neighbor_type == "ceos":
        _bind_topology_ceos(
            server_host=server_host,
            testbed_resources=testbed_resources,
            topology_definition=topology_definition,
            neighbor_type=neighbor_type
        )

    if neighbor_type == "ceos":
        _generate_ceos_startup_configs(
            server_host=server_host,
            testbed=testbed,
            testbed_resources=testbed_resources,
            topology_definition=topology_definition,
            neighbor_type=neighbor_type
        )

    if neighbor_type == "ceos":
        # Prepare the ceos image on the server
        _prepare_ceos_image(server_host=server_host)
        _deploy_ceos_containers(
            server_host=server_host,
            testbed_resources=testbed_resources,
            testbed_name=testbed.name
        )

    # Update testbed info to server after deployment
    logger.info(f"Updating testbed info to server '{selected_server}'")
    testbed_info = {
        **testbed_resources,
        'status': 'deployed'
    }
    server_host.server_testbeds(
        operation='update',
        testbeds_json_file=C.SERVER_TESTBEDS_FILE,
        testbed_info=testbed_info,
        task_directives={'become': True}
    )


def _find_deployed_server(testbed_name: str, group_inventory_file: str, server: str | None = None):
    """
    Find which server has the testbed deployed.

    Args:
        testbed_name: Name of the testbed to find
        group_inventory_file: Path to group inventory file
        server: Optional server name to verify against

    Returns:
        tuple: (server_name, deployed_testbed_info)

    Raises:
        ValueError: If testbed not found or server mismatch
    """
    logger.info("Checking if testbed is deployed on any server in the group")
    servers = AnsibleHosts(group_inventory_file, 'server')
    deployed_testbeds = _get_all_deployed_testbeds(servers)

    # Find which server has this testbed
    found_server = None
    deployed_testbed_info = None
    for server_name, deployed_testbeds_info in deployed_testbeds.items():
        for deployed_testbed in deployed_testbeds_info.get('testbeds', []):
            if deployed_testbed.get('name') == testbed_name:
                found_server = server_name
                deployed_testbed_info = deployed_testbed
                logger.info(f"Found testbed '{testbed_name}' deployed on server '{server_name}'")
                break
        if found_server:
            break

    if found_server is None:
        raise ValueError(f"Testbed '{testbed_name}' is not deployed on any server")

    # If server is provided, verify it matches the found server
    if server is not None:
        if server != found_server:
            raise ValueError(
                f"Testbed '{testbed_name}' is deployed on server '{found_server}', "
                f"but you specified server '{server}'"
            )
        logger.debug(f"Verified testbed is on specified server '{server}'")
    else:
        logger.info(f"Auto-detected server '{found_server}' for undeployment")

    return found_server, deployed_testbed_info


def _undeploy_kvm_vms(server_host: TestServer, duts_info: dict):
    """
    Remove KVM virtual machines.

    Args:
        server_host: TestServer object for the target server
        duts_info: Dictionary of DUT VM information
    """
    if not duts_info:
        logger.debug("No DUTs found in deployed testbed info")
        return

    logger.info(f"Removing {len(duts_info)} KVM VM(s)")
    with server_host:
        for dut_name in duts_info.keys():
            logger.debug(f"Destroying and undefining VM '{dut_name}'")
            # Destroy VM if running
            server_host.shell(
                f"virsh destroy '{dut_name}'",
                task_directives={"become": True, "ignore_errors": True}
            )
            # Undefine VM
            server_host.shell(
                f"virsh undefine '{dut_name}'",
                task_directives={"become": True, "ignore_errors": True}
            )
    logger.info(f"Removed {len(duts_info)} KVM VM(s)")


def undeploy_testbed(
        testbed_file: str,
        testbed_name: str,
        neighbor_type: str = "ceos",
        server: str | None = None,
    ):
    """
    Undeploy a testbed from a server.

    Args:
        testbed_file: Path to testbed configuration file
        testbed_name: Name of the testbed to undeploy
        neighbor_type: Type of neighbor devices (default: "ceos")
        server: Target server name (optional, will auto-detect if not provided)
    """
    logger.info(f"Starting undeployment of testbed '{testbed_name}' from '{testbed_file}'")

    # Initialize the testbed object
    testbed: Testbed = get_testbed(testbed_file, testbed_name)
    if testbed is None:
        raise ValueError(f"Testbed '{testbed_name}' not found in file '{testbed_file}'")

    logger.debug(f"Loaded testbed configuration: group={testbed.group}, type={testbed.topology}")

    # Prepare the group inventory file
    logger.debug(f"Generating group inventory file for group '{testbed.group}'")
    group_inventory_file = generate_group_inventory_file(testbed.group, refresh=True)

    # Find which server has the testbed deployed
    server, deployed_testbed_info = _find_deployed_server(testbed_name, group_inventory_file, server)

    # Extract testbed index (always available even for partial deployments)
    testbed_index = deployed_testbed_info.get('index')
    if testbed_index is None:
        raise ValueError(f"Testbed '{testbed_name}' found on server '{server}' but has no index allocated")

    logger.info(f"Undeploying testbed '{testbed_name}' from server '{server}' (index: {testbed_index})")

    # Get topology definition and allocate resources to get container names
    topology_definition = get_topology_definition(testbed.topology)
    testbed_resources = allocate_testbed_resources(testbed, testbed_index, topology_definition)

    # Create server_host object for the target server
    server_host = TestServer(group_inventory_file, server)

    # Build list of all containers to delete
    containers_to_delete = []

    # Add PTF container
    ptf_name = list(testbed_resources['ptf'].keys())[0]
    containers_to_delete.append(ptf_name)

    # Add neighbor containers (ceos_ and net_ for each neighbor)
    if neighbor_type == "ceos":
        for neighbor_name in testbed_resources['neighbors'].keys():
            containers_to_delete.append(f"ceos_{neighbor_name}")
            containers_to_delete.append(f"net_{neighbor_name}")

    # Delete all containers in parallel using xargs
    if containers_to_delete:
        logger.info(f"Removing {len(containers_to_delete)} container(s) in parallel")
        containers_list = " ".join(containers_to_delete)
        server_host.shell(
            f"echo '{containers_list}' | xargs -n 1 -P 5 docker rm -f",
            task_directives={"become": True, "ignore_errors": True}
        )
        logger.info(f"Removed {len(containers_to_delete)} container(s)")

    # Remove KVM VMs if testbed type is kvm
    if testbed.type == "kvm":
        duts_info = testbed_resources.get('duts', {})
        _undeploy_kvm_vms(server_host, duts_info)

    # Remove OVS bridges and topology connections
    logger.info("Removing OVS bridges and topology connections")
    result = server_host.testbed_topology(
        operation='undeploy',
        topology_definition=topology_definition,
        testbed_resources=testbed_resources,
        neighbor_type=neighbor_type,
        task_directives={'become': True, 'ignore_errors': True}
    )

    if result.get('failed', False) and not result.get('ignored', False):
        logger.warning(f"Failed to remove some topology components: {result.get('msg', 'Unknown error')}")
    else:
        logger.info("Successfully removed OVS bridges and topology connections")

    # Remove testbed info from server
    logger.info(f"Removing testbed '{testbed_name}' info from server '{server}'")
    server_host.server_testbeds(
        operation='delete',
        testbeds_json_file=C.SERVER_TESTBEDS_FILE,
        testbed_name=testbed_name,
        task_directives={'become': True}
    )

    logger.info(f"Successfully undeployed testbed '{testbed_name}' from server '{server}'")

