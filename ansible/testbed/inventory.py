import csv
import ipaddress
import yaml
from pathlib import Path
from typing import Any

from ansible.parsing.dataloader import DataLoader
from ansible.inventory.manager import InventoryManager
from ansible.vars.manager import VariableManager
from ansible.vars.hostvars import HostVars

from .config import CONSTANTS as C
from .testbed import Testbed


# Cache for inventory managers to avoid re-parsing inventory files
_inventory_cache: dict[tuple, tuple[DataLoader, InventoryManager, VariableManager]] = {}


def _get_inventory_cache_key(inventories: str | list[str]) -> tuple:
    """Generate a cache key from inventory path(s)."""
    if isinstance(inventories, str):
        return (inventories,)
    return tuple(sorted(inventories))


def clear_ansible_var_cache() -> None:
    """Clear the cached inventory managers.

    Call this when inventory files have been modified and need to be re-read.
    """
    global _inventory_cache
    _inventory_cache.clear()


def get_ansible_var(
    inventories: str | list[str],
    hostname: str,
    var_name: str,
    default: Any = None
) -> Any:
    """
    Get an Ansible variable for a specific host from inventory.

    This helper function retrieves variables that are visible to a host,
    including host_vars, group_vars, inventory vars, and extra_vars.

    Note: Inventory data is cached for performance. If inventory files are modified,
    call clear_ansible_var_cache() to force re-reading.

    Args:
        inventories: Inventory file path(s) - can be a single file path or list of paths
        hostname: Name of the host to get the variable for
        var_name: Variable name to retrieve
        default: Default value to return if variable is not found

    Returns:
        Value of the variable, or default if not found

    Example:
        # Single inventory file
        mgmt_ip = get_ansible_var('_INV_GROUP_lab.yml', 'vlab-01', 'ansible_host')

        # Multiple inventory files
        user = get_ansible_var(
            ['_INV_GROUP_lab.yml', '_INV_TESTBED_vlab-01.yml'],
            'vlab-01',
            'ansible_user',
            default='admin'
        )

        # Clear cache if inventory files changed
        clear_ansible_var_cache()
    """
    cache_key = _get_inventory_cache_key(inventories)

    # Check cache first
    if cache_key not in _inventory_cache:
        # Not in cache, create new managers
        loader = DataLoader()
        inventory = InventoryManager(loader=loader, sources=inventories)
        variable_manager = VariableManager(loader=loader, inventory=inventory)

        # Trigger ansible to render variables with template expressions
        HostVars(inventory=inventory, variable_manager=variable_manager, loader=loader)

        # Store in cache
        _inventory_cache[cache_key] = (loader, inventory, variable_manager)

    # Use cached managers
    loader, inventory, variable_manager = _inventory_cache[cache_key]

    # Get the host object
    host = inventory.get_host(hostname)
    if host is None:
        return default

    # Get all variables for the host
    host_vars = variable_manager._hostvars[hostname]

    return host_vars.get(var_name, default)


def read_devices_csv(group_name: str) -> list[dict]:
    """
    Read device information from CSV file for the specified group.

    Args:
        group_name: Name of the group (e.g., 'lab', 'snappi-sonic')

    Returns:
        List of dictionaries containing device information
    """
    csv_file = Path(C.ANSIBLE_DIR) / "files" / f"sonic_{group_name}_devices.csv"

    devices = []
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            devices.append(row)

    return devices


def _read_yaml_file(file_path: Path) -> dict:
    """
    Helper function to read a YAML file and return its contents as a dict.

    Args:
        file_path: Path to the YAML file

    Returns:
        Dictionary containing the YAML content, or empty dict if file doesn't exist
    """
    if not file_path.exists():
        return {}

    with open(file_path, 'r') as f:
        return yaml.safe_load(f) or {}


def read_host_vars(group_name: str) -> dict:
    """
    Read host variables from YAML file for the specified group.

    Args:
        group_name: Name of the group (e.g., 'lab', 'snappi-sonic')

    Returns:
        Dictionary with hostname as keys, each containing var name/value pairs.
        Returns empty dict if file doesn't exist.

    Example structure:
        {
            'switch1': {'var1': 'value1', 'var2': 'value2'},
            'switch2': {'var1': 'value3', 'var2': 'value4'}
        }
    """
    vars_file = Path(C.ANSIBLE_DIR) / "files" / f"sonic_{group_name}_host_vars.yml"
    return _read_yaml_file(vars_file)


def read_group_vars(group_name: str) -> dict:
    """
    Read group variables from YAML file for the specified group.

    Args:
        group_name: Name of the group (e.g., 'lab', 'snappi-sonic')

    Returns:
        Dictionary with children group names as keys, each containing var name/value pairs.
        Returns empty dict if file doesn't exist.

    Example structure:
        {
            'duts': {'ansible_user': 'admin', 'ansible_connection': 'network_cli'},
            'fanout': {'ansible_user': 'root', 'some_var': 'value'}
        }
    """
    vars_file = Path(C.ANSIBLE_DIR) / "files" / f"sonic_{group_name}_group_vars.yml"
    return _read_yaml_file(vars_file)


def generate_group_inventory_file(group_name: str, refresh: bool = False) -> str:
    # Generate inventory file path: _INV_GROUP_<group_name>.yml under ansible directory
    inventory_file = Path(C.ANSIBLE_DIR) / f"_INV_GROUP_{group_name}.yml"

    # If file exists and refresh is False, return existing file
    if inventory_file.exists() and not refresh:
        return str(inventory_file)

    inventory_content = {
        "all": {
            "children": {
                "server": {"hosts": {}, "vars": {}},
                "dut": {"hosts": {}, "vars": {}},
                "fanout": {"hosts": {}, "vars": {}},
                "ptf": {"hosts": {}, "vars": {}},
                "console": {"hosts": {}, "vars": {}},
                "pdu": {"hosts": {}, "vars": {}},
                "bmc": {"hosts": {}, "vars": {}},
                "unknown": {"hosts": {}, "vars": {}},
                "vm_host": {"children": {"server": {}}},
            },
            "vars": {}
        }
    }

    device_type_to_children_group_map = {
        "devsonic": "dut",
        "kvm": "dut",
        "fanoutleaf": "fanout",
        "fanoutroot": "fanout",
        "ptf": "ptf",
        "consoleserver": "console",
        "pdu": "pdu",
        "mgmttstorrouter": "bmc",
        "server": "server",
    }

    # Read group and host variables
    group_vars = read_group_vars(group_name)
    host_vars = read_host_vars(group_name)

    group_devices = read_devices_csv(group_name)
    for device in group_devices:

        ########################################
        device_hostname = device['Hostname']
        device_type = device['Type']
        device_mgmt_ip = device['ManagementIp']
        device_hwsku = device['HwSku']
        ########################################

        # Convert CIDR notation to plain IP address using ipaddress library
        # This handles both '10.20.10.2/24' and '10.20.10.2' formats
        ip_obj = ipaddress.ip_interface(device_mgmt_ip)
        device_mgmt_ip = str(ip_obj.ip)

        # Use ansible_hostv6 for IPv6 addresses, ansible_host for IPv4
        ansible_host_key = 'ansible_hostv6' if ip_obj.version == 6 else 'ansible_host'

        children_group = device_type_to_children_group_map.get(device_type.lower(), 'unknown')

        # Build host entry with base attributes
        host_entry = {
            ansible_host_key: device_mgmt_ip,
            'hwsku': device_hwsku
        }

        # Add host-specific variables if defined
        if device_hostname in host_vars and host_vars[device_hostname]:
            host_entry.update(host_vars[device_hostname])

        inventory_content['all']['children'][children_group]['hosts'][device_hostname] = host_entry

    # Add group variables to each group
    for children_group_name in inventory_content['all']['children']:
        if children_group_name != 'vm_host':  # Skip vm_host as it only has children, not hosts
            # Only add vars if this specific group has variables defined
            if children_group_name in group_vars and group_vars[children_group_name]:
                inventory_content['all']['children'][children_group_name]['vars'].update(group_vars[children_group_name])
    if 'all' in group_vars and group_vars['all']:
        inventory_content['all']['vars'].update(group_vars['all'])

    # Write inventory content to YAML file
    with open(inventory_file, 'w') as f:
        yaml.dump(inventory_content, f, default_flow_style=False, sort_keys=False)

    return str(inventory_file)


def generate_testbed_inventory_file(
        testbed: Testbed,
        testbed_resources: dict,
        selected_server: str,
        refresh: bool = False,
        conn_graph: dict | None = None
    ) -> str:
    """
    Generate inventory file for the specified testbed.

    Args:
        testbed: Testbed object
        testbed_resources: Allocated resources for the testbed
        selected_server: Server hostname where testbed is deployed
        refresh: If True, regenerate the inventory file even if it exists
        conn_graph: Connection graph definition (optional, for fanout/console/pdu/bmc groups)
    """

    inventory_content = {
        "all": {
            "children": {
                "server": {"hosts": {}, "vars": {}},
                "duts": {"hosts": {}, "vars": {}},
                "neighbor": {"hosts": {}, "vars": {}},
                "ptf": {"hosts": {}, "vars": {}},
                "fanout": {"hosts": {}, "vars": {}},
                "console": {"hosts": {}, "vars": {}},
                "pdu": {"hosts": {}, "vars": {}},
                "bmc": {"hosts": {}, "vars": {}},
                "unknown": {"hosts": {}, "vars": {}},
                "vm_host": {"children": {"server": {}}},
            },
            "vars": {},
        }
    }
    # Generate inventory file path: _INV_TESTBED_<testbed_name>.yml under ansible directory
    inventory_file = Path(C.ANSIBLE_DIR) / f"_INV_TESTBED_{testbed.name}.yml"

    # If file exists and refresh is False, return existing file
    if inventory_file.exists() and not refresh:
        return str(inventory_file)

    # Read group devices and variables (used for both KVM and physical testbeds)
    group_devices = read_devices_csv(testbed.group)
    host_vars = read_host_vars(testbed.group)
    group_vars = read_group_vars(testbed.group)

    # Add selected server to server group
    for device in group_devices:
        if device['Hostname'] == selected_server:
            device_mgmt_ip = device['ManagementIp']

            # Parse IP to get address without prefix length
            ip_obj = ipaddress.ip_interface(device_mgmt_ip)
            device_mgmt_ip_addr = str(ip_obj.ip)

            # Use ansible_hostv6 for IPv6, ansible_host for IPv4
            ansible_host_key = 'ansible_hostv6' if ip_obj.version == 6 else 'ansible_host'

            # Build server entry
            server_entry = {
                ansible_host_key: device_mgmt_ip_addr
            }

            # Add host-specific variables if defined
            if selected_server in host_vars and host_vars[selected_server]:
                server_entry.update(host_vars[selected_server])

            inventory_content['all']['children']['server']['hosts'][selected_server] = server_entry
            break

    # Add DUTs for KVM testbed type
    if testbed.type == "kvm":
        dut_ips = testbed_resources.get('duts', {})
        for dut_name, dut_ip_dict in dut_ips.items():
            # Parse IPv4 to get address without prefix length
            ipv4_obj = ipaddress.ip_interface(dut_ip_dict['ipv4'])
            ipv4_addr = str(ipv4_obj.ip)

            # Parse IPv6 to get address without prefix length
            ipv6_obj = ipaddress.ip_interface(dut_ip_dict['ipv6'])
            ipv6_addr = str(ipv6_obj.ip)

            dut_entry = {
                'ansible_host': ipv4_addr,
                'ansible_hostv6': ipv6_addr
            }

            # Add host-specific variables if defined
            if dut_name in host_vars and host_vars[dut_name]:
                dut_entry.update(host_vars[dut_name])

            inventory_content['all']['children']['duts']['hosts'][dut_name] = dut_entry
    else:
        # For physical testbeds, get DUT details from group devices
        for device in group_devices:
            device_hostname = device['Hostname']

            # Only include devices that are in the testbed's DUT list
            if device_hostname in testbed.duts:
                device_mgmt_ip = device['ManagementIp']
                device_hwsku = device['HwSku']

                # Parse IP to get address without prefix length
                ip_obj = ipaddress.ip_interface(device_mgmt_ip)
                device_mgmt_ip_addr = str(ip_obj.ip)

                # Use ansible_hostv6 for IPv6, ansible_host for IPv4
                ansible_host_key = 'ansible_hostv6' if ip_obj.version == 6 else 'ansible_host'

                # Build host entry with base attributes
                host_entry = {
                    ansible_host_key: device_mgmt_ip_addr,
                    'hwsku': device_hwsku
                }

                # Add host-specific variables if defined
                if device_hostname in host_vars and host_vars[device_hostname]:
                    host_entry.update(host_vars[device_hostname])

                inventory_content['all']['children']['duts']['hosts'][device_hostname] = host_entry

    # Add PTF container
    ptf_ips = testbed_resources.get('ptf', {})
    for ptf_name, ptf_ip_dict in ptf_ips.items():
        # Parse IPv4 to get address without prefix length
        ipv4_obj = ipaddress.ip_interface(ptf_ip_dict['ipv4'])
        ipv4_addr = str(ipv4_obj.ip)

        # Parse IPv6 to get address without prefix length
        ipv6_obj = ipaddress.ip_interface(ptf_ip_dict['ipv6'])
        ipv6_addr = str(ipv6_obj.ip)

        inventory_content['all']['children']['ptf']['hosts'][ptf_name] = {
            'ansible_host': ipv4_addr,
            'ansible_hostv6': ipv6_addr
        }

    # Add neighbor VMs
    neighbor_ips = testbed_resources.get('neighbors', {})
    for neighbor_name, neighbor_ip_dict in neighbor_ips.items():
        # Parse IPv4 to get address without prefix length
        ipv4_obj = ipaddress.ip_interface(neighbor_ip_dict['ipv4'])
        ipv4_addr = str(ipv4_obj.ip)

        # Parse IPv6 to get address without prefix length
        ipv6_obj = ipaddress.ip_interface(neighbor_ip_dict['ipv6'])
        ipv6_addr = str(ipv6_obj.ip)

        inventory_content['all']['children']['neighbor']['hosts'][neighbor_name] = {
            'ansible_host': ipv4_addr,
            'ansible_hostv6': ipv6_addr
        }

    #TODO: For fanout, console, pdu, bmc, unknown groups - to be implemented based on conn_graph

    # Add group variables to each group
    for children_group_name in inventory_content['all']['children']:
        # Only add vars if this specific group has variables defined
        if children_group_name in group_vars and group_vars[children_group_name]:
            inventory_content['all']['children'][children_group_name]['vars'].update(group_vars[children_group_name])

    # Add 'all' group variables
    if 'all' in group_vars and group_vars['all']:
        inventory_content['all']['vars'].update(group_vars['all'])

    # Write inventory content to YAML file
    with open(inventory_file, 'w') as f:
        yaml.dump(inventory_content, f, default_flow_style=False, sort_keys=False)

    return str(inventory_file)
