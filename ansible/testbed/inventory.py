import csv
import ipaddress
import yaml
from pathlib import Path

from .config import CONSTANTS as C


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
        if device_hostname in host_vars:
            host_entry.update(host_vars[device_hostname])

        inventory_content['all']['children'][children_group]['hosts'][device_hostname] = host_entry

    # Add group variables to each group
    for children_group_name in inventory_content['all']['children']:
        if children_group_name != 'vm_host':  # Skip vm_host as it only has children, not hosts
            # Only add vars if this specific group has variables defined
            if children_group_name in group_vars:
                inventory_content['all']['children'][children_group_name]['vars'].update(group_vars[children_group_name])
    if 'all' in group_vars:
        inventory_content['all']['vars'].update(group_vars['all'])

    # Write inventory content to YAML file
    with open(inventory_file, 'w') as f:
        yaml.dump(inventory_content, f, default_flow_style=False, sort_keys=False)

    return str(inventory_file)
