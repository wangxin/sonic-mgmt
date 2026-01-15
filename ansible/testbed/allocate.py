import logging
import ipaddress

from .testbed import Testbed
from .config import CONSTANTS as C


logger = logging.getLogger(__name__)


# IPv4 offsets (decimal, human-friendly)
MANAGEMENT_BRIDGE_IP_OFFSET = 1
SONIC_KVM_MANAGEMENT_IP_OFFSET = 10
PTF_MANAGEMENT_IP_OFFSET = 20
NEIGHBOR_MANAGEMENT_IP_OFFSET = 30

# IPv6 offsets (hex-friendly for readability)
MANAGEMENT_BRIDGE_IP_OFFSET_V6 = 0x1       # ::1
SONIC_KVM_MANAGEMENT_IP_OFFSET_V6 = 0x10   # ::10
PTF_MANAGEMENT_IP_OFFSET_V6 = 0x20         # ::20
NEIGHBOR_MANAGEMENT_IP_OFFSET_V6 = 0x30    # ::30

SERIAL_PORT_BASE = 5000


def _calculate_testbed_network(
        base: str, testbed_index: int,
    ) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """
    Calculate the network range for a specific testbed.

    Args:
        base: Base network CIDR (e.g., '192.168.0.0/20')
        testbed_index: Testbed index on the server

    Returns:
        The testbed's network range
    """
    base_network = ipaddress.ip_network(base, strict=False)
    network_size = base_network.num_addresses
    testbed_network_int = int(base_network.network_address) + (testbed_index * network_size)
    testbed_network = ipaddress.ip_network(
        f"{ipaddress.ip_address(testbed_network_int)}/{base_network.prefixlen}", strict=False
    )
    return testbed_network


def generate_ptf_name(testbed_index: int) -> str:
    """
    Generate PTF name for a testbed.

    Args:
        testbed_index: Testbed index on the server

    Returns:
        str: PTF name (e.g., 'PTF00', 'PTF01')
    """
    return f"PTF{testbed_index:02d}"


def generate_neighbor_names(testbed_index: int, vm_count: int) -> list[str]:
    """
    Generate list of neighbor VM names for a testbed.

    Args:
        testbed_index: Testbed index on the server
        vm_count: Number of neighbor VMs

    Returns:
        list[str]: List of neighbor VM names (e.g., ['VM0000', 'VM0001', ...])
    """
    return [f"VM{testbed_index:02d}{vm_index:03d}" for vm_index in range(vm_count)]


def allocate_testbed_resources(
        testbed_obj: Testbed,
        testbed_index: int,
        topology_definition: dict
    ) -> dict:
    """
    Allocate all resources needed for a testbed.

    Args:
        testbed_index: Allocated testbed index on the server
        testbed_obj: Testbed object instance
        topology_definition: Topology definition loaded from vars/topo_*.yml

    Returns:
        dict: Allocated resources with keys:
            - 'index': testbed index on the server
            - 'type': testbed type (e.g., 'kvm', 'physical')
            - 'topology': topology name (e.g., 't0', 't1')
            - 'bridge': dict mapping bridge name to dict with 'ipv4' and 'ipv6' keys
            - 'duts': dict mapping DUT names to dict with 'ipv4', 'ipv6', and 'serial_port' keys (KVM only)
            - 'ptf': dict mapping PTF name to dict with 'ipv4' and 'ipv6' keys
            - 'neighbors': dict mapping neighbor VM names to dict with 'ipv4' and 'ipv6' keys
    """
    logger.info(
        f"Allocating resources for testbed index {testbed_index}, "
        f"topology '{testbed_obj.topology}', type '{testbed_obj.type}'"
    )

    # Calculate testbed networks for IPv4 and IPv6
    testbed_network_v4 = _calculate_testbed_network(
        C.TESTBED_MANAGEMENT_NETWORK_BASE, testbed_index
    )
    testbed_network_v6 = _calculate_testbed_network(
        C.TESTBED_MANAGEMENT_NETWORK_BASE_V6, testbed_index
    )

    # Allocate bridge management IPs (gateway) - both IPv4 and IPv6
    bridge_ip_v4 = allocate_ips(
        testbed_network_v4, MANAGEMENT_BRIDGE_IP_OFFSET
    )[0]
    bridge_ip_v6 = allocate_ips(
        testbed_network_v6, MANAGEMENT_BRIDGE_IP_OFFSET_V6
    )[0]
    # Construct bridge name
    bridge_name = f"br{testbed_index}m"
    bridges = {bridge_name: {'ipv4': bridge_ip_v4, 'ipv6': bridge_ip_v6}}

    # Allocate DUT management IPs (for KVM testbeds only) - both IPv4 and IPv6
    if testbed_obj.type == "kvm":
        dut_count = len(testbed_obj.duts)
        # Get allocated IPv4 IPs
        allocated_ips_v4 = allocate_ips(
            testbed_network_v4, SONIC_KVM_MANAGEMENT_IP_OFFSET, count=dut_count
        )
        # Get allocated IPv6 IPs
        allocated_ips_v6 = allocate_ips(
            testbed_network_v6, SONIC_KVM_MANAGEMENT_IP_OFFSET_V6, count=dut_count
        )
        # Allocate serial ports for each DUT
        serial_ports = [
            SERIAL_PORT_BASE + (testbed_index * 100) + dut_idx
            for dut_idx in range(dut_count)
        ]
        # Map DUT names to IPs and serial ports with IPv4, IPv6, and serial_port
        duts = {
            dut_name: {'ipv4': ipv4, 'ipv6': ipv6, 'serial_port': serial_port}
            for dut_name, ipv4, ipv6, serial_port in zip(
                testbed_obj.duts, allocated_ips_v4, allocated_ips_v6, serial_ports
            )
        }

    # Allocate PTF management IPs - both IPv4 and IPv6
    ptf_ip_v4 = allocate_ips(
        testbed_network_v4, PTF_MANAGEMENT_IP_OFFSET
    )[0]
    ptf_ip_v6 = allocate_ips(
        testbed_network_v6, PTF_MANAGEMENT_IP_OFFSET_V6
    )[0]
    # Construct PTF name
    ptf_name = generate_ptf_name(testbed_index)
    ptf = {ptf_name: {'ipv4': ptf_ip_v4, 'ipv6': ptf_ip_v6}}

    # Allocate neighbor VM management IPs (always for all testbed types) - both IPv4 and IPv6
    vm_count = len(topology_definition.get('configuration', {}))
    neighbor_ips_list_v4 = allocate_ips(
        testbed_network_v4, NEIGHBOR_MANAGEMENT_IP_OFFSET, count=vm_count
    )
    neighbor_ips_list_v6 = allocate_ips(
        testbed_network_v6, NEIGHBOR_MANAGEMENT_IP_OFFSET_V6, count=vm_count
    )
    # Construct neighbor VM names with both IPv4 and IPv6
    neighbor_names = generate_neighbor_names(testbed_index, vm_count)
    neighbors = {
        name: {'ipv4': ipv4, 'ipv6': ipv6}
        for name, ipv4, ipv6 in zip(neighbor_names, neighbor_ips_list_v4, neighbor_ips_list_v6)
    }

    # Build result - only include 'duts' for KVM testbeds
    allocated_resources = {
        'index': testbed_index,
        'name': testbed_obj.name,
        'type': testbed_obj.type,
        'topology': testbed_obj.topology,
        'bridge': bridges,
        'ptf': ptf,
        'neighbors': neighbors
    }
    if testbed_obj.type == "kvm":
        allocated_resources['duts'] = duts

    logger.info(
        f"Successfully allocated resources for testbed index {testbed_index}: "
        f"{len(duts) if testbed_obj.type == 'kvm' else 0} DUT(s), 1 PTF, {len(neighbors)} neighbor(s)"
    )
    return allocated_resources


def allocate_ips(
        testbed_network: ipaddress.IPv4Network | ipaddress.IPv6Network,
        offset: int,
        count: int = 1
    ) -> list[str]:
    """
    Allocate IP addresses within a testbed network.

    Args:
        testbed_network: The testbed's network range
        offset: Offset to apply within the testbed's network
        count: Number of IPs to allocate (default: 1)

    Returns:
        list[str]: List of allocated IP addresses in CIDR format
    """
    ips = []
    for i in range(count):
        ip_int = int(testbed_network.network_address) + offset + i
        ip = f"{ipaddress.ip_address(ip_int)}/{testbed_network.prefixlen}"
        ips.append(ip)
    return ips
