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
        testbed_index: int, base: str
    ) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Calculate the network range for a specific testbed.

    Args:
        testbed_index: Testbed index on the server
        base: Base network CIDR (e.g., '192.168.0.0/20')

    Returns:
        Tuple of (base_network, testbed_network)
    """
    base_network = ipaddress.ip_network(base, strict=False)
    network_size = base_network.num_addresses
    testbed_network_int = int(base_network.network_address) + (testbed_index * network_size)
    testbed_network = ipaddress.ip_network(
        f"{ipaddress.ip_address(testbed_network_int)}/{base_network.prefixlen}", strict=False
    )
    return base_network, testbed_network


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

    # Allocate bridge management IPs (gateway) - both IPv4 and IPv6
    bridge_ip_v4 = allocate_management_bridge_ip(
        testbed_index,
        C.TESTBED_MANAGEMENT_NETWORK_BASE,
        MANAGEMENT_BRIDGE_IP_OFFSET
    )
    bridge_ip_v6 = allocate_management_bridge_ip(
        testbed_index,
        C.TESTBED_MANAGEMENT_NETWORK_BASE_V6,
        MANAGEMENT_BRIDGE_IP_OFFSET_V6
    )
    # Construct bridge name
    bridge_name = f"br{testbed_index}m"
    bridge_ips = {bridge_name: {'ipv4': bridge_ip_v4, 'ipv6': bridge_ip_v6}}

    # Allocate DUT management IPs (for KVM testbeds only) - both IPv4 and IPv6
    if testbed_obj.type == "kvm":
        dut_count = len(testbed_obj.duts)
        # Get allocated IPv4 IPs
        allocated_ips_v4 = allocate_sonic_kvm_management_ip(
            testbed_index,
            C.TESTBED_MANAGEMENT_NETWORK_BASE,
            SONIC_KVM_MANAGEMENT_IP_OFFSET,
            count=dut_count
        )
        # Get allocated IPv6 IPs
        allocated_ips_v6 = allocate_sonic_kvm_management_ip(
            testbed_index,
            C.TESTBED_MANAGEMENT_NETWORK_BASE_V6,
            SONIC_KVM_MANAGEMENT_IP_OFFSET_V6,
            count=dut_count
        )
        # Allocate serial ports for each DUT
        serial_ports = [
            SERIAL_PORT_BASE + (testbed_index * 100) + dut_idx
            for dut_idx in range(dut_count)
        ]
        # Map DUT names to IPs and serial ports with IPv4, IPv6, and serial_port
        dut_ips = {
            dut_name: {'ipv4': ipv4, 'ipv6': ipv6, 'serial_port': serial_port}
            for dut_name, ipv4, ipv6, serial_port in zip(
                testbed_obj.duts, allocated_ips_v4, allocated_ips_v6, serial_ports
            )
        }

    # Allocate PTF management IPs - both IPv4 and IPv6
    ptf_ip_v4 = allocate_ptf_management_ip(
        testbed_index,
        C.TESTBED_MANAGEMENT_NETWORK_BASE,
        PTF_MANAGEMENT_IP_OFFSET
    )
    ptf_ip_v6 = allocate_ptf_management_ip(
        testbed_index,
        C.TESTBED_MANAGEMENT_NETWORK_BASE_V6,
        PTF_MANAGEMENT_IP_OFFSET_V6
    )
    # Construct PTF name
    ptf_name = f"PTF{testbed_index:02d}"
    ptf_ips = {ptf_name: {'ipv4': ptf_ip_v4, 'ipv6': ptf_ip_v6}}

    # Allocate neighbor VM management IPs (always for all testbed types) - both IPv4 and IPv6
    vm_count = len(topology_definition.get('configuration', {}))
    neighbor_ips_list_v4 = allocate_neighbor_vm_management_ips(
        testbed_index,
        C.TESTBED_MANAGEMENT_NETWORK_BASE,
        NEIGHBOR_MANAGEMENT_IP_OFFSET,
        vm_count
    )
    neighbor_ips_list_v6 = allocate_neighbor_vm_management_ips(
        testbed_index,
        C.TESTBED_MANAGEMENT_NETWORK_BASE_V6,
        NEIGHBOR_MANAGEMENT_IP_OFFSET_V6,
        vm_count
    )
    # Construct neighbor VM names with both IPv4 and IPv6
    vm_ips = {
        f"VM{testbed_index:02d}{vm_index:03d}": {'ipv4': ipv4, 'ipv6': ipv6}
        for vm_index, (ipv4, ipv6) in enumerate(zip(neighbor_ips_list_v4, neighbor_ips_list_v6))
    }

    # Build result - only include 'duts' for KVM testbeds
    allocated_resources = {
        'index': testbed_index,
        'type': testbed_obj.type,
        'topology': testbed_obj.topology,
        'bridge': bridge_ips,
        'ptf': ptf_ips,
        'neighbors': vm_ips
    }
    if testbed_obj.type == "kvm":
        allocated_resources['duts'] = dut_ips

    logger.info(
        f"Successfully allocated resources for testbed index {testbed_index}: "
        f"{len(dut_ips) if testbed_obj.type == 'kvm' else 0} DUT(s), 1 PTF, {len(vm_ips)} neighbor(s)"
    )
    return allocated_resources


def allocate_management_bridge_ip(testbed_index: int, base: str, offset: int) -> str:
    """
    Allocate management IP address for the management bridge gateway.

    Args:
        testbed_index: Testbed index on the server
        base: Base network CIDR (e.g., '192.168.0.0/20')
        offset: Offset to apply within the testbed's IP range

    Returns:
        str: Allocated bridge management IP address
    """
    logger.debug(
        f"Allocating management bridge IP for testbed index {testbed_index} at offset {offset}"
    )

    base_network, testbed_network = _calculate_testbed_network(testbed_index, base)

    # Allocate the bridge IP
    bridge_ip = f"{testbed_network.network_address + offset}/{base_network.prefixlen}"
    logger.debug(f"Allocated bridge IP: {bridge_ip}")

    return bridge_ip


def allocate_sonic_kvm_management_ip(testbed_index: int, base: str, offset: int, count: int = 1) -> list[str]:
    """
    Allocate management IP addresses for SONiC KVM(s) based on testbed index and offset.

    Args:
        testbed_index: Testbed index on the server
        base: Base network CIDR (e.g., '192.168.0.0/20')
        offset: Offset to apply within the testbed's IP range
        count: Number of SONiC KVM IPs to allocate (default: 1, e.g., 2 for dualtor)

    Returns:
        list[str]: List of allocated SONiC KVM management IP addresses
    """
    logger.debug(
        f"Allocating {count} SONiC KVM management IP(s) for testbed index {testbed_index} "
        f"starting at offset {offset}"
    )

    base_network, testbed_network = _calculate_testbed_network(testbed_index, base)

    # Allocate IPs sequentially within the testbed's network
    sonic_kvm_ips = []
    for i in range(count):
        ip_int = int(testbed_network.network_address) + offset + i
        management_ip = f"{ipaddress.ip_address(ip_int)}/{base_network.prefixlen}"
        sonic_kvm_ips.append(management_ip)

    logger.info(
        f"Allocated {count} SONiC KVM management IP(s) for testbed index {testbed_index}"
    )
    return sonic_kvm_ips


def allocate_ptf_management_ip(testbed_index: int, base: str, offset: int) -> str:
    """
    Allocate management IP address for PTF container based on testbed index and offset.

    Args:
        testbed_index: Testbed index on the server
        base: Base network CIDR (e.g., '192.168.0.0/20')
        offset: Offset to apply within the testbed's IP range

    Returns:
        str: Allocated PTF management IP address
    """
    logger.debug(f"Allocating PTF management IP for testbed index {testbed_index} with offset {offset}")

    base_network, testbed_network = _calculate_testbed_network(testbed_index, base)

    # Allocate IP at the specified offset within the testbed's network
    ip_int = int(testbed_network.network_address) + offset
    management_ip = f"{ipaddress.ip_address(ip_int)}/{base_network.prefixlen}"

    logger.info(f"Allocated PTF management IP {management_ip} for testbed index {testbed_index}")
    return management_ip


def allocate_neighbor_vm_management_ips(
        testbed_index: int,
        base: str,
        offset: int,
        vm_count: int
    ) -> list[str]:
    """
    Allocate management IP addresses for neighbor VMs.

    Args:
        testbed_index: Testbed index on the server
        base: Base network CIDR (e.g., '192.168.0.0/20')
        offset: Offset to apply within the testbed's IP range
        vm_count: Number of neighbor VMs to allocate IPs for

    Returns:
        list[str]: List of allocated neighbor VM management IP addresses
    """
    logger.debug(f"Allocating {vm_count} neighbor VM management IPs for testbed index {testbed_index}")

    base_network, testbed_network = _calculate_testbed_network(testbed_index, base)

    # Allocate IPs for each neighbor VM within the testbed's network
    neighbor_vm_ips = []
    for i in range(vm_count):
        ip_int = int(testbed_network.network_address) + offset + i
        management_ip = f"{ipaddress.ip_address(ip_int)}/{base_network.prefixlen}"
        neighbor_vm_ips.append(management_ip)

    logger.info(
        f"Allocated {len(neighbor_vm_ips)} neighbor VM management IPs for testbed index {testbed_index}"
    )
    return neighbor_vm_ips
