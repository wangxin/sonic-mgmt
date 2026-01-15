#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2026
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: tb_topology
short_description: Manage testbed topology connections
description:
    - This module manages network topology connections for testbed environments.
    - It handles virtual network interfaces and connections between devices.
version_added: "1.0.0"
options:
    operation:
        description:
            - The operation to perform.
        type: str
        required: true
        choices: ['deploy', 'undeploy']
    topology_definition:
        description:
            - Topology configuration data.
        type: dict
        required: false
    testbed_resources:
        description:
            - Testbed resources configuration.
        type: dict
        required: false
    neighbor_type:
        description:
            - Type of neighbor device for topology deployment.
            - Use 'ceos' for Arista cEOS neighbors.
        type: str
        required: false
        choices: ['ceos']
author:
    - Testbed Automation Team
'''

EXAMPLES = r'''
# Deploy topology connections for KVM testbed
- name: Deploy testbed topology
  tb_topology:
    operation: deploy
    neighbor_type: ceos
    topology_definition:
      topology:
        VMs:
          ARISTA01T1:
            vlans: [0, 1, 2]
        host_interfaces: [0, 1, 2]
      configuration:
        ARISTA01T1:
          interfaces:
            Ethernet1: {}
            Ethernet2: {}
      configuration_properties:
        common:
          nhipv4: 10.10.246.254
    testbed_resources:
      type: kvm
      index: 0
      ptf:
        PTF00:
          ipv4: 192.168.0.1/20
      duts:
        vlab-01:
          fp_ports: ['vlab-01-0', 'vlab-01-1']
      neighbors:
        VM00000: {}
      bridge:
        br0m:
          ipv4: 192.168.0.1/20

# Undeploy topology connections
- name: Undeploy testbed topology
  tb_topology:
    operation: undeploy
    neighbor_type: ceos
    testbed_resources:
      type: kvm
      index: 0
      ptf:
        PTF00: {}
      neighbors:
        VM00000: {}
'''

RETURN = r'''
changed:
    description: Whether the topology state was changed.
    type: bool
    returned: always
msg:
    description: Status message.
    type: str
    returned: always
topology:
    description: Current topology configuration.
    type: dict
    returned: always
'''

from ansible.module_utils.basic import AnsibleModule
import asyncio
import os
import subprocess
import docker
from natsort import natsorted


class TestbedTopology:
    """Testbed topology manager for creating and managing network connections."""

    def __init__(self, module):
        """Initialize topology manager.

        Args:
            module: AnsibleModule instance
        """
        self.module = module

        self.operation = module.params['operation']
        self.topology_definition = module.params.get('topology_definition', {})
        self.testbed_resources = module.params.get('testbed_resources', {})
        self.neighbor_type = module.params.get('neighbor_type')

        # Build neighbor to VM name mapping
        topo_config = self.topology_definition.get('topology', {})
        neighbor_names = natsorted(self.testbed_resources.get('neighbors', {}).keys())
        vm_names = natsorted(topo_config.get('VMs', {}).keys())
        self.neighbor_to_vm_name_map = {}
        self.vm_name_to_neighbor_map = {}
        for neighbor_name, vm_name in zip(neighbor_names, vm_names):
            self.neighbor_to_vm_name_map[neighbor_name] = vm_name
            self.vm_name_to_neighbor_map[vm_name] = neighbor_name

        self.docker_client = docker.from_env()
        self.changed = False
        self.msg = ''

    async def _run(self, command, check=True, ignore_errors=False):
        """Run a shell command asynchronously with full shell support (pipes, redirects, etc.).

        Args:
            command: Shell command string to execute
            check: If True, raise exception on non-zero exit code
            ignore_errors: If True, don't raise exception even if check=True

        Returns:
            dict: Dictionary with keys:
                - rc: Return code
                - stdout: Standard output as string
                - stderr: Standard error as string
                - failed: Boolean indicating if command failed

        Raises:
            subprocess.CalledProcessError: If check=True and command fails (unless ignore_errors=True)
        """
        # Support Ansible check mode (dry-run)
        if self.module.check_mode:
            return {
                'rc': 0,
                'stdout': '',
                'stderr': '',
                'failed': False,
                'skipped': True
            }

        try:
            # Create subprocess with shell support
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            # Wait for command to complete and get output
            stdout_bytes, stderr_bytes = await proc.communicate()

            # Decode bytes to string
            stdout = stdout_bytes.decode('utf-8') if stdout_bytes else ''
            stderr = stderr_bytes.decode('utf-8') if stderr_bytes else ''

            cmd_result = {
                'rc': proc.returncode,
                'stdout': stdout,
                'stderr': stderr,
                'failed': proc.returncode != 0
            }

            if check and proc.returncode != 0 and not ignore_errors:
                raise subprocess.CalledProcessError(
                    proc.returncode,
                    command,
                    output=stdout,
                    stderr=stderr
                )

            return cmd_result

        except subprocess.CalledProcessError as e:
            if not ignore_errors:
                raise
            return {
                'rc': e.returncode,
                'stdout': e.output or '',
                'stderr': e.stderr or '',
                'failed': True
            }

    async def _create_veth_to_namespace(self, namespace_pid, veth_external, veth_internal):
        """Create veth pair and move one end to network namespace.

        Args:
            namespace_pid: Network namespace ID (container PID)
            veth_external: Name for the external veth interface (host side)
            veth_internal: Name for the internal veth interface (namespace side)

        Raises:
            subprocess.CalledProcessError: If any command fails
        """
        # Check if external interface already exists
        check_result = await self._run(
            f"ip link show {veth_external}",
            check=False,
            ignore_errors=True
        )

        # If interface already exists, skip creation
        if check_result['rc'] == 0:
            return

        # Create veth pair with temporary name for internal interface (append 'i' to avoid conflicts)
        temp_internal = f"{veth_external}i"
        await self._run(
            f"ip link add {veth_external} type veth peer name {temp_internal}"
        )

        # Move internal interface to network namespace
        await self._run(
            f"ip link set {temp_internal} netns {namespace_pid}"
        )

        # Rename internal interface to desired name in namespace
        await self._run(
            f"nsenter -t {namespace_pid} -n ip link set {temp_internal} name {veth_internal}"
        )

        # Bring up external interface
        await self._run(
            f"ip link set {veth_external} up"
        )

        # Bring up internal interface in namespace
        await self._run(
            f"nsenter -t {namespace_pid} -n ip link set {veth_internal} up"
        )

    async def _create_ovs_bridge_with_ports(self, bridge_name, port_names, clear_flows=False):
        """Create Open vSwitch bridge and attach all ports in a single command.

        This is more efficient than creating the bridge and adding ports separately,
        as it executes everything in one ovs-vsctl transaction.

        Args:
            bridge_name: Name for the OVS bridge
            port_names: List of interface names to attach to the bridge
            clear_flows: If True, delete all flows and set secure mode.
                        If False, keep default flows (bridge acts like a normal switch).

        Raises:
            subprocess.CalledProcessError: If any command fails
        """
        # Build single ovs-vsctl command: create bridge and add all ports
        # Format: ovs-vsctl --may-exist add-br br0 -- --may-exist add-port br0 port1 -- --may-exist add-port br0 port2 ...
        cmd_parts = [f"ovs-vsctl --may-exist add-br {bridge_name}"]

        # Add all ports in the same transaction
        for port_name in port_names:
            cmd_parts.append(f"-- --may-exist add-port {bridge_name} {port_name}")

        # Execute the combined command
        await self._run(" ".join(cmd_parts))

        if clear_flows:
            # Delete all default flows to prevent any traffic forwarding
            await self._run(
                f"ovs-ofctl del-flows {bridge_name}"
            )

            # Set fail mode to secure (drop packets when no matching flows)
            await self._run(
                f"ovs-vsctl set-fail-mode {bridge_name} secure"
            )

        # Explicitly bring up the bridge interface
        # (OVS bridges are usually auto-up, but we ensure it for reliability)
        await self._run(
            f"ip link set {bridge_name} up"
        )

    async def _add_flows_to_bridge(self, bridge_name, flows_file_path, clear_existing=True):
        """Add OpenFlow rules to a bridge from a flows file.

        This method applies OpenFlow rules from a file to the specified bridge.
        The flows file should contain one flow rule per line in OpenFlow format.

        Args:
            bridge_name: Name of the OVS bridge to add flows to
            flows_file_path: Path to the file containing OpenFlow rules
            clear_existing: If True (default), clear all existing flows before adding new ones.
                          This ensures idempotent behavior and avoids conflicts.
                          Set to False to append flows to existing ones.

        Raises:
            FileNotFoundError: If the flows file does not exist
            subprocess.CalledProcessError: If the ovs-ofctl command fails

        Example flows file format:
            in_port=1,actions=output:2
            in_port=2,actions=output:1
            priority=100,in_port=3,dl_type=0x0800,actions=output:4
        """
        # Verify flows file exists
        if not os.path.exists(flows_file_path):
            raise FileNotFoundError(f"Flows file not found: {flows_file_path}")

        # Clear existing flows if requested (recommended for idempotent behavior)
        if clear_existing:
            await self._run(
                f"ovs-ofctl del-flows {bridge_name}"
            )

        # Apply flows from file using ovs-ofctl add-flows
        await self._run(
            f"ovs-ofctl add-flows {bridge_name} {flows_file_path}"
        )

    async def _assign_bridge_ip(self, bridge_name, ipv4=None, ipv6=None):
        """Assign IP addresses to a bridge interface.

        Args:
            bridge_name: Name of the bridge
            ipv4: IPv4 address with prefix (e.g., '192.168.0.1/20')
            ipv6: IPv6 address with prefix (e.g., 'fd00::1/64')

        Raises:
            subprocess.CalledProcessError: If command fails
        """
        if ipv4:
            # Check if IPv4 address already assigned
            check_result = await self._run(
                f"ip addr show dev {bridge_name} | grep -q '{ipv4}'",
                check=False,
                ignore_errors=True
            )
            # Only add if not already present
            if check_result['rc'] != 0:
                await self._run(
                    f"ip addr add {ipv4} dev {bridge_name}"
                )

        if ipv6:
            # Check if IPv6 address already assigned
            check_result = await self._run(
                f"ip addr show dev {bridge_name} | grep -q '{ipv6}'",
                check=False,
                ignore_errors=True
            )
            # Only add if not already present
            if check_result['rc'] != 0:
                await self._run(
                    f"ip addr add {ipv6} dev {bridge_name}"
                )

    async def _assign_namespace_interface_ip(self, namespace_pid, interface_name, ipv4=None, ipv6=None):
        """Assign IP addresses to an interface inside a network namespace.

        Args:
            namespace_pid: Network namespace ID (container PID)
            interface_name: Name of the interface inside the namespace
            ipv4: IPv4 address with prefix (e.g., '192.168.0.20/20')
            ipv6: IPv6 address with prefix (e.g., 'fd00::20/64')

        Raises:
            subprocess.CalledProcessError: If command fails
        """
        if ipv4:
            # Check if IPv4 address already assigned
            check_result = await self._run(
                f"nsenter -t {namespace_pid} -n ip addr show dev {interface_name} | grep -q '{ipv4}'",
                check=False,
                ignore_errors=True
            )
            # Only add if not already present
            if check_result['rc'] != 0:
                await self._run(
                    f"nsenter -t {namespace_pid} -n ip addr add {ipv4} dev {interface_name}"
                )

        if ipv6:
            # Check if IPv6 address already assigned
            check_result = await self._run(
                f"nsenter -t {namespace_pid} -n ip addr show dev {interface_name} | grep -q '{ipv6}'",
                check=False,
                ignore_errors=True
            )
            # Only add if not already present
            if check_result['rc'] != 0:
                await self._run(
                    f"nsenter -t {namespace_pid} -n ip addr add {ipv6} dev {interface_name}"
                )

    async def _get_container_pid(self, container_name):
        """Get the PID of a Docker container.

        Args:
            container_name: Name of the container

        Returns:
            str: Container PID

        Raises:
            docker.errors.NotFound: If container is not found
            Exception: If failed to get container PID
        """
        container = await asyncio.to_thread(self.docker_client.containers.get, container_name)
        pid = str(container.attrs['State']['Pid'])
        return pid

    async def _collect_container_pids(self, container_names):
        """Collect PIDs for given container names.

        Args:
            container_names: List of container names

        Returns:
            dict: Mapping from container name to PID
        """
        if not container_names:
            return {}

        # Get all PIDs concurrently
        pids = await asyncio.gather(*[
            self._get_container_pid(name)
            for name in container_names
        ])

        # Map container names to PIDs
        return dict(zip(container_names, pids))

    def _collect_ptf_interfaces(self):
        """Collect all PTF interfaces from topology definition.

        Returns:
            list: Sorted list of PTF interface numbers
        """
        topo_config = self.topology_definition.get('topology', {})
        host_interfaces = topo_config.get('host_interfaces', [])
        disabled_host_interfaces = topo_config.get('disabled_host_interfaces', [])

        # Collect VLAN interfaces from VMs configuration
        vms_config = topo_config.get('VMs', {})
        vlan_interfaces = []
        for vm_config in vms_config.values():
            vlan_interfaces.extend(vm_config.get('vlans', []))

        # Combine all PTF dataplane interfaces and return sorted
        return sorted(set(host_interfaces + disabled_host_interfaces + vlan_interfaces))

    def _get_ptf_interface_names(self, ptf_name, all_ptf_interfaces):
        """Get list of PTF interface names (veth external sides).

        Args:
            ptf_name: PTF container name
            all_ptf_interfaces: Sorted list of PTF interface numbers

        Returns:
            dict: {
                'management': 'PTF00-m',
                'dataplane': ['PTF00-0', 'PTF00-1', ...],
                'backplane': 'PTF00-b'
            }
        """
        if not ptf_name:
            return {'management': None, 'dataplane': [], 'backplane': None}

        return {
            'management': f"{ptf_name}-m",
            'dataplane': [f"{ptf_name}-{i}" for i in all_ptf_interfaces],
            'backplane': f"{ptf_name}-b"
        }

    def _get_neighbor_interface_names(self, neighbor_name):
        """Get list of neighbor interface names for a single neighbor.

        Args:
            neighbor_name: Neighbor container name (e.g., 'VM00000')

        Returns:
            dict: {
                'management': 'VM00000-m',
                'dataplane': ['VM00000-t0', 'VM00000-t1', ...],
                'backplane': 'VM00000-b'
            }
        """
        vm_name = self.neighbor_to_vm_name_map.get(neighbor_name)
        if not vm_name:
            return {'management': None, 'dataplane': [], 'backplane': None}

        neighbor_config = self.topology_definition.get('configuration', {}).get(vm_name, {})
        interfaces = neighbor_config.get('interfaces', {})

        # Find max interface number
        max_interface_num = 0
        for interface_name in interfaces.keys():
            if interface_name.startswith('Ethernet'):
                interface_num_int = int(interface_name.replace('Ethernet', ''))
                max_interface_num = max(max_interface_num, interface_num_int)

        return {
            'management': f"{neighbor_name}-m",
            'dataplane': [f"{neighbor_name}-t{i-1}" for i in range(1, max_interface_num + 1)],
            'backplane': f"{neighbor_name}-b"
        }

    def _get_all_neighbor_interface_names(self):
        """Get all neighbor interface names from testbed resources.

        Returns:
            dict: Mapping from neighbor names to their interface names.
                Format: {
                    'VM00000': {'management': 'VM00000-m', 'dataplane': [...], 'backplane': 'VM00000-b'},
                    ...
                }
        """
        all_neighbor_interface_names = {}

        if self.neighbor_type != 'ceos':
            return all_neighbor_interface_names

        neighbor_resources = self.testbed_resources.get('neighbors', {})
        for neighbor_name in neighbor_resources.keys():
            neighbor_interface_names = self._get_neighbor_interface_names(neighbor_name)
            if neighbor_interface_names['management']:  # Only add if valid
                all_neighbor_interface_names[neighbor_name] = neighbor_interface_names

        return all_neighbor_interface_names

    def _get_dut_interface_names(self):
        """Get all DUT interface names from testbed resources.

        Returns:
            dict: Mapping from DUT names to their interface names.
                Format: {
                    'vlab-01': {'management': 'vlab-01-m', 'dataplane': ['vlab-01-0', ...]},
                    ...
                }
        """
        dut_interface_names = {}

        if self.testbed_resources.get('type') != 'kvm':
            return dut_interface_names

        dut_resources = self.testbed_resources.get('duts', {})
        for dut_name, dut_config in dut_resources.items():
            fp_ports = dut_config.get('fp_ports', [])
            dut_interface_names[dut_name] = {
                'management': f"{dut_name}-m",
                'dataplane': fp_ports
            }

        return dut_interface_names

    def _build_ptf_interface_args(self, ptf_pid, ptf_interface_names, testbed_index):
        """Build veth creation and interface attachment arguments for PTF container.

        Args:
            ptf_pid: PTF container PID
            ptf_interface_names: Dict with PTF interface names ({'management': str, 'dataplane': list, 'backplane': str})
            testbed_index: Testbed index for bridge names

        Returns:
            tuple: (veth_creation_args, interface_attachment_args)
        """
        veth_creation_args = []
        interface_attachment_args = []

        if not ptf_pid:
            return veth_creation_args, interface_attachment_args

        # Management interface
        if ptf_interface_names['management']:
            veth_creation_args.append({
                'namespace_pid': ptf_pid,
                'veth_external': ptf_interface_names['management'],
                'veth_internal': 'mgmt'
            })
            interface_attachment_args.append({
                'bridge_name': f"br{testbed_index}m",
                'interface_name': ptf_interface_names['management']
            })

        # Data plane interfaces
        for idx, veth_external in enumerate(ptf_interface_names['dataplane']):
            veth_creation_args.append({
                'namespace_pid': ptf_pid,
                'veth_external': veth_external,
                'veth_internal': f"eth{idx}"
            })
            interface_attachment_args.append({
                'bridge_name': f"br{testbed_index}d",
                'interface_name': veth_external
            })

        # Backplane interface
        if ptf_interface_names['backplane']:
            veth_creation_args.append({
                'namespace_pid': ptf_pid,
                'veth_external': ptf_interface_names['backplane'],
                'veth_internal': 'backplane'
            })
            interface_attachment_args.append({
                'bridge_name': f"br{testbed_index}b",
                'interface_name': ptf_interface_names['backplane']
            })

        return veth_creation_args, interface_attachment_args

    def _build_dut_interface_args(self, dut_interface_names, testbed_index):
        """Build interface attachment arguments for KVM DUT.

        Args:
            dut_interface_names: Dict mapping DUT names to their interface names
                Format: {
                    'vlab-01': {'management': 'vlab-01-m', 'dataplane': ['vlab-01-0', ...]},
                    ...
                }
            testbed_index: Testbed index for bridge names

        Returns:
            list: interface_attachment_args
        """
        interface_attachment_args = []

        for dut_name, interface_names in dut_interface_names.items():
            # Management interface
            if interface_names['management']:
                interface_attachment_args.append({
                    'bridge_name': f"br{testbed_index}m",
                    'interface_name': interface_names['management']
                })

            # Dataplane interfaces
            for port_name in interface_names['dataplane']:
                interface_attachment_args.append({
                    'bridge_name': f"br{testbed_index}d",
                    'interface_name': port_name
                })

        return interface_attachment_args

    def _build_neighbor_interface_args(self, neighbor_pids, neighbor_interface_names, testbed_index):
        """Build veth creation and interface attachment arguments for neighbor containers.

        Args:
            neighbor_pids: Dict mapping neighbor names to PIDs
            neighbor_interface_names: Dict mapping neighbor names to their interface names
                Format: {
                    'VM00000': {'management': 'VM00000-m', 'dataplane': [...], 'backplane': 'VM00000-b'},
                    ...
                }
            testbed_index: Testbed index for bridge names

        Returns:
            tuple: (veth_creation_args, interface_attachment_args)
        """
        veth_creation_args = []
        interface_attachment_args = []

        for neighbor_name, neighbor_pid in neighbor_pids.items():
            # Get VM name and interface names
            vm_name = self.neighbor_to_vm_name_map.get(neighbor_name)
            if not vm_name:
                continue

            interface_names = neighbor_interface_names.get(neighbor_name)
            if not interface_names:
                continue

            # Management interface
            if interface_names['management']:
                veth_creation_args.append({
                    'namespace_pid': neighbor_pid,
                    'veth_external': interface_names['management'],
                    'veth_internal': 'eth0'
                })
                interface_attachment_args.append({
                    'bridge_name': f"br{testbed_index}m",
                    'interface_name': interface_names['management']
                })

            # Dataplane interfaces (VM00000-t0 → eth1, VM00000-t1 → eth2, etc.)
            for idx, veth_external in enumerate(interface_names['dataplane']):
                veth_creation_args.append({
                    'namespace_pid': neighbor_pid,
                    'veth_external': veth_external,
                    'veth_internal': f"eth{idx+1}"
                })
                interface_attachment_args.append({
                    'bridge_name': f"br{testbed_index}d",
                    'interface_name': veth_external
                })

            # Backplane interface (next eth after dataplane interfaces)
            if interface_names['backplane']:
                backplane_interface_num = len(interface_names['dataplane']) + 1
                veth_creation_args.append({
                    'namespace_pid': neighbor_pid,
                    'veth_external': interface_names['backplane'],
                    'veth_internal': f"eth{backplane_interface_num}"
                })
                interface_attachment_args.append({
                    'bridge_name': f"br{testbed_index}b",
                    'interface_name': interface_names['backplane']
                })

        return veth_creation_args, interface_attachment_args

    async def _create_ovs_bridges(self, interface_attachment_args, testbed_index):
        """Create OVS bridges and attach all interfaces.

        Args:
            interface_attachment_args: List of interface attachment arguments
            testbed_index: Testbed index for bridge names
        """
        # Group interface attachments by bridge name
        bridge_ports = {
            f"br{testbed_index}m": [],
            f"br{testbed_index}b": [],
            f"br{testbed_index}d": []
        }

        for attachment in interface_attachment_args:
            bridge_name = attachment['bridge_name']
            interface_name = attachment['interface_name']
            bridge_ports[bridge_name].append(interface_name)

        # Prepare OVS bridge creation with ports arguments
        bridge_creation_args = []

        # Management bridge (no flow clearing - acts like normal switch)
        bridge_creation_args.append({
            'bridge_name': f"br{testbed_index}m",
            'port_names': bridge_ports[f"br{testbed_index}m"],
            'clear_flows': False
        })

        # Backplane bridge (no flow clearing - acts like normal switch)
        bridge_creation_args.append({
            'bridge_name': f"br{testbed_index}b",
            'port_names': bridge_ports[f"br{testbed_index}b"],
            'clear_flows': False
        })

        # Dataplane bridge (clear flows - explicit flow control)
        bridge_creation_args.append({
            'bridge_name': f"br{testbed_index}d",
            'port_names': bridge_ports[f"br{testbed_index}d"],
            'clear_flows': True
        })

        # Create OVS bridges with all ports in single command per bridge (concurrent)
        await asyncio.gather(*[
            self._create_ovs_bridge_with_ports(**bridge_args)
            for bridge_args in bridge_creation_args
        ])

    def _build_openflow_rule(self, rule_dict, priority=100):
        """Build an OpenFlow rule string from a rule dictionary.

        Args:
            rule_dict: Dictionary with format:
                {
                    "in_port": "vlab-01-29",
                    "vlan": 129,  # Could be None
                    "vlan_action": "pop",  # Could be "push", "pop" or None.
                    "out_ports": ["PTF00-29", "VM00000-t0"],  # Must be a list
                    "priority": 100  # Optional, defaults to method parameter if not specified
                }
            priority: Default flow rule priority if not specified in rule_dict (default 100)

        Returns:
            str: OpenFlow rule string

        Examples:
            With VLAN pop:
                Input: {"in_port": "vlab-01-29", "vlan": 129, "vlan_action": "pop",
                        "out_ports": ["PTF00-29", "VM00000-t0"]}
                Output: "priority=100,in_port=vlab-01-29,dl_vlan=129,actions=strip_vlan,output:PTF00-29,output:VM00000-t0"

            Without VLAN:
                Input: {"in_port": "vlab-01-29", "vlan": None, "vlan_action": None,
                        "out_ports": ["PTF00-29", "VM00000-t0"]}
                Output: "priority=100,in_port=vlab-01-29,actions=output:PTF00-29,output:VM00000-t0"
        """
        in_port = rule_dict.get("in_port")
        vlan = rule_dict.get("vlan")
        vlan_action = rule_dict.get("vlan_action")
        out_ports = rule_dict.get("out_ports", [])
        rule_priority = rule_dict.get("priority", priority)

        # Build match criteria
        match_parts = [f"priority={rule_priority}", f"in_port={in_port}"]

        if vlan is not None:
            match_parts.append(f"dl_vlan={vlan}")

        # Build actions
        actions = []

        if vlan is not None and vlan_action:
            if vlan_action == "pop":
                actions.append("strip_vlan")
            elif vlan_action == "push":
                actions.append("set_vlan_id")

        # Add output actions for all output ports
        for out_port in out_ports:
            actions.append(f"output:{out_port}")

        # Combine match and actions
        match_str = ",".join(match_parts)
        actions_str = ",".join(actions)

        return f"{match_str},actions={actions_str}"

    async def _assign_bridge_ips(self):
        """Assign IP addresses to bridges."""
        bridge_ip_args = []
        bridge_resources = self.testbed_resources.get('bridge', {})
        for bridge_name, ip_config in bridge_resources.items():
            bridge_ip_args.append({
                'bridge_name': bridge_name,
                'ipv4': ip_config.get('ipv4'),
                'ipv6': ip_config.get('ipv6')
            })

        await asyncio.gather(*[
            self._assign_bridge_ip(**ip_args)
            for ip_args in bridge_ip_args
        ])

    def _build_dataplane_flows(self, ptf_interface_names, dut_interface_names, neighbor_interface_names):
        """Build OpenFlow rule dictionaries for dataplane bridge.

        Args:
            ptf_interface_names: Dict with PTF interface names
            dut_interface_names: Dict mapping DUT names to their interface names
            neighbor_interface_names: Dict mapping neighbor names to their interface names

        Returns:
            list: List of OpenFlow rule dictionaries
        """
        topo_config = self.topology_definition.get('topology', {})
        host_interfaces = topo_config.get('host_interfaces', [])
        testbed_type = self.testbed_resources.get('type')

        openflow_rules = []

        # Skip if testbed type is not kvm
        if testbed_type != 'kvm':
            return openflow_rules

        # Build mapping from port_index to PTF port name for quick lookup
        ptf_port_map = {idx: port_name for idx, port_name in enumerate(ptf_interface_names['dataplane'])}

        # Get first DUT for the rules
        dut_names = natsorted(dut_interface_names.keys())
        if not dut_names:
            return openflow_rules

        first_dut = dut_names[0]
        first_dut_ports = dut_interface_names[first_dut]['dataplane']

        # Loop through host interfaces
        for host_interface in host_interfaces:
            # Skip if not an integer (for dualtor)
            if not isinstance(host_interface, int):
                continue

            port_index = host_interface

            # Get PTF and DUT port names
            ptf_port_name = ptf_port_map.get(port_index)
            dut_port_name = first_dut_ports[port_index] if port_index < len(first_dut_ports) else None

            if ptf_port_name and dut_port_name:
                # Rule 1: PTF -> DUT (no VLAN)
                openflow_rules.append({
                    'in_port': ptf_port_name,
                    'vlan': None,
                    'vlan_action': None,
                    'out_ports': [dut_port_name]
                })

                # Rule 2: DUT -> PTF (no VLAN)
                openflow_rules.append({
                    'in_port': dut_port_name,
                    'vlan': None,
                    'vlan_action': None,
                    'out_ports': [ptf_port_name]
                })

        # Loop through VMs in topology
        vms_config = topo_config.get('VMs', {})
        for vm_name, vm_config in vms_config.items():
            neighbor_name = self.vm_name_to_neighbor_map.get(vm_name)
            neighbor_port_list = neighbor_interface_names.get(neighbor_name, {}).get('dataplane', [])
            vlans = vm_config.get('vlans', [])

            # Loop through VLAN port indices
            for idx, port_index in enumerate(vlans):
                # Skip if not an integer (for dualtor)
                if not isinstance(port_index, int):
                    continue

                ptf_port_name = ptf_port_map.get(port_index)
                dut_port_name = first_dut_ports[port_index] if port_index < len(first_dut_ports) else None
                neighbor_port_name = neighbor_port_list[idx] if idx < len(neighbor_port_list) else None

                openflow_rules.append({
                    'in_port': dut_port_name,
                    'vlan': None,
                    'vlan_action': None,
                    'out_ports': [ptf_port_name, neighbor_port_name]
                })
                openflow_rules.append({
                    'in_port': ptf_port_name,
                    'vlan': None,
                    'vlan_action': None,
                    'out_ports': [dut_port_name]
                })
                openflow_rules.append({
                    'in_port': neighbor_port_name,
                    'vlan': None,
                    'vlan_action': None,
                    'out_ports': [dut_port_name]
                })

        return openflow_rules

    async def _apply_dataplane_flows(self, openflow_rules, testbed_index):
        """Convert OpenFlow rule dicts to strings, save to file, and apply to bridge.

        Args:
            openflow_rules: List of OpenFlow rule dictionaries
            testbed_index: Testbed index for bridge and file naming
        """
        if not openflow_rules:
            return

        # Convert rule dicts to rule strings and save to file
        flows_file_path = f"/tmp/br{testbed_index}d_flows.txt"
        with open(flows_file_path, 'w') as f:
            for rule_dict in openflow_rules:
                rule_string = self._build_openflow_rule(rule_dict)
                f.write(rule_string + '\n')

        # Add OpenFlow rules to dataplane bridge
        await self._add_flows_to_bridge(f"br{testbed_index}d", flows_file_path)

    async def _assign_ptf_interface_ips(self, ptf_pid, ptf_name):
        """Assign IP addresses to PTF interfaces.

        Args:
            ptf_pid: PTF container PID
            ptf_name: PTF container name
        """
        ptf_interface_ip_args = []

        if not (ptf_pid and ptf_name):
            return

        # Management interface IP assignment
        ptf_resources = self.testbed_resources.get('ptf', {})
        ptf_ip_config = ptf_resources.get(ptf_name, {})
        if ptf_ip_config:
            ptf_interface_ip_args.append({
                'namespace_pid': ptf_pid,
                'interface_name': 'mgmt',
                'ipv4': ptf_ip_config.get('ipv4'),
                'ipv6': ptf_ip_config.get('ipv6')
            })

        # Backplane interface IP assignment
        # Get PTF backplane IP addresses from topology definition (without prefix length)
        # These are stored in configuration_properties.common.nhipv4 and nhipv6
        config_props = self.topology_definition.get('configuration_properties', {})
        common_props = config_props.get('common', {})
        bp_ipv4_addr = common_props.get('nhipv4')
        bp_ipv6_addr = common_props.get('nhipv6')

        # Extract prefix lengths from VM bp_interface configuration
        # Note: We only use the PREFIX LENGTH from VM bp_interface, not the IP address
        # The actual PTF IP comes from nhipv4/nhipv6 above
        vm_configs = self.topology_definition.get('configuration', {})
        bp_ipv4_prefix = None
        bp_ipv6_prefix = None

        for vm_config in vm_configs.values():
            bp_interface = vm_config.get('bp_interface', {})
            if bp_interface:
                # Extract only the prefix length (e.g., "24" from "10.10.246.29/24")
                if not bp_ipv4_prefix and bp_interface.get('ipv4'):
                    bp_ipv4_with_prefix = bp_interface['ipv4']
                    bp_ipv4_prefix = bp_ipv4_with_prefix.split('/')[-1] if '/' in bp_ipv4_with_prefix else None

                if not bp_ipv6_prefix and bp_interface.get('ipv6'):
                    bp_ipv6_with_prefix = bp_interface['ipv6']
                    bp_ipv6_prefix = bp_ipv6_with_prefix.split('/')[-1] if '/' in bp_ipv6_with_prefix else None

                # Break if we found both prefix lengths
                if bp_ipv4_prefix and bp_ipv6_prefix:
                    break

        # Construct PTF backplane IP addresses by combining nhipv4/nhipv6 with prefix lengths
        ptf_bp_ipv4 = f"{bp_ipv4_addr}/{bp_ipv4_prefix}" if bp_ipv4_addr and bp_ipv4_prefix else None
        ptf_bp_ipv6 = f"{bp_ipv6_addr}/{bp_ipv6_prefix}" if bp_ipv6_addr and bp_ipv6_prefix else None

        if ptf_bp_ipv4 or ptf_bp_ipv6:
            ptf_interface_ip_args.append({
                'namespace_pid': ptf_pid,
                'interface_name': 'backplane',
                'ipv4': ptf_bp_ipv4,
                'ipv6': ptf_bp_ipv6
            })

        # Assign all PTF interface IPs concurrently
        await asyncio.gather(*[
            self._assign_namespace_interface_ip(**ip_args)
            for ip_args in ptf_interface_ip_args
        ])

    async def deploy(self):
        """Deploy topology connections.

        Returns:
            dict: Result dictionary with changed status and message

        Raises:
            docker.errors.NotFound: If container is not found
            Exception: If failed to get container PID
        """
        # Get testbed index for later use
        testbed_index = self.testbed_resources.get('index')

        # Collect container names from resources
        ptf_name = None
        ptf_resources = self.testbed_resources.get('ptf', {})
        if ptf_resources:
            ptf_name = list(ptf_resources.keys())[0]

        neighbor_names = []
        if self.neighbor_type == 'ceos':
            neighbor_resources = self.testbed_resources.get('neighbors', {})
            neighbor_names = list(neighbor_resources.keys())

        # Build container names list for PID collection
        container_names = []
        if ptf_name:
            container_names.append(ptf_name)
        # For cEOS neighbors, prepend 'net_' to neighbor names
        container_names.extend([f"net_{name}" for name in neighbor_names])

        # Collect PIDs for all containers
        container_pids = await self._collect_container_pids(container_names)

        # Extract PTF and neighbor PIDs from result
        ptf_pid = container_pids.get(ptf_name) if ptf_name else None
        neighbor_pids = {name: container_pids.get(f"net_{name}") for name in neighbor_names}

        # Collect all PTF interfaces
        all_ptf_interfaces = self._collect_ptf_interfaces()

        # Get PTF interface names
        ptf_interface_names = self._get_ptf_interface_names(ptf_name, all_ptf_interfaces)

        # Get DUT interface names
        dut_interface_names = self._get_dut_interface_names()

        # Get neighbor interface names
        neighbor_interface_names = self._get_all_neighbor_interface_names()

        # Build interface configuration arguments for all components
        ptf_veth_args, ptf_attach_args = self._build_ptf_interface_args(
            ptf_pid, ptf_interface_names, testbed_index
        )
        dut_attach_args = self._build_dut_interface_args(dut_interface_names, testbed_index)
        neighbor_veth_args, neighbor_attach_args = self._build_neighbor_interface_args(
            neighbor_pids, neighbor_interface_names, testbed_index
        )

        # Combine all arguments
        veth_creation_args = ptf_veth_args + neighbor_veth_args
        interface_attachment_args = ptf_attach_args + dut_attach_args + neighbor_attach_args

        # Create veth pairs and attach to namespaces concurrently
        await asyncio.gather(*[
            self._create_veth_to_namespace(**veth_args)
            for veth_args in veth_creation_args
        ])

        # Create OVS bridges with all ports
        await self._create_ovs_bridges(interface_attachment_args, testbed_index)

        # Build and apply OpenFlow rules for dataplane bridge
        openflow_rules = self._build_dataplane_flows(ptf_interface_names, dut_interface_names, neighbor_interface_names)
        await self._apply_dataplane_flows(openflow_rules, testbed_index)

        # Assign IP addresses to bridges
        await self._assign_bridge_ips()

        # Assign IP addresses to PTF interfaces
        await self._assign_ptf_interface_ips(ptf_pid, ptf_name)

        self.changed = True
        self.msg = 'Topology deployment completed'

        return self._build_result()

    async def undeploy(self):
        """Undeploy topology connections.

        Removes OVS bridges and veth pairs. Uses the same interface name generation
        functions as deploy() to identify which veth pairs to delete.

        Returns:
            dict: Result dictionary with changed status and message
        """
        # Get testbed index for bridge names
        testbed_index = self.testbed_resources.get('index')

        if testbed_index is None:
            self.changed = False
            self.msg = 'No testbed index found, nothing to undeploy'
            return self._build_result()

        # Collect all interface names using the same functions as deploy
        veth_interfaces_to_delete = []

        # PTF interfaces
        ptf_resources = self.testbed_resources.get('ptf', {})
        if ptf_resources:
            ptf_name = list(ptf_resources.keys())[0]
            all_ptf_interfaces = self._collect_ptf_interfaces()
            ptf_interface_names = self._get_ptf_interface_names(ptf_name, all_ptf_interfaces)

            if ptf_interface_names['management']:
                veth_interfaces_to_delete.append(ptf_interface_names['management'])
            veth_interfaces_to_delete.extend(ptf_interface_names['dataplane'])
            if ptf_interface_names['backplane']:
                veth_interfaces_to_delete.append(ptf_interface_names['backplane'])

        # Neighbor interfaces
        neighbor_interface_names = self._get_all_neighbor_interface_names()
        for interface_names in neighbor_interface_names.values():
            if interface_names['management']:
                veth_interfaces_to_delete.append(interface_names['management'])
            veth_interfaces_to_delete.extend(interface_names['dataplane'])
            if interface_names['backplane']:
                veth_interfaces_to_delete.append(interface_names['backplane'])

        # Define bridge names
        bridges = [
            f"br{testbed_index}m",
            f"br{testbed_index}b",
            f"br{testbed_index}d"
        ]

        # Build deletion tasks
        delete_tasks = []

        # Add veth interface deletion tasks
        for veth_interface in veth_interfaces_to_delete:
            delete_tasks.append(
                self._run(
                    f"ip link delete {veth_interface}",
                    check=False,
                    ignore_errors=True
                )
            )

        # Add bridge deletion tasks
        for bridge_name in bridges:
            delete_tasks.append(
                self._run(
                    f"ovs-vsctl --if-exists del-br {bridge_name}",
                    check=False,
                    ignore_errors=True
                )
            )


        # Execute all deletions concurrently
        await asyncio.gather(*delete_tasks)

        self.changed = True
        self.msg = f'Topology undeployment completed for testbed index {testbed_index}'

        return self._build_result()

    async def execute(self):
        """Execute the requested operation.

        Returns:
            dict: Result dictionary based on operation

        Raises:
            Exception: If operation is invalid
        """
        operations = {
            'deploy': self.deploy,
            'undeploy': self.undeploy
        }

        operation_method = operations.get(self.operation)
        if not operation_method:
            raise ValueError(f"Invalid operation: {self.operation}")

        return await operation_method()

    def _build_result(self):
        """Build result dictionary for Ansible.

        Returns:
            dict: Result with changed, msg, and topology
        """
        result = {
            'changed': self.changed,
            'msg': self.msg,
            'topology': self.topology_definition
        }

        return result


def main():
    """Main module execution."""

    module_args = dict(
        operation=dict(type='str', required=True, choices=['deploy', 'undeploy']),
        topology_definition=dict(type='dict', required=False, default={}),
        testbed_resources=dict(type='dict', required=False, default={}),
        neighbor_type=dict(type='str', required=False)
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    try:
        tb_topo = TestbedTopology(module)
        # Run async execute() in sync context
        result = asyncio.run(tb_topo.execute())
        module.exit_json(**result)

    except Exception as e:
        module.fail_json(msg=f"Module execution failed: {str(e)}", changed=False)


if __name__ == '__main__':
    main()
