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
        type: str
        required: false
author:
    - Testbed Automation Team
'''

EXAMPLES = r'''
# Deploy topology connections
- name: Deploy testbed topology
  tb_topology:
    operation: deploy
    neighbor_type: arista
    topology_definition:
      duts: []
      neighbors: []
      ptf: []
    testbed_resources:
      vcpus: 4
      memory: 8192

# Undeploy topology connections
- name: Undeploy testbed topology
  tb_topology:
    operation: undeploy
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

    async def create_veth_to_namespace(self, namespace_pid, veth_external, veth_internal):
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

    async def create_ovs_bridge(self, bridge_name, clear_flows=False):
        """Create Open vSwitch bridge.

        Args:
            bridge_name: Name for the OVS bridge
            clear_flows: If True, delete all flows and set secure mode.
                        If False, keep default flows (bridge acts like a normal switch).

        Raises:
            subprocess.CalledProcessError: If any command fails
        """
        # Create OVS bridge (--may-exist makes this idempotent)
        await self._run(
            f"ovs-vsctl --may-exist add-br {bridge_name}"
        )

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

    async def attach_interface_to_bridge(self, bridge_name, interface_name):
        """Attach a network interface to an OVS bridge.

        Args:
            bridge_name: Name of the OVS bridge
            interface_name: Name of the interface to attach

        Raises:
            subprocess.CalledProcessError: If command fails
        """
        # Use --may-exist to make this idempotent
        await self._run(
            f"ovs-vsctl --may-exist add-port {bridge_name} {interface_name}"
        )

    async def assign_bridge_ip(self, bridge_name, ipv4=None, ipv6=None):
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

    async def deploy(self):
        """Deploy topology connections.

        Returns:
            dict: Result dictionary with changed status and message

        Raises:
            docker.errors.NotFound: If container is not found
            Exception: If failed to get container PID
        """
        # Collect PTF container PID and name
        ptf_pid = None
        ptf_name = None
        ptf_resources = self.testbed_resources.get('ptf', {})
        if ptf_resources:
            # Get the first (and typically only) PTF container name
            ptf_name = list(ptf_resources.keys())[0]
            ptf_pid = await self._get_container_pid(ptf_name)

        # Collect neighbor container PIDs for ceos neighbor type
        neighbor_pids = {}
        if self.neighbor_type == 'ceos':
            neighbor_resources = self.testbed_resources.get('neighbors', {})
            neighbor_names = list(neighbor_resources.keys())
            if neighbor_names:
                # Get all PIDs concurrently
                pids = await asyncio.gather(*[
                    self._get_container_pid(f"net_{neighbor_name}")
                    for neighbor_name in neighbor_names
                ])
                # Map PIDs to neighbor names
                neighbor_pids = dict(zip(neighbor_names, pids))

        # Build mapping between testbed_resources neighbor names and topology_definition neighbor names
        # Both lists are natsorted to create 1-to-1 mapping
        resource_to_topo = {}
        topo_to_resource = {}

        if self.topology_definition.get('configuration'):
            # Get neighbor names from topology definition configurations
            topo_neighbors = natsorted(self.topology_definition['configuration'].keys())

            # Get neighbor names from testbed resources
            resource_neighbors = natsorted(self.testbed_resources.get('neighbors', {}).keys())

            # Create bidirectional mapping
            for resource_name, topo_name in zip(resource_neighbors, topo_neighbors):
                resource_to_topo[resource_name] = topo_name
                topo_to_resource[topo_name] = resource_name

        # Get testbed index for bridge names
        testbed_index = self.testbed_resources.get('index')

        # Prepare veth creation and interface attachment arguments together
        veth_creation_args = []
        interface_attachment_args = []

        # Process PTF container interfaces
        if ptf_pid and ptf_name:
            # Management interface
            veth_external = f"{ptf_name}-m"
            veth_creation_args.append({
                'namespace_pid': ptf_pid,
                'veth_external': veth_external,
                'veth_internal': 'mgmt'
            })
            interface_attachment_args.append({
                'bridge_name': f"br{testbed_index}m",
                'interface_name': veth_external
            })

            # Data plane interfaces based on topology definition
            topo_config = self.topology_definition.get('topology', {})
            host_interfaces = topo_config.get('host_interfaces', [])
            disabled_host_interfaces = topo_config.get('disabled_host_interfaces', [])

            # Collect VLAN interfaces from VMs configuration
            vms_config = topo_config.get('VMs', {})
            vlan_interfaces = []
            for vm_config in vms_config.values():
                vlan_interfaces.extend(vm_config.get('vlans', []))

            # Combine all PTF dataplane interfaces
            all_ptf_interfaces = set(host_interfaces + disabled_host_interfaces + vlan_interfaces)

            for interface_num in all_ptf_interfaces:
                veth_external = f"{ptf_name}-{interface_num}"
                veth_creation_args.append({
                    'namespace_pid': ptf_pid,
                    'veth_external': veth_external,
                    'veth_internal': f"eth{interface_num}"
                })
                interface_attachment_args.append({
                    'bridge_name': f"br{testbed_index}d",
                    'interface_name': veth_external
                })

            # Backplane interface
            veth_external = f"{ptf_name}-b"
            veth_creation_args.append({
                'namespace_pid': ptf_pid,
                'veth_external': veth_external,
                'veth_internal': 'backplane'
            })
            interface_attachment_args.append({
                'bridge_name': f"br{testbed_index}b",
                'interface_name': veth_external
            })

        # Process KVM DUT interfaces (no veth creation, only attachment)
        if self.testbed_resources.get('type') == 'kvm':
            dut_resources = self.testbed_resources.get('duts', {})

            for dut_name in dut_resources.keys():
                # Management interface: {dut_name}-0
                interface_attachment_args.append({
                    'bridge_name': f"br{testbed_index}m",
                    'interface_name': f"{dut_name}-0"
                })

                # Dataplane interfaces: {dut_name}-1, {dut_name}-2, etc.
                # DUT interfaces correspond to PTF interfaces: {dut_name}-1 -> PTF eth0, {dut_name}-2 -> PTF eth1, etc.
                for idx, ptf_interface_num in enumerate(sorted(all_ptf_interfaces), start=1):
                    interface_attachment_args.append({
                        'bridge_name': f"br{testbed_index}d",
                        'interface_name': f"{dut_name}-{idx}"
                    })

        # Process neighbor container interfaces
        for neighbor_name, neighbor_pid in neighbor_pids.items():
            # Management interface
            veth_external = f"{neighbor_name}-m"
            veth_creation_args.append({
                'namespace_pid': neighbor_pid,
                'veth_external': veth_external,
                'veth_internal': 'eth0'
            })
            interface_attachment_args.append({
                'bridge_name': f"br{testbed_index}m",
                'interface_name': veth_external
            })

            # Data plane and backplane interfaces
            vm_name = resource_to_topo.get(neighbor_name)
            if vm_name:
                neighbor_config = self.topology_definition.get('configuration', {}).get(vm_name, {})
                interfaces = neighbor_config.get('interfaces', {})

                # Process all Ethernet interfaces and track max interface number
                max_interface_num = 0
                for interface_name in interfaces.keys():
                    if interface_name.startswith('Ethernet'):
                        interface_num = interface_name.replace('Ethernet', '')
                        interface_num_int = int(interface_num)
                        max_interface_num = max(max_interface_num, interface_num_int)

                        # Dataplane interface
                        veth_external = f"{neighbor_name}-t{interface_num_int - 1}"
                        veth_creation_args.append({
                            'namespace_pid': neighbor_pid,
                            'veth_external': veth_external,
                            'veth_internal': f"eth{interface_num}"
                        })
                        interface_attachment_args.append({
                            'bridge_name': f"br{testbed_index}d",
                            'interface_name': veth_external
                        })

                # Backplane interface
                backplane_interface_num = max_interface_num + 1
                veth_external = f"{neighbor_name}-b"
                veth_creation_args.append({
                    'namespace_pid': neighbor_pid,
                    'veth_external': veth_external,
                    'veth_internal': f"eth{backplane_interface_num}"
                })
                interface_attachment_args.append({
                    'bridge_name': f"br{testbed_index}b",
                    'interface_name': veth_external
                })

        # Create veth pairs and attach to namespaces concurrently
        await asyncio.gather(*[
            self.create_veth_to_namespace(**veth_args)
            for veth_args in veth_creation_args
        ])

        # Prepare OVS bridge creation arguments
        bridge_creation_args = []

        # Management bridge (no flow clearing - acts like normal switch)
        bridge_creation_args.append({
            'bridge_name': f"br{testbed_index}m",
            'clear_flows': False
        })

        # Backplane bridge (no flow clearing - acts like normal switch)
        bridge_creation_args.append({
            'bridge_name': f"br{testbed_index}b",
            'clear_flows': False
        })

        # Dataplane bridge (clear flows - explicit flow control)
        bridge_creation_args.append({
            'bridge_name': f"br{testbed_index}d",
            'clear_flows': True
        })

        # Create OVS bridges concurrently
        await asyncio.gather(*[
            self.create_ovs_bridge(**bridge_args)
            for bridge_args in bridge_creation_args
        ])

        # Assign IP addresses to bridges
        bridge_ip_args = []
        bridge_resources = self.testbed_resources.get('bridge', {})
        for bridge_name, ip_config in bridge_resources.items():
            bridge_ip_args.append({
                'bridge_name': bridge_name,
                'ipv4': ip_config.get('ipv4'),
                'ipv6': ip_config.get('ipv6')
            })

        await asyncio.gather(*[
            self.assign_bridge_ip(**ip_args)
            for ip_args in bridge_ip_args
        ])

        # Attach all interfaces to bridges concurrently
        await asyncio.gather(*[
            self.attach_interface_to_bridge(**attachment_args)
            for attachment_args in interface_attachment_args
        ])

        self.changed = True
        self.msg = 'Topology deployment completed'

        return self._build_result()

    async def undeploy(self):
        """Undeploy topology connections.

        Returns:
            dict: Result dictionary with changed status and message
        """
        # TODO: Implement topology undeployment logic

        self.changed = True
        self.msg = 'Topology undeployment not yet implemented'

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
