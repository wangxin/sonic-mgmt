import logging

from pathlib import Path
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

from .testbed import Testbed, get_testbed
from .inventory import generate_group_inventory_file, generate_testbed_inventory_file
from .base import AnsibleHosts, AnsibleLocalhost
from .deploy import _get_all_deployed_testbeds
from .settings import CONSTANTS as C
from .base.server import TestServer

logger = logging.getLogger(__name__)


def configure_duts(
        testbed_file: str,
        testbed_name: str,
        server: str | None = None,
):
    """
    Configure DUTs in a testbed.

    Args:
        testbed_file: Path to testbed configuration file
        testbed_name: Name of the testbed to configure
        server: Target server name (optional, will auto-detect from deployed testbed)
    """
    logger.info(f"Starting configuration of testbed '{testbed_name}' from '{testbed_file}'")

    # Initialize the testbed object
    testbed: Testbed = get_testbed(testbed_file, testbed_name)
    if testbed is None:
        raise ValueError(f"Testbed '{testbed_name}' not found in file '{testbed_file}'")

    logger.debug(f"Loaded testbed configuration: group={testbed.group}, type={testbed.topology}")

    # Prepare the group inventory file
    logger.debug(f"Generating group inventory file for group '{testbed.group}'")
    group_inventory_file = generate_group_inventory_file(testbed.group, refresh=True)

    # Find the deployed testbed
    # If server specified, only check that server; otherwise check all servers in the group
    host_pattern = server if server else 'server'
    logger.info(f"Checking for deployed testbed on: {host_pattern}")
    servers = AnsibleHosts(group_inventory_file, host_pattern)
    deployed_testbeds = _get_all_deployed_testbeds(servers)

    # Search for the testbed in the results
    deployed_testbed_info = None

    for server_name, deployed_testbeds_info in deployed_testbeds.items():
        for deployed_testbed in deployed_testbeds_info.get('testbeds', []):
            if deployed_testbed.get('name') == testbed_name:
                server = server_name
                deployed_testbed_info = deployed_testbed
                logger.info(f"Found testbed '{testbed_name}' deployed on server '{server_name}'")
                break
        if deployed_testbed_info:
            break

    if deployed_testbed_info is None:
        if server:
            raise ValueError(f"Testbed '{testbed_name}' is not deployed on server '{server}'.")
        else:
            raise ValueError(f"Testbed '{testbed_name}' is not deployed on any server.")

    logger.debug(f"Deployed testbed info: {deployed_testbed_info}")


    # Verify the testbed is in deployed status
    testbed_status = deployed_testbed_info.get('status')
    if testbed_status != 'deployed':
        raise ValueError(
            f"Testbed '{testbed_name}' on server '{server}' has status '{testbed_status}', "
            f"but expected 'deployed'. Cannot configure testbed that is not fully deployed."
        )

    # Generate testbed inventory file
    logger.info(f"Generating testbed inventory file for '{testbed.name}'")
    testbed_inventory_file = generate_testbed_inventory_file(
        testbed=testbed,
        testbed_resources=deployed_testbed_info,
        selected_server=server,
        refresh=True
    )
    logger.info(f"Testbed inventory file generated: {testbed_inventory_file}")

    server_host = TestServer(testbed_inventory_file, server)

    # Ensure local SSH public key is in server's authorized_keys
    logger.debug("Adding local SSH public key to server's authorized_keys")
    local_ssh_pubkey_path = Path.home() / '.ssh' / 'id_rsa.pub'
    if not local_ssh_pubkey_path.exists():
        raise FileNotFoundError(
            f"Local SSH public key not found at {local_ssh_pubkey_path}. "
            f"Please generate one using: ssh-keygen -t rsa"
        )

    with open(local_ssh_pubkey_path, 'r') as f:
        ssh_pubkey = f.read().strip()
    server_host.authorized_key(
        user="{{ ansible_user }}",
        key=ssh_pubkey,
        state="present"
    )
    proxy_user = server_host.get_host_var('ansible_user', default=None)
    proxy_host = server_host.get_host_var('ansible_host', default=None)
    if proxy_user is None or proxy_host is None:
        raise ValueError(
            f"Failed to retrieve 'ansible_user' or 'ansible_host' for server '{server}'. "
            f"Cannot set up SSH proxy."
        )
    dut_hosts = AnsibleHosts(
        testbed_inventory_file,
        'duts',
        hostvars={
            # 'ansible_ssh_extra_args': f'-o ProxyJump="{proxy_user}@{proxy_host} -i ~/.ssh/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no" -o ControlMaster=no -o ControlPath=none'
            # 'ansible_ssh_extra_args': f'-o PreferredAuthentications=password -o IPQoS=throughput -T -J "{proxy_user}@{proxy_host} -i ~/.ssh/id_rsa -o RequestTTY=no -T -o ControlMaster=no -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"'
            # 'ansible_ssh_args': f'-T -o ProxyJump="{proxy_user}@{proxy_host} -i ~/.ssh/id_rsa -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no" -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ServerAliveCountMax=40 -o TCPKeepAlive=yes -o IPQoS=throughput -o Compression=no'
            'ansible_ssh_extra_args': f'-o ProxyJump="{proxy_user}@{proxy_host} -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"',
            # 'ansible_ssh_extra_args': f'-F /home/ubuntu/code/sonic-mgmt-ng/ansible/_ssh_config'
        }
    )

    # Determine template file name and path
    template_name = "minigraph_template.j2"
    template_dir = Path(C.ANSIBLE_DIR) / 'templates'
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

    # Load the minigraph template
    minigraph_template = jinja_env.get_template(template_name)

    localhost = localhost = AnsibleLocalhost(testbed_inventory_file)

    all_sysports = []
    all_inbands = {}
    all_inbands_ipv6 = {}
    all_loopback4096 = {}
    all_loopback4096_ipv6 = {}
    all_slots = {}
    for dut_host in dut_hosts:
        sysports = dut_host.visible_vars.get('all_sysports', [])
        all_sysports.extend(sysports)

        voq_inband_ip = dut_host.visible_vars.get('voq_inband_ip', None)
        if voq_inband_ip is not None:
            all_inbands[dut_host.hostname] = voq_inband_ip

        voq_inband_ipv6 = dut_host.visible_vars.get('voq_inband_ipv6', None)
        if voq_inband_ipv6 is not None:
            all_inbands_ipv6[dut_host.hostname] = voq_inband_ipv6

        loopback4096_ip = dut_host.visible_vars.get('loopback4096_ip', None)
        if loopback4096_ip is not None:
            all_loopback4096[dut_host.hostname] = loopback4096_ip

        loopback4096_ipv6 = dut_host.visible_vars.get('loopback4096_ipv6', None)
        if loopback4096_ipv6 is not None:
            all_loopback4096_ipv6[dut_host.hostname] = loopback4096_ipv6

        slot_num = dut_host.visible_vars.get('slot_num', None)
        if slot_num is not None:
            all_slots[dut_host.hostname] = slot_num

    for dut_index, dut_host in enumerate(dut_hosts):

        hwsku = dut_host.visible_vars.get('hwsku', '')
        asics_present= dut_host.visible_vars.get('asics_present', [])
        num_asics = dut_host.visible_vars.get('num_asics', 1)
        card_type= dut_host.visible_vars.get('card_type', None)
        iface_speed = dut_host.visible_vars.get('iface_speed', 0)
        breakout_speed = dut_host.visible_vars.get('breakout_speed', {})


        topo_facts = localhost.topo_facts(
            topo=testbed.topology,
            hwsku=hwsku,
            testbed_name=testbed.name,
            asics_present=asics_present,
            card_type=card_type if card_type is not None else 'fixed',
        ).get('ansible_facts', {})
        vm_topo_config = topo_facts.get('vm_topo_config', {})

        port_alias_facts = localhost.port_alias(
            hwsku=hwsku,
            num_asic=num_asics,
        ).get('ansible_facts', {})
        port_alias = port_alias_facts.get('port_alias', [])
        port_alias_map = port_alias_facts.get('port_alias_map', {})
        port_name_map = port_alias_facts.get('port_name_map', {})
        port_name = list(port_name_map.keys())
        port_speed = port_alias_facts.get('port_speed', {})
        portchannel_config = vm_topo_config.get('DUT', {}).get('portchannel_config', {})

        intf_names = {}
        for _vm_name, _vm_info in vm_topo_config.get('vm', {}).items():
            _vm_all_intf_indexes = _vm_info.get('interface_indexes', [])
            _vm_intf_indexes = _vm_all_intf_indexes[dut_index] if dut_index < len(_vm_all_intf_indexes) else []
            _vm_intf_names = [port_alias[intf] for intf in _vm_intf_indexes]
            intf_names[_vm_name] = _vm_intf_names

        conn_graph_facts = localhost.conn_graph_facts(
            host=dut_host.hostname,
            group=testbed.group,
        ).get('ansible_facts', {})

        # Build VLAN interfaces list from enabled host interfaces
        host_interfaces_by_dut = vm_topo_config.get('host_interfaces_by_dut', [])
        disabled_host_interfaces_by_dut = vm_topo_config.get('disabled_host_interfaces_by_dut', [])

        dut_host_interfaces = host_interfaces_by_dut[dut_index] if dut_index < len(host_interfaces_by_dut) else []
        dut_disabled_host_interfaces = (
            disabled_host_interfaces_by_dut[dut_index]
            if dut_index < len(disabled_host_interfaces_by_dut)
            else []
        )
        dut_enabled_host_interfaces = set(dut_host_interfaces) - set(dut_disabled_host_interfaces)
        vlan_intfs = [port_alias[intf] for intf in dut_enabled_host_interfaces]

        vlan_configs = localhost.vlan_config(
            vm_topo_config=vm_topo_config,
            port_alias=port_alias,
            vlan_config='',
        ).get('ansible_facts', {}).get('vlan_configs', {})


        # Prepare template variables
        template_vars = {
            # Basic topology and hardware info
            'topo': testbed.topology,
            'vm_topo_config': vm_topo_config,
            'inventory_hostname': dut_host.hostname,
            'hwsku': hwsku,
            'num_asics': num_asics,

            # Port and interface mappings
            'port_alias': port_alias,
            'port_name': port_name,
            'port_alias_map': port_alias_map,
            'port_name_map': port_name,
            'port_speed': port_speed,
            'intf_names': intf_names,
            'portchannel_config': portchannel_config,

            # DUT index for multi-DUT topologies
            'dut_index': dut_index,

            # Device connection information
            'device_conn': conn_graph_facts.get('device_conn', {}),

            # Interface speed configuration
            'iface_speed': iface_speed,
            'breakout_speed': breakout_speed,

            # VOQ and system port configuration (for voq switch types)
            'all_sysports': all_sysports,
            'all_inbands': all_inbands,
            'all_inbands_ipv6': all_inbands_ipv6,
            'all_loopback4096': all_loopback4096,
            'all_loopback4096_ipv6': all_loopback4096_ipv6,
            'all_slots': all_slots,

            # ASIC topology configuration (for multi-ASIC)
            'asic_topo_config': topo_facts.get('asic_topo_config', {}),
            'front_panel_asic_ifnames': port_alias_facts.get('front_panel_asic_ifnames', []),

            # VLAN interfaces (for servers/hosts)
            'vlan_intfs': vlan_intfs,
            'vlan_configs': vlan_configs,

            # Dual-ToR specific
            'dual_tor_facts': {},
            'mux_cable_facts': {},
            'tunnel_configs': {},

            # MACsec configuration
            # 'macsec_card': '',
            # 'enable_macsec': '',

            # Auto-negotiation
            'msft_an_enabled': '',
        }

        switch_type = dut_host.visible_vars.get('switch_type', None)
        if switch_type is not None:
            template_vars['switch_type'] = switch_type

        subtype = dut_host.visible_vars.get('subtype', None)
        if subtype is not None:
            template_vars['subtype'] = subtype

        if card_type is not None:
            template_vars['card_type'] = card_type

        slot_num = dut_host.visible_vars.get('slot_num', None)
        if slot_num is not None:
            template_vars['slot_num'] = slot_num

        msft_an_enabled = dut_host.visible_vars.get('msft_an_enabled', None)
        if msft_an_enabled is not None:
            template_vars['msft_an_enabled'] = msft_an_enabled

        minigraph_content = minigraph_template.render(template_vars)

        # Save a copy to localhost for debugging
        local_minigraph_dir = Path(C.ANSIBLE_DIR) / 'minigraph'
        local_minigraph_dir.mkdir(parents=True, exist_ok=True)
        local_minigraph_path = local_minigraph_dir / f'minigraph_{dut_host.hostname}.xml'
        logger.debug(f"Saving minigraph to {local_minigraph_path} for debugging")
        with open(local_minigraph_path, 'w') as f:
            f.write(minigraph_content)

        dut_host.command('pwd')
        # dut_host.command('date')
        # dut_host.copy(
        #     content=minigraph_content,
        #     dest='/etc/sonic/minigraph.xml',
        #     mode="0644",
        #     task_directives={"become": True}
        # )

    # TODO: Implement DUT configuration logic
    # logger.info(f"DUT configuration for testbed '{testbed_name}' not yet implemented")