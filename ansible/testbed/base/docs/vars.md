# Host and group variables

Before this library, host and group variables could be specified in 3 places:
* ansible/host_vars/<hostname>.yml
* ansible/group_vars/<group>/<any_file>.yml
* Inventory files

With this library, variables specified under ansible/host_vars and ansible/group_vars are still valid and will be loaded automatically.
However, because this library dynamically generates inventory files, variables specified in existing inventory files will not be loaded since the legacy inventory files are not used by this library.

With this library, alternatively, host and group variables can be specified in the following files:
* ansible/files/sonic_<group>_host_vars.yml
* ansible/files/sonic_<group>_group_vars.yml

Here, each `<group>` corresponds to the devices connected to a root fanout switch. The `<group>` here is different from the Ansible inventory group.

In file ansible/files/sonic_<group>_host_vars.yml, the top-level key is the host name, such as `vlab-01`, `server_1`, etc.

In file ansible/files/sonic_<group>_group_vars.yml, the top-level key is the Ansible inventory group name, such as `server`, `ptf`, `all`, etc.

Summary table of host and group variables


Location | Before this library | With this library
--- | --- | ---
ansible/host_vars/<hostname>.yml | Yes | Yes
ansible/group_vars/<group>/<any_file>.yml | Yes | Yes
Inventory files | Yes | No
ansible/files/sonic_<group>_host_vars.yml | No | Yes
ansible/files/sonic_<group>_group_vars.yml | No | Yes

# How to get host and group variables

```python
from ansible.testbed.base.ansible_hosts import AnsibleHost, AnsibleHosts
# Create AnsibleHost instance
dut = AnsibleHost(
    inventory='veos_vtb',
    pattern='vlab-01'
)
duts = AnsibleHosts(
    inventory='veos_vtb',
    pattern=['vlab-01', 'vlab-02']
)

dut.host_vars  # Get all host variables as a dict
dut.visible_vars  # Get all variables visible to host (host vars merged with group vars)
dut.get_host_var('ansible_user')  # Get specific host variable
dut.get_host_var('ansible_hostv6', default='::1')  # Get specific host variable with default value
dut.get_visible_var('asic_type', default='unknown')  # Get variable visible to host (host vars merged with group vars)

# For AnsibleHosts instance, specify the host name as the first argument
duts.get_host_var('vlab-02', 'ansible_user')  # Get specific host variable for host 'vlab-02'
duts.get_visible_var('vlab-01', 'port_alias', default={})
```
