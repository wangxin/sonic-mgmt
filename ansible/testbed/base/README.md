# Run Ansible in Python

Ansible is an agentless tool that can perform operations on remote hosts through SSH or other connections. For SONiC testbed deployment and testing, nearly all devices in a testbed are accessible via SSH, making Ansible an ideal tool for these tasks. Over the years, the community has developed extensive code on top of Ansible in the sonic-mgmt repository, including numerous customized modules and plugins that are heavily used.

For testbed deployment, Ansible playbooks invoke various built-in and customized modules. For SONiC testing, pytest-based scripts leverage Ansible through the pytest-ansible plugin.

## Motivation

This library addresses several limitations of the current approach:

* **Limited expressiveness**: Ansible playbooks are YAML-based and lack the full capabilities of a programming language. Complex data processing and flexible code reuse are challenging. By running Ansible modules directly from Python, we gain access to a full-featured programming language to address these limitations.

* **Dependency constraints**: While pytest-based scripts can execute Ansible modules through the pytest-ansible plugin, this approach requires a pytest environment. This is impractical for general-purpose Python CLI tools that shouldn't need to run as pytest test scripts. Additionally, the pytest-ansible plugin doesn't support all Ansible features.

## Benefits

This library enables you to execute any Ansible module on remote hosts directly from Python, without additional dependencies. Python's capabilities—including sophisticated data processing, flexible code reuse, better performance, and more—make tasks that are difficult in playbooks straightforward to implement.

## Quick Example

Assume we have a typical container-based "vms-kvm-t0" testbed deployed (https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.VsSetup.md). Below is a simple example of calling the `command` ansible module to run command `hostname` on the `vlab-0` device.

```
xiwang5@sonic-mgmt:/data/code/sonic-mgmt/ansible$ python
Python 3.12.3 (main, Aug 14 2025, 17:47:21) [GCC 13.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from testbed.base.ansible_hosts import AnsibleHost, AnsibleHosts
>>> dut = AnsibleHost('veos_vtb', 'vlab-01')
>>> res = dut.command('hostname')
>>> from pprint import pprint as pp
>>> pp(res)
{'_ansible_no_log': False,
 '_task_fields': {'action': 'command',
                  'become': None,
                  'become_method': 'sudo',
                  'become_user': None,
                  'connection': 'ssh',
                  'ignore_errors': False,
                  'ignore_unreachable': None,
                  'register': None,
                  'retries': None,
                  'timeout': 0},
 'ansible_facts': {'discovered_interpreter_python': '/usr/bin/python3.11'},
 'changed': True,
 'cmd': ['hostname'],
 'delta': '0:00:00.018778',
 'end': '2025-12-04 08:34:03.458685',
 'failed': False,
 'hostname': 'vlab-01',
 'invocation': {'module_args': {'_raw_params': 'hostname',
                                '_uses_shell': False,
                                'argv': None,
                                'chdir': None,
                                'creates': None,
                                'executable': None,
                                'expand_argument_vars': True,
                                'removes': None,
                                'stdin': None,
                                'stdin_add_newline': True,
                                'strip_empty_ends': True},
                'module_name': 'command'},
 'msg': '',
 'rc': 0,
 'reachable': True,
 'start': '2025-12-04 08:34:03.439907',
 'stderr': '',
 'stderr_lines': [],
 'stdout': 'vlab-01',
 'stdout_lines': ['vlab-01']}
>>>
>>> neighbors = AnsibleHosts('veos_vtb', ['VM0100', 'VM0101'], hostvars={'ansible_connection': 'network_cli', 'ansible_network_os': 'eos', 'ansible_user': 'admin', 'ansible_password': '123456'})
>>> res = neighbors.eos_command(commands='show version')
>>> pp(res)
{'VM0100': {'_ansible_no_log': False,
            '_task_fields': {'action': 'eos_command',
                             'become': None,
                             'become_method': 'sudo',
                             'become_user': None,
                             'connection': 'ssh',
                             'ignore_errors': False,
                             'ignore_unreachable': None,
                             'register': None,
                             'retries': None,
                             'timeout': 0},
            'changed': False,
            'failed': False,
            'hostname': 'VM0100',
            'invocation': {'module_args': {'commands': ['show version'],
                                           'interval': 1,
                                           'match': 'all',
                                           'retries': 10,
                                           'wait_for': None},
                           'module_name': 'eos_command'},
            'reachable': True,
            'stdout': ['Arista cEOSLab\nHardware version: \nSerial number: 7A8266BB08BE6CEEC9DC486E99B18540\nHardware MAC address: 1a98.6eff.d5c2\nSystem MAC address: 1a98.6eff.d5c2\n\nSoftware image version: 4.32.5M-41241764.4325M (engineering build)\nArchitecture: x86_64\nInternal build version: 4.32.5M-41241764.4325M\nInternal build ID: a14e5148-5c2b-40f1-98fc-58e12706de3a\nImage format version: 1.0\nImage optimization: None\n\nKernel version: 6.8.0-1041-azure\n\nUptime: 2 weeks, 0 days, 7 hours and 6 minutes\nTotal memory: 32816864 kB\nFree memory: 13906184 kB'],
            'stdout_lines': [['Arista cEOSLab',
                              'Hardware version: ',
                              'Serial number: 7A8266BB08BE6CEEC9DC486E99B18540',
                              'Hardware MAC address: 1a98.6eff.d5c2',
                              'System MAC address: 1a98.6eff.d5c2',
                              '',
                              'Software image version: 4.32.5M-41241764.4325M (engineering build)',
                              'Architecture: x86_64',
                              'Internal build version: 4.32.5M-41241764.4325M',
                              'Internal build ID: a14e5148-5c2b-40f1-98fc-58e12706de3a',
                              'Image format version: 1.0',
                              'Image optimization: None',
                              '',
                              'Kernel version: 6.8.0-1041-azure',
                              '',
                              'Uptime: 2 weeks, 0 days, 7 hours and 6 minutes',
                              'Total memory: 32816864 kB',
                              'Free memory: 13906184 kB']]},
 'VM0101': {'_ansible_no_log': False,
            '_task_fields': {'action': 'eos_command',
                             'become': None,
                             'become_method': 'sudo',
                             'become_user': None,
                             'connection': 'ssh',
                             'ignore_errors': False,
                             'ignore_unreachable': None,
                             'register': None,
                             'retries': None,
                             'timeout': 0},
            'changed': False,
            'failed': False,
            'hostname': 'VM0101',
            'invocation': {'module_args': {'commands': ['show version'],
                                           'interval': 1,
                                           'match': 'all',
                                           'retries': 10,
                                           'wait_for': None},
                           'module_name': 'eos_command'},
            'reachable': True,
            'stdout': ['Arista cEOSLab\nHardware version: \nSerial number: 8F1C2A7DD04914C25CDAAFD8859018D3\nHardware MAC address: 3259.ff7c.d95a\nSystem MAC address: 3259.ff7c.d95a\n\nSoftware image version: 4.32.5M-41241764.4325M (engineering build)\nArchitecture: x86_64\nInternal build version: 4.32.5M-41241764.4325M\nInternal build ID: a14e5148-5c2b-40f1-98fc-58e12706de3a\nImage format version: 1.0\nImage optimization: None\n\nKernel version: 6.8.0-1041-azure\n\nUptime: 2 weeks, 0 days, 7 hours and 6 minutes\nTotal memory: 32816864 kB\nFree memory: 13906092 kB'],
            'stdout_lines': [['Arista cEOSLab',
                              'Hardware version: ',
                              'Serial number: 8F1C2A7DD04914C25CDAAFD8859018D3',
                              'Hardware MAC address: 3259.ff7c.d95a',
                              'System MAC address: 3259.ff7c.d95a',
                              '',
                              'Software image version: 4.32.5M-41241764.4325M (engineering build)',
                              'Architecture: x86_64',
                              'Internal build version: 4.32.5M-41241764.4325M',
                              'Internal build ID: a14e5148-5c2b-40f1-98fc-58e12706de3a',
                              'Image format version: 1.0',
                              'Image optimization: None',
                              '',
                              'Kernel version: 6.8.0-1041-azure',
                              '',
                              'Uptime: 2 weeks, 0 days, 7 hours and 6 minutes',
                              'Total memory: 32816864 kB',
                              'Free memory: 13906092 kB']]}}
>>>
```

For more examples and guides for how to use this library, please refer to the `docs` subfolder.

## Guides

* [Basic usage](docs/basic_usage.md)
* [Extra hostvars and options](docs/hostvars_options.md)
* [Logging](docs/logging.md)
* [task_directives](docs/task_directives.md)
* Advanced topics
  * [Asynchronous tasks](docs/async.md)
  * [Ansible variables](docs/vars.md)
  * [Fork](docs/fork.md)

Possible topics:

connection
performance
debug

Jinja template
When conditions, use in task or use `if` in python
Loops. Loop in ansible, loop in python.
fork
run async
