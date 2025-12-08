# Host Variables and Options

When creating instances or executing Ansible modules, you can customize behavior using the `hostvars` and `options` parameters.

Reference:
* [Ansible playbook variables](https://docs.ansible.com/projects/ansible/latest/playbook_guide/playbooks_variables.html)
* [Ansible playbook options](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html#common-options)

## Host Variables (`hostvars`)

The `hostvars` parameter allows you to provide additional variables that will be available to Ansible modules during execution.

### Usage in Constructor

```python
# Single host with custom variables
dut = AnsibleHost(
    inventory='veos_vtb',
    pattern='vlab-01',
    hostvars={
        'ansible_user': 'admin',
        'ansible_password': '123456',
        'custom_var': 'value'
    }
)

# Multiple hosts with shared variables
neighbors = AnsibleHosts(
    inventory='veos_vtb',
    pattern=['VM0100', 'VM0101'],
    hostvars={
        'ansible_connection': 'network_cli',
        'ansible_network_os': 'eos',
        'ansible_user': 'admin',
        'ansible_password: '123456'
    }
)
res = neighbors.eos_command(commands='show version')
```

### Characteristics

- **Type**: `dict[str, Any]`
- **Scope**: Variables are merged with existing inventory variables and become visible to all modules
- **Priority**: Host variables passed to the constructor have high priority and override inventory variables

### Common Use Cases

- **Authentication credentials**: `ansible_user`, `ansible_password`, `ansible_ssh_private_key_file`
- **Connection settings**: `ansible_connection`, `ansible_port`, `ansible_network_os`
- **Custom variables**: Any application-specific variables needed by modules or templates

## Options (`options`)

The `options` parameter controls how Ansible executes modules on the target hosts.

### Available Options

Default values are determined by Ansible's configuration, which can be set via `ansible.cfg` or environment variables (e.g., `ANSIBLE_FORKS`, `ANSIBLE_TIMEOUT`).

Not all options defined in [Ansible playbook options](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html#common-options) are supported by the lib. The currently supported options:

| Option | Type | Default Source | Typical Default | Description |
|--------|------|----------------|-----------------|-------------|
| `connection` | str | `DEFAULT_TRANSPORT` | `'smart'` | Connection type (ssh, local, network_cli, etc.) |
| `forks` | int | `DEFAULT_FORKS` | `5` | Number of parallel processes for execution |
| `timeout` | int | `DEFAULT_TIMEOUT` | `10` | Connection timeout in seconds |
| `task_timeout` | int | `TASK_TIMEOUT` | `0` | Task execution timeout (0 = no timeout) |
| `become` | bool | `DEFAULT_BECOME` | `False` | Enable privilege escalation |
| `become_method` | str | `DEFAULT_BECOME_METHOD` | `'sudo'` | Privilege escalation method (sudo, su, etc.) |

### Usage in Constructor

Options specified in the constructor apply to all module executions for that instance:

```python
# Configure connection and parallelism
eos_hosts = AnsibleHosts(
    inventory='veos_vtb',
    pattern='VM0100,VM0101,VM0102,VM0103',
    hostvars={
        'ansible_user': 'admin',
        'ansible_password': '123456',
        'ansible_network_os': 'eos',
    },
    options={
        'connection': 'network_cli',
        'forks': 2,
    }
)
res = eos_hosts.eos_command(commands="show version")
```

### Usage in Module Execution

Options can also be passed when running individual modules, overriding constructor-level settings:

```python
# Override options for specific execution
result = dut.run_module(
    'command',
    args=['ifconfig'],
    options={
        'verbosity': 2,
        'timeout': 30,
        'become': True
    }
)

# Using implicit mode with default options
result = dut.shell('ls -la')
```

### Priority

When options are specified in multiple places, they follow this priority order (highest to lowest):

1. **Runtime options** - Passed to `run_module()` or similar methods
2. **Constructor options** - Provided when creating the instance
3. **Default values** - From Ansible configuration and constants

### Batch Mode Behavior

**Important**: When running modules in batch mode (using `with` statement or `load_module` + `run_loaded_modules`), the `hostvars` and `options` parameters passed to individual module execution methods are **ignored**.

```python
# Batch mode using 'with' statement
with dut:
    # These hostvars/options are IGNORED
    dut.command('uptime', options={'verbosity': 2})
    dut.run_module('shell', args=['date'], options={'timeout': 60})
# Only constructor-level options apply

# Batch mode using load_module
dut.load_module('command', args=['uptime'], options={'verbosity': 2})  # options IGNORED
dut.load_module('shell', args=['date'], options={'timeout': 60})      # options IGNORED
result = dut.run_loaded_modules()
```

**Reason**: In batch mode, all tasks are executed within a single Ansible Playbook object under the hood. The lib's architecture does not support per-task customization of host variables or execution options. All modules in the batch share the `hostvars` and `options` that were passed to the constructor.

**Workaround**: If you need different options for different modules, execute them individually rather than in batch mode:

```python
# Execute separately with different options
result1 = dut.command('uptime', options={'verbosity': 2})
result2 = dut.shell('date', options={'timeout': 60})
```

### Common Scenarios

**High verbosity for debugging:**
```python
result = host.command('who', options={'verbosity': 3})
```

**Parallel execution on multiple hosts:**
```python
hosts = AnsibleHosts('inventory', 'webservers', options={'forks': 20})
```

## Best Practices

1. **Set common options in constructor**: Define frequently-used options at instance creation to avoid repetition
2. **Override at runtime for exceptions**: Use runtime options for one-off scenarios requiring different settings
3. **Adjust forks for performance**: Increase forks for large-scale parallel operations, but stay within system limits
