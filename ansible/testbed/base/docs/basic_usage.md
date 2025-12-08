# Dependencies

The lib mainly depends on `ansible` package. The recommended environment for using this tool is to run it in the `docker-sonic-mgmt` container.

The lib can be independently used. But to re-use the existing plugins, customized moduels in the sonic-mgmt repository, need to let ansible know the location of these plugins/modules. Usually we can export below environment variables:

```bash
BASE_PATH="/data/code/sonic-mgmt"
export ANSIBLE_CONFIG=${BASE_PATH}/ansible
export ANSIBLE_HOME=${BASE_PATH}/ansible
export ANSIBLE_LIBRARY=${BASE_PATH}/ansible/library/
export ANSIBLE_MODULE_UTILS=${BASE_PATH}/ansible/module_utils
export ANSIBLE_ACTION_PLUGINS=${BASE_PATH}/ansible/plugins/action
export ANSIBLE_CONNECTION_PLUGINS=${BASE_PATH}/ansible/plugins/connection
export ANSIBLE_CLICONF_PLUGINS=${BASE_PATH}/ansible/cliconf_plugins
export ANSIBLE_TERMINAL_PLUGINS=${BASE_PATH}/ansible/terminal_plugins
```


# Creating Instances

The library provides three classes for running Ansible modules on remote hosts:
* `AnsibleHost` - For exactly one host
* `AnsibleHosts` - For one or more hosts
* `AnsibleLocalhost` - For the special localhost (single host)

## Constructor Arguments

### `AnsibleHost` and `AnsibleHosts`

Both classes require the following arguments:

* **`inventory`** (str | list[str]): Path to Ansible inventory file(s). Use a single string for one inventory file, or a list of strings for multiple files.

* **`pattern`** (str): Host pattern following [Ansible inventory pattern rules](https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_patterns.html). Ansible's built-in matching finds hosts that match the pattern in the provided inventory files.

* **`hostvars`** (dict, optional): Additional variables for the matched hosts. See []() for details.

* **`options`** (dict, optional): Ansible execution options. See []() for details.

### `AnsibleLocalhost`

`AnsibleLocalhost` is designed specifically for localhost operations and does not require inventory files or host patterns.

## Examples

```python
from testbed.base.ansible_hosts import AnsibleHost, AnsibleHosts, AnsibleLocalhost

# Single host
dut = AnsibleHost('veos_vtb', 'vlab-01')

# Multiple hosts with custom variables
neighbors = AnsibleHosts(
    'veos_vtb',
    ['VM0100', 'VM0101'],
    hostvars={'ansible_user': 'root', 'ansible_password': '123456'}
)

# Localhost
localhost = AnsibleLocalhost()
```

# Running Ansible Modules

Once you've created an instance, you can execute Ansible modules on the target hosts.

## Running a Single Module

You can execute a single Ansible module using either implicit or explicit syntax:

### Implicit Syntax: `<instance>.<module_name>(module_args, **module_kwargs)`

The implicit syntax provides a cleaner, more Pythonic syntax:

```python
res1 = dut.command('uptime')
res2 = neighbors.command('who')
res3 = localhost.command('pwd')
```

### Explicit Syntax: `<instance>.run_module(<module_name>, args=[*module_args], kwargs={**module_kwargs})`

The explicit syntax is useful when the module name is dynamic or stored in a variable:

```python
res1 = dut.run_module('command', ['uptime'])
res2 = neighbors.run_module('command', ['who'])
res3 = localhost.run_module('command', args=['pwd'])
```


## Running Multiple Modules in Batch

To reduce overhead when running multiple modules on the same host(s), you can batch the executions together.

### Method 1: Using `load_module` and `run_loaded_modules`

Load multiple modules and execute them together:

```python
# Load modules
dut.load_module('command', ['uptime'])
dut.load_module('command', ['date'])
res1 = dut.run_loaded_modules()

# Works with multiple hosts too
neighbors.load_module('command', ['uptime'])
neighbors.load_module('command', ['date'])
res2 = neighbors.run_loaded_modules()

# And localhost
localhost.load_module('command', ['uptime'])
localhost.load_module('command', ['date'])
res3 = localhost.run_loaded_modules()
```

### Method 2: Using `with` Statement (Context Manager)

The context manager approach provides cleaner syntax:

```python
with dut:
    dut.command('date')
    dut.run_module('command', args=['uptime'])
res1 = dut.results

with neighbors:
    neighbors.command('date')
    neighbors.run_module('command', args=['uptime'])
res2 = neighbors.results

with localhost:
    localhost.command('date')
    localhost.run_module('command', args=['uptime'])
res3 = localhost.results
```

**Note:** When using the `with` statement, you must explicitly retrieve results via the `results` attribute. After accessing `results`, its value is automatically reset to `{}`.


# Understanding Results

Results are returned directly when executing modules. When using the `with` statement, you must explicitly access the `results` attribute to retrieve them. After accessing `results`, its value is automatically reset to `{}`.

## Result Format Variations

The result format depends on the instance type (single vs. multiple hosts) and execution mode (single vs. batch):

| Instance Type | Hosts | Mode | Modules | Result Format |
|---------------|-------|------|---------|---------------|
| AnsibleHost / AnsibleLocalhost | 1 | Single | 1 | `result` |
| AnsibleHost / AnsibleLocalhost | 1 | Batch | 1 | `result` |
| AnsibleHost / AnsibleLocalhost | 1 | Batch | >1 | `[result, result, ...]` |
| AnsibleHosts | 1 | Single | 1 | `{"<hostname>": result}` |
| AnsibleHosts | 1 | Batch | 1 | `{"<hostname>": result}` |
| AnsibleHosts | 1 | Batch | >1 | `{"<hostname>": [result, result, ...]}` |
| AnsibleHosts | >1 | Single | 1 | `{"<hostname1>": result, "<hostname2>": result, ...}` |
| AnsibleHosts | >1 | Batch | 1 | `{"<hostname1>": result, "<hostname2>": result, ...}` |
| AnsibleHosts | >1 | Batch | >1 | `{"<hostname1>": [result, result, ...], "<hostname2>": [result, result, ...], ...}` |

The basic rules of result format:
* For AnsibleHost and AnsibleLocalhost instances, the result or results are directly returned and is not keyed by its hostname.
* For AnsibleHosts, the results are always keyed by hostname. Even when the pattern only match a single host.
* For single mode, the result is not put in a list.
* For batch mode, when only 1 module is loaded, the result is not put in a list. When more than 1 modules are loaded, the results are put in a list.

## Result Structure

Each `result` represents the output of a single Ansible module execution. It is a dictionary with the following typical structure:
```json
{
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "changed": true,
    "stdout": "Fri Dec  5 07:42:12 AM UTC 2025",
    "stderr": "",
    "rc": 0,
    "cmd": [
        "date"
    ],
    "start": "2025-12-05 07:42:12.552911",
    "end": "2025-12-05 07:42:12.570302",
    "delta": "0:00:00.017391",
    "msg": "",
    "invocation": {
        "module_args": {
            "_raw_params": "date",
            "_uses_shell": false,
            "expand_argument_vars": true,
            "stdin_add_newline": true,
            "strip_empty_ends": true,
            "argv": null,
            "chdir": null,
            "executable": null,
            "creates": null,
            "removes": null,
            "stdin": null
        },
        "module_name": "command"
    },
    "stdout_lines": [
        "Fri Dec  5 07:42:12 AM UTC 2025"
    ],
    "stderr_lines": [],
    "_ansible_no_log": false,
    "_task_fields": {
        "action": "command",
        "become": null,
        "become_method": "sudo",
        "become_user": null,
        "connection": "ssh",
        "ignore_errors": false,
        "ignore_unreachable": null,
        "register": null,
        "retries": null,
        "timeout": 0
    }
}
```

## Results - tech details

Ansible uses callback to collect module results. The default callback only logs ansible results on console. In the lib, we need to get the results for further processing. For that purpose, a customized callback is defined and used by the lib. Code of the callback is at `ansible/plugins/callback/json_results.py`.

## Common Fields

While the keys in a result dictionary vary depending on the Ansible module used, these fields are typically always present:

* **`hostname`** - The target host name
* **`failed`** - Boolean indicating whether the task failed
* **`reachable`** - Boolean indicating whether the host was reachable
* **`invocation`** - Details about how the module was invoked
* **`_task_fields`** - Additional task configuration details
