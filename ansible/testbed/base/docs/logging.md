# Logging

There are two types of logging related to the library:
1. Ansible logging (including the customized callback plugin for collecting module execution results: `ansible/plugins/callback/json_results.py`)
2. Library logging

## Ansible Logging

Ansible logging is controlled by the [`DEFAULT_VERBOSITY`](https://docs.ansible.com/projects/ansible/latest/reference_appendices/config.html#default-verbosity) configuration. Typically, you don't need to adjust this option, but when troubleshooting issues, increasing Ansible's logging verbosity is especially useful for debugging.

The `json_results` callback plugin logging is also controlled by this Ansible `verbosity` configuration.

There are two methods to configure Ansible logging level:
1. Configure `verbosity` in `ansible.cfg` under `[defaults]` section. For example:
```
[defaults]
verbosity=3
```
2. Set environment variable. For example:
```bash
export ANSIBLE_VERBOSITY=3
```
The environment variable `ANSIBLE_VERBOSITY` has higher priority.

The following examples demonstrate the effect of changing Ansible logging verbosity. Assume we have a script file `ansible/demo_ansible_logging.py` with the following content:

```python
from testbed.base.ansible_hosts import AnsibleHost
dut = AnsibleHost('veos_vtb', 'vlab-01')
dut.command('uptime')
```

### Default verbosity=0

By default, there is no Ansible logging output.
```
$ python demo_ansible_logging.py
$
```

### verbosity=1

With `export ANSIBLE_VERBOSITY=1`, there is still no Ansible log output. However, the `json_results` plugin logs one line when a module is executed.
```
$ export ANSIBLE_VERBOSITY=1
$ python demo_ansible_logging.py
[vlab-01] => {"module_name": "command", "reachable": true, "failed": false}
```

### verbosity=2

With `export ANSIBLE_VERBOSITY=2`, basic Ansible logs are displayed. The `json_results` plugin logs detailed module execution results.
```
$ export ANSIBLE_VERBOSITY=2
$ python demo_ansible_logging.py
Skipping callback 'json_results', as we already have a stdout callback.
Skipping callback 'yaml', as we already have a stdout callback.
Skipping callback 'default', as we already have a stdout callback.
Skipping callback 'minimal', as we already have a stdout callback.
Skipping callback 'oneline', as we already have a stdout callback.
[vlab-01] => {"hostname": "vlab-01", "reachable": true, "failed": false, "changed": true, "stdout": " 03:05:14 up 18 days, 35 min,  0 user,  load average: 0.50, 0.45, 0.44", "stderr": "", "rc": 0, "cmd": ["uptime"], "start": "2025-12-08 03:05:14.846624", "end": "2025-12-08 03:05:14.861304", "delta": "0:00:00.014680", "msg": "", "invocation": {"module_args": {"_raw_params": "uptime", "_uses_shell": false, "expand_argument_vars": true, "stdin_add_newline": true, "strip_empty_ends": true, "argv": null, "chdir": null, "executable": null, "creates": null, "removes": null, "stdin": null}, "module_name": "command"}, "stdout_lines": [" 03:05:14 up 18 days, 35 min,  0 user,  load average: 0.50, 0.45, 0.44"], "stderr_lines": [], "ansible_facts": {"discovered_interpreter_python": "/usr/bin/python3.11"}, "_ansible_no_log": false, "_task_fields": {"action": "command", "become": null, "become_method": "sudo", "become_user": null, "connection": "ssh", "ignore_errors": false, "ignore_unreachable": null, "register": null, "retries": null, "timeout": 0}}
```

### verbosity=3

With `export ANSIBLE_VERBOSITY=3`, Ansible outputs very detailed logs. The effect is equivalent to appending `-vvv` to the `ansible-playbook` command. The `json_results` plugin outputs indented JSON results for better readability.
```
xiwang5@sonic-mgmt-new:/data/code/sonic-mgmt-ng/ansible$ export ANSIBLE_VERBOSITY=3
xiwang5@sonic-mgmt-new:/data/code/sonic-mgmt-ng/ansible$ python demo_ansible_logging.py
Skipping callback 'json_results', as we already have a stdout callback.
Skipping callback 'yaml', as we already have a stdout callback.
Skipping callback 'default', as we already have a stdout callback.
Skipping callback 'minimal', as we already have a stdout callback.
Skipping callback 'oneline', as we already have a stdout callback.
<vlab-01> Attempting python interpreter discovery
<10.250.0.101> ESTABLISH SSH CONNECTION FOR USER: admin
<10.250.0.101> SSH: EXEC sshpass -d12 ssh -vvv -o ControlMaster=auto -o ControlPersist=180s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ServerAliveCountMax=40 -o StrictHostKeyChecking=no -o 'User="admin"' -o ConnectTimeout=60 -o 'ControlPath="/home/xiwang5/.ansible/cp/e95704e219"' 10.250.0.101 '/bin/sh -c '"'"'echo PLATFORM; uname; echo FOUND; command -v '"'"'"'"'"'"'"'"'python3.13'"'"'"'"'"'"'"'"'; command -v '"'"'"'"'"'"'"'"'python3.12'"'"'"'"'"'"'"'"'; command -v '"'"'"'"'"'"'"'"'python3.11'"'"'"'"'"'"'"'"'; command -v '"'"'"'"'"'"'"'"'python3.10'"'"'"'"'"'"'"'"'; command -v '"'"'"'"'"'"'"'"'python3.9'"'"'"'"'"'"'"'"'; command -v '"'"'"'"'"'"'"'"'python3.8'"'"'"'"'"'"'"'"'; command -v '"'"'"'"'"'"'"'"'/usr/bin/python3'"'"'"'"'"'"'"'"'; command -v '"'"'"'"'"'"'"'"'python3'"'"'"'"'"'"'"'"'; echo ENDFOUND && sleep 0'"'"''
<10.250.0.101> (0, b'PLATFORM\nLinux\nFOUND\n/usr/bin/python3.11\n/usr/bin/python3\n/usr/bin/python3\nENDFOUND\n', b"OpenSSH_9.6p1 Ubuntu-3ubuntu13.14, OpenSSL 3.0.13 30 Jan 2024\r\ndebug1: Reading configuration data /etc/ssh/ssh_config\r\ndebug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files\r\ndebug1: /etc/ssh/ssh_config line 21: Applying options for *\r\ndebug2: resolve_canonicalize: hostname 10.250.0.101 is address\r\ndebug1: auto-mux: Trying existing master at '/home/xiwang5/.ansible/cp/e95704e219'\r\ndebug2: fd 3 setting O_NONBLOCK\r\ndebug2: mux_client_hello_exchange: master version 4\r\ndebug3: mux_client_forwards: request forwardings: 0 local, 0 remote\r\ndebug3: mux_client_request_session: entering\r\ndebug3: mux_client_request_alive: entering\r\ndebug3: mux_client_request_alive: done pid = 10501\r\ndebug3: mux_client_request_session: session request sent\r\ndebug1: mux_client_request_session: master session id: 2\r\ndebug3: mux_client_read_packet_timeout: read header failed: Broken pipe\r\ndebug2: Received exit status from master 0\r\n")
<10.250.0.101> ESTABLISH SSH CONNECTION FOR USER: admin
<10.250.0.101> SSH: EXEC sshpass -d12 ssh -vvv -o ControlMaster=auto -o ControlPersist=180s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ServerAliveCountMax=40 -o StrictHostKeyChecking=no -o 'User="admin"' -o ConnectTimeout=60 -o 'ControlPath="/home/xiwang5/.ansible/cp/e95704e219"' 10.250.0.101 '/bin/sh -c '"'"'/usr/bin/python3.11 && sleep 0'"'"''
<10.250.0.101> (0, b'{"platform_dist_result": [], "osrelease_content": "PRETTY_NAME=\\"Debian GNU/Linux 12 (bookworm)\\"\\nNAME=\\"Debian GNU/Linux\\"\\nVERSION_ID=\\"12\\"\\nVERSION=\\"12 (bookworm)\\"\\nVERSION_CODENAME=bookworm\\nID=debian\\nHOME_URL=\\"https://www.debian.org/\\"\\nSUPPORT_URL=\\"https://www.debian.org/support\\"\\nBUG_REPORT_URL=\\"https://bugs.debian.org/\\"\\n"}\n', b"OpenSSH_9.6p1 Ubuntu-3ubuntu13.14, OpenSSL 3.0.13 30 Jan 2024\r\ndebug1: Reading configuration data /etc/ssh/ssh_config\r\ndebug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files\r\ndebug1: /etc/ssh/ssh_config line 21: Applying options for *\r\ndebug2: resolve_canonicalize: hostname 10.250.0.101 is address\r\ndebug1: auto-mux: Trying existing master at '/home/xiwang5/.ansible/cp/e95704e219'\r\ndebug2: fd 3 setting O_NONBLOCK\r\ndebug2: mux_client_hello_exchange: master version 4\r\ndebug3: mux_client_forwards: request forwardings: 0 local, 0 remote\r\ndebug3: mux_client_request_session: entering\r\ndebug3: mux_client_request_alive: entering\r\ndebug3: mux_client_request_alive: done pid = 10501\r\ndebug3: mux_client_request_session: session request sent\r\ndebug1: mux_client_request_session: master session id: 2\r\ndebug3: mux_client_read_packet_timeout: read header failed: Broken pipe\r\ndebug2: Received exit status from master 0\r\n")
<vlab-01> Python interpreter discovery fallback (unsupported Linux distribution: debian)
Using module file /opt/venv/lib/python3.12/site-packages/ansible/modules/command.py
Pipelining is enabled.
<10.250.0.101> ESTABLISH SSH CONNECTION FOR USER: admin
<10.250.0.101> SSH: EXEC sshpass -d12 ssh -vvv -o ControlMaster=auto -o ControlPersist=180s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -o ServerAliveCountMax=40 -o StrictHostKeyChecking=no -o 'User="admin"' -o ConnectTimeout=60 -o 'ControlPath="/home/xiwang5/.ansible/cp/e95704e219"' 10.250.0.101 '/bin/sh -c '"'"'/usr/bin/python3.11 && sleep 0'"'"''
<10.250.0.101> (0, b'\n{"changed": true, "stdout": " 03:06:44 up 18 days, 36 min,  0 user,  load average: 0.64, 0.53, 0.47", "stderr": "", "rc": 0, "cmd": ["uptime"], "start": "2025-12-08 03:06:44.479910", "end": "2025-12-08 03:06:44.487397", "delta": "0:00:00.007487", "msg": "", "invocation": {"module_args": {"_raw_params": "uptime", "_uses_shell": false, "expand_argument_vars": true, "stdin_add_newline": true, "strip_empty_ends": true, "argv": null, "chdir": null, "executable": null, "creates": null, "removes": null, "stdin": null}}}\n', b"OpenSSH_9.6p1 Ubuntu-3ubuntu13.14, OpenSSL 3.0.13 30 Jan 2024\r\ndebug1: Reading configuration data /etc/ssh/ssh_config\r\ndebug1: /etc/ssh/ssh_config line 19: include /etc/ssh/ssh_config.d/*.conf matched no files\r\ndebug1: /etc/ssh/ssh_config line 21: Applying options for *\r\ndebug2: resolve_canonicalize: hostname 10.250.0.101 is address\r\ndebug1: auto-mux: Trying existing master at '/home/xiwang5/.ansible/cp/e95704e219'\r\ndebug2: fd 3 setting O_NONBLOCK\r\ndebug2: mux_client_hello_exchange: master version 4\r\ndebug3: mux_client_forwards: request forwardings: 0 local, 0 remote\r\ndebug3: mux_client_request_session: entering\r\ndebug3: mux_client_request_alive: entering\r\ndebug3: mux_client_request_alive: done pid = 10501\r\ndebug3: mux_client_request_session: session request sent\r\ndebug1: mux_client_request_session: master session id: 2\r\ndebug3: mux_client_read_packet_timeout: read header failed: Broken pipe\r\ndebug2: Received exit status from master 0\r\n")
[vlab-01] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "changed": true,
    "stdout": " 03:06:44 up 18 days, 36 min,  0 user,  load average: 0.64, 0.53, 0.47",
    "stderr": "",
    "rc": 0,
    "cmd": [
        "uptime"
    ],
    "start": "2025-12-08 03:06:44.479910",
    "end": "2025-12-08 03:06:44.487397",
    "delta": "0:00:00.007487",
    "msg": "",
    "invocation": {
        "module_args": {
            "_raw_params": "uptime",
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
        " 03:06:44 up 18 days, 36 min,  0 user,  load average: 0.64, 0.53, 0.47"
    ],
    "stderr_lines": [],
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python3.11"
    },
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

### verbosity=4

When `ANSIBLE_VERBOSITY` is set to `4` or higher, Ansible outputs even more detailed logs. The logging output from the `json_results` plugin remains the same as verbosity level 3.

## Library Logging

Library logging is controlled by setting the `verbosity` value in the `options` argument.
Both the class constructor and module execution methods (implicit and explicit) support the `options` argument.
The value in module execution methods has higher priority. However, when running modules in batch mode, the `options` argument in module execution methods is ignored. Only the argument in the class constructor takes effect.

If the environment variable `ANSIBLE_PYAPI_VERBOSITY` is set, it has the highest priority.

Priority | Example | Description
---------|---------|------------
0 (low) |  `dut = AnsibleHost('veos_vtb', 'vlab-01', options={'verbosity': 1})`  | Class constructor
1 | `dut.command('uptime', options={'verbosity': 2})` | Implicit module execution method
1 | `dut.run_module('command', args=['uptime'], options={'verbosity': 2})` | Explicit module execution method
2 (high) | `export ANSIBLE_PYAPI_VERBOSITY=3` | Environment variable

In the following batch mode examples, the `options` argument in module execution methods has no effect:

```python
dut.load_module('command', args=['uptime'], options={'verbosity': 3})
dut.run_loaded_modules()

with dut:
    dut.command('uptime', options={'verbosity': 3})
    dut.run_module('command', args=['pwd'], options={'verbosity': 3})
```

Similarly, assume we have a script file `ansible/demo_ansible_logging.py` with the following content:
```python
import logging
from testbed.base.ansible_hosts import AnsibleHost
logging.basicConfig(level=logging.DEBUG)

dut = AnsibleHost('veos_vtb', 'vlab-01', options={'verbosity': 0})
dut.command('uptime')
```

Running the script in the docker-sonic-mgmt container demonstrates the effect of different library logging levels.

### verbosity=0

When verbosity is 0, there is no library logging output.

```
$ python demo_ansible_logging.py
$
```

### verbosity=1

When verbosity is 1, running each Ansible module generates two log entries. One logs the module invocation without details of module arguments. The other logs the results with only basic information such as hostname and module name. Detailed module results are not included.

```
$ python demo_ansible_logging.py
DEBUG:ansible_pyapi:demo_ansible_logging.py:6 >> ['vlab-01'] => command
DEBUG:ansible_pyapi:/data/code/sonic-mgmt-ng/ansible/demo_ansible_logging.py:6 >> ['vlab-01'] => done
$
```

### Default verbosity=2

This is the default verbosity level. When verbosity is 2, running each Ansible module generates two log entries. One logs the module invocation with detailed module arguments. The other logs the results with detailed module output.

```
$ python demo_ansible_logging.py
DEBUG:ansible_pyapi:demo_ansible_logging.py:6 >> ['vlab-01'] => command, args=["uptime"], kwargs={}, module_attrs={}
DEBUG:ansible_pyapi:/data/code/sonic-mgmt-ng/ansible/demo_ansible_logging.py:6 >> ['vlab-01'] => {"hostname": "vlab-01", "reachable": true, "failed": false, "changed": true, "stdout": " 08:43:52 up 18 days,  6:14,  0 user,  load average: 0.20, 0.41, 0.55", "stderr": "", "rc": 0, "cmd": ["uptime"], "start": "2025-12-08 08:43:52.270293", "end": "2025-12-08 08:43:52.284446", "delta": "0:00:00.014153", "msg": "", "invocation": {"module_args": {"_raw_params": "uptime", "_uses_shell": false, "expand_argument_vars": true, "stdin_add_newline": true, "strip_empty_ends": true, "argv": null, "chdir": null, "executable": null, "creates": null, "removes": null, "stdin": null}, "module_name": "command"}, "stdout_lines": [" 08:43:52 up 18 days,  6:14,  0 user,  load average: 0.20, 0.41, 0.55"], "stderr_lines": [], "ansible_facts": {"discovered_interpreter_python": "/usr/bin/python3.11"}, "_ansible_no_log": false, "_task_fields": {"action": "command", "become": null, "become_method": "sudo", "become_user": null, "connection": "ssh", "ignore_errors": false, "ignore_unreachable": null, "register": null, "retries": null, "timeout": 0}}
$
```

### verbosity=3

When verbosity is 3, running each Ansible module generates two log entries. One logs the module invocation with detailed module arguments in indented format. The other logs the results with detailed module output in indented JSON format.

```
$ python demo_ansible_logging.py
DEBUG:ansible_pyapi:demo_ansible_logging.py:6 >> ['vlab-01'] => command, args=["uptime"], kwargs={}, module_attrs={}
DEBUG:ansible_pyapi:/data/code/sonic-mgmt-ng/ansible/demo_ansible_logging.py:6 >> ['vlab-01'] => {"hostname": "vlab-01", "reachable": true, "failed": false, "changed": true, "stdout": " 08:43:52 up 18 days,  6:14,  0 user,  load average: 0.20, 0.41, 0.55", "stderr": "", "rc": 0, "cmd": ["uptime"], "start": "2025-12-08 08:43:52.270293", "end": "2025-12-08 08:43:52.284446", "delta": "0:00:00.014153", "msg": "", "invocation": {"module_args": {"_raw_params": "uptime", "_uses_shell": false, "expand_argument_vars": true, "stdin_add_newline": true, "strip_empty_ends": true, "argv": null, "chdir": null, "executable": null, "creates": null, "removes": null, "stdin": null}, "module_name": "command"}, "stdout_lines": [" 08:43:52 up 18 days,  6:14,  0 user,  load average: 0.20, 0.41, 0.55"], "stderr_lines": [], "ansible_facts": {"discovered_interpreter_python": "/usr/bin/python3.11"}, "_ansible_no_log": false, "_task_fields": {"action": "command", "become": null, "become_method": "sudo", "become_user": null, "connection": "ssh", "ignore_errors": false, "ignore_unreachable": null, "register": null, "retries": null, "timeout": 0}}
xiwang5@sonic-mgmt-new:/data/code/sonic-mgmt-ng/ansible$
xiwang5@sonic-mgmt-new:/data/code/sonic-mgmt-ng/ansible$ python demo_ansible_logging.py
DEBUG:ansible_pyapi:demo_ansible_logging.py:6 >> ['vlab-01'] => command, args=["uptime"], kwargs={}, module_attrs={}
DEBUG:ansible_pyapi:/data/code/sonic-mgmt-ng/ansible/demo_ansible_logging.py:6 >> ['vlab-01'] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "changed": true,
    "stdout": " 08:44:29 up 18 days,  6:14,  0 user,  load average: 0.54, 0.47, 0.56",
    "stderr": "",
    "rc": 0,
    "cmd": [
        "uptime"
    ],
    "start": "2025-12-08 08:44:29.835856",
    "end": "2025-12-08 08:44:29.843866",
    "delta": "0:00:00.008010",
    "msg": "",
    "invocation": {
        "module_args": {
            "_raw_params": "uptime",
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
        " 08:44:29 up 18 days,  6:14,  0 user,  load average: 0.54, 0.47, 0.56"
    ],
    "stderr_lines": [],
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python3.11"
    },
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
$
```

### verbosity=4

When verbosity is 4, in addition to the logs from verbosity level 3, an extra log entry is added for TaskQueueManager statistics.

```
$ python demo_ansible_logging.py
DEBUG:ansible_pyapi:demo_ansible_logging.py:6 >> ['vlab-01'] => command, args=["uptime"], kwargs={}, module_attrs={}
DEBUG:ansible_pyapi:/data/code/sonic-mgmt-ng/ansible/demo_ansible_logging.py:6 >> ['vlab-01'] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "changed": true,
    "stdout": " 08:45:46 up 18 days,  6:16,  0 user,  load average: 0.45, 0.47, 0.55",
    "stderr": "",
    "rc": 0,
    "cmd": [
        "uptime"
    ],
    "start": "2025-12-08 08:45:46.486001",
    "end": "2025-12-08 08:45:46.501264",
    "delta": "0:00:00.015263",
    "msg": "",
    "invocation": {
        "module_args": {
            "_raw_params": "uptime",
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
        " 08:45:46 up 18 days,  6:16,  0 user,  load average: 0.45, 0.47, 0.55"
    ],
    "stderr_lines": [],
    "ansible_facts": {
        "discovered_interpreter_python": "/usr/bin/python3.11"
    },
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
DEBUG:ansible_pyapi:/data/code/sonic-mgmt-ng/ansible/demo_ansible_logging.py:6 >> TaskQueueManager Stats: {
    "processed": {
        "vlab-01": 1
    },
    "failures": {},
    "ok": {
        "vlab-01": 1
    },
    "unreachable": {},
    "changed": {
        "vlab-01": 1
    },
    "skipped": {},
    "rescued": {},
    "ignored": {}
}
$
```
