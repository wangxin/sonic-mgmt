# Async

This library supports running Ansible tasks asynchronously using Ansible's async feature. You can achieve this by using task_directives to specify "async" and "poll" parameters for a task. The behavior is the same as the standard Ansible async feature.

Ansible official documentation: https://docs.ansible.com/ansible/latest/user_guide/playbooks_async.html

## Avoid Connection Timeouts: poll>0

```python

myhost = AnsibleHost(
    inventory="veos_vtb",
    pattern="vlab-01",
)
myhost.command(
    "sleep 15",
    task_directives={"async": 45, "poll": 2}
)
myhost.command(
    "echo 'This runs after the sleep command is complete'",
)
```

In the above example, the command "sleep 15" will run asynchronously on the host "vlab-01". The task will be allowed to run for up to 45 seconds, and Ansible will poll for the result every 2 seconds. This prevents connection timeouts that may occur if the task takes longer than the default SSH timeout.

Below is the log of running the above code. Note that Ansible polls for the result every 2 seconds until the task is complete.

```
07:04:21 - DEBUG - unittest_async.py:76 >> ['vlab-01'] => command, args=["sleep", "15"], kwargs={}, task_directives={"async": 45, "poll": 2}
07:04:41 - DEBUG - /data/code/sonic-mgmt-ng/ansible/testbed/unittest/unittest_async.py:76 >> ['vlab-01'] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "started": 1,
    "finished": 1,
    "stdout": "",
    "stderr": "",
    "stdout_lines": [],
    "stderr_lines": [],
    "ansible_job_id": "j882242369895.845881",
    "results_file": "/home/admin/.ansible_async/j882242369895.845881",
    "changed": true,
    "rc": 0,
    "cmd": [
        "sleep",
        "15"
    ],
    "start": "2026-01-07 07:04:21.655091",
    "end": "2026-01-07 07:04:36.674306",
    "delta": "0:00:15.019215",
    "msg": "",
    "invocation": {
        "module_args": {
            "_raw_params": "sleep 15",
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
07:04:41 - DEBUG - unittest_async.py:80 >> ['vlab-01'] => command, args=["echo", "'This", "runs", "after", "the", "sleep", "command", "completes'"], kwargs={}, task_directives={}
07:04:42 - DEBUG - /data/code/sonic-mgmt-ng/ansible/testbed/unittest/unittest_async.py:80 >> ['vlab-01'] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "changed": true,
    "stdout": "This runs after the sleep command completes",
    "stderr": "",
    "rc": 0,
    "cmd": [
        "echo",
        "This runs after the sleep command completes"
    ],
    "start": "2026-01-07 07:04:39.781925",
    "end": "2026-01-07 07:04:39.787731",
    "delta": "0:00:00.005806",
    "msg": "",
    "invocation": {
        "module_args": {
            "_raw_params": "echo 'This runs after the sleep command completes'",
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
        "This runs after the sleep command completes"
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

## Run Tasks Concurrently: poll=0

```python
myhost = AnsibleHost(
    inventory="veos_vtb",
    pattern="vlab-01",
)

# Simulate long running operation, allow to run for 45 seconds, fire and forget
myhost.command(
    "sleep 15",
    task_directives={"async": 45, "poll": 0}
)

myhost.command(
    "echo 'This runs immediately after starting the sleep command'",
)
```

Below is the log of running the above code. Note that the second command runs immediately after starting the first command, without waiting for the first command to complete.

```
06:48:43 - DEBUG - unittest_async.py:61 >> ['vlab-01'] => command, args=["sleep", "15"], kwargs={}, task_directives={"async": 45, "poll": 0}
06:48:45 - DEBUG - /data/code/sonic-mgmt-ng/ansible/testbed/unittest/unittest_async.py:61 >> ['vlab-01'] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "started": 1,
    "finished": 0,
    "ansible_job_id": "j502372134103.841115",
    "results_file": "/home/admin/.ansible_async/j502372134103.841115",
    "changed": true,
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
06:48:45 - DEBUG - unittest_async.py:65 >> ['vlab-01'] => command, args=["echo", "'This", "runs", "immediately", "after", "starting", "the", "sleep", "command'"], kwargs={}, task_directives={}
06:48:46 - DEBUG - /data/code/sonic-mgmt-ng/ansible/testbed/unittest/unittest_async.py:65 >> ['vlab-01'] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "changed": true,
    "stdout": "This runs immediately after starting the sleep command",
    "stderr": "",
    "rc": 0,
    "cmd": [
        "echo",
        "This runs immediately after starting the sleep command"
    ],
    "start": "2026-01-07 06:48:43.965489",
    "end": "2026-01-07 06:48:43.970104",
    "delta": "0:00:00.004615",
    "msg": "",
    "invocation": {
        "module_args": {
            "_raw_params": "echo 'This runs immediately after starting the sleep command'",
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
        "This runs immediately after starting the sleep command"
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

## Query Async Task Result Using Python

```python
myhost = AnsibleHost(
    inventory="veos_vtb",
    pattern="vlab-01",
)
res = myhost.command(
    'sleep 15',
    task_directives={'async': 45, 'poll': 0}
)
jid = res['ansible_job_id']

timeout = 20
while timeout > 0:
    res_status = myhost.async_status(jid=jid)
    is_complete = res_status.get('finished', 0)
    if is_complete:
        print("Async Task Completed:", json.dumps(res_status, indent=4))
        break
    else:
        print("Async Task Not Completed Yet. Checking Again...")
        timeout -= 2
        time.sleep(2)
```

## Query Async Task Result Using "retries"

```python
myhost = AnsibleHost(
    inventory="veos_vtb",
    pattern="vlab-01",
)
res = myhost.command(
    'sleep 15',
    task_directives={'async': 45, 'poll': 0}
)
jid = res['ansible_job_id']

myhost.async_status(
    jid=jid,
    task_directives={
        'register': 'job_result',
        'retries': 10,
        'delay': 3,
        'until': 'job_result is finished'
    }
)
```

Example log of the above code:
```
07:25:18 - DEBUG - unittest_async.py:90 >> ['vlab-01'] => command, args=["sleep", "15"], kwargs={}, task_directives={"async": 45, "poll": 0}
07:25:20 - DEBUG - /data/code/sonic-mgmt-ng/ansible/testbed/unittest/unittest_async.py:90 >> ['vlab-01'] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "started": 1,
    "finished": 0,
    "ansible_job_id": "j299593220699.852211",
    "results_file": "/home/admin/.ansible_async/j299593220699.852211",
    "changed": true,
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
07:25:20 - DEBUG - unittest_async.py:96 >> ['vlab-01'] => async_status, args=[""], kwargs={"jid": "j299593220699.852211"}, task_directives={"register": "job_result", "retries": 10, "delay": 3, "until": "job_result is finished"}
07:25:38 - DEBUG - /data/code/sonic-mgmt-ng/ansible/testbed/unittest/unittest_async.py:96 >> ['vlab-01'] => {
    "hostname": "vlab-01",
    "reachable": true,
    "failed": false,
    "started": 1,
    "finished": 1,
    "stdout": "",
    "stderr": "",
    "stdout_lines": [],
    "stderr_lines": [],
    "ansible_job_id": "j299593220699.852211",
    "results_file": "/home/admin/.ansible_async/j299593220699.852211",
    "changed": true,
    "rc": 0,
    "cmd": [
        "sleep",
        "15"
    ],
    "start": "2026-01-07 07:25:18.464567",
    "end": "2026-01-07 07:25:33.483811",
    "delta": "0:00:15.019244",
    "msg": "",
    "invocation": {
        "module_args": {
            "_raw_params": "sleep 15",
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
        "module_name": "async_status"
    },
    "_ansible_no_log": false,
    "attempts": 6,
    "_task_fields": {
        "action": "async_status",
        "become": null,
        "become_method": "sudo",
        "become_user": null,
        "connection": "ssh",
        "ignore_errors": false,
        "ignore_unreachable": null,
        "register": "job_result",
        "retries": 10,
        "timeout": 0
    }
}
```
