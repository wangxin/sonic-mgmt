# Task directives

The structure of an Ansible task generally looks like this:
```yaml
- name: This is the task's name
  <module_name>:  # e.g., command, file, apt, etc.
    <module_argument>: <value>
    <module_argument>: <value>
  <TASK DIRECTIVE>: <value>  # e.g., become, delegate_to, register
  <ANOTHER TASK DIRECTIVE>: <value>
```

A module's behavior can be affected by some task directives like `become`, `delegate_to`, `register`, etc.

This library also supports the task directives by the `task_directives` argument for the module execution methods (implicit and explicit).

Example:
```python
dut.command('ifconfig', task_directives={'become': True})
```
In the above example, the `ifconfig` command will be executed with `sudo`.

```python
dut.command('hostname', task_directives={'delegate_to': 'localhost'})
```
In the above example, the `hostname` is executed on `localhost`. This example is just to demonstrate the usage of `delegated_to` task directive. To run a command on localhost, it is recommended to use the `AnsibleLocalhost` object.
