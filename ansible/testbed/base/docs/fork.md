# Fork - Run Tasks on Multiple Hosts in Parallel

Ansible natively supports running tasks on multiple hosts in parallel through "forking". In the existing pytest library, the pytest-ansible plugin does not support forking. Significant effort was required to enable parallel execution across multiple hosts. With this new library, Ansible's forking capability is fully exposed, making it easy to leverage the fork feature for parallel operations on multiple hosts.

```python
neighbors = AnsibleHosts(
    inventory="veos_vtb",
    pattern=['VM0100', 'VM0101', 'VM0102', 'VM0103'],
    hostvars={
        'ansible_user': 'root',
        'ansible_password': '123456'
    }
)

neighbors.shell('sleep 5 && echo "Hello from $(hostname)"')
```

The default fork value is Ansible's DEFAULT_FORKS, which is 5 (https://docs.ansible.com/projects/ansible/latest/reference_appendices/config.html#default-forks). The above example has 4 hosts, so the task will be executed on all 4 hosts in parallel.

If you change the fork value to 2, the task will be executed on 2 hosts in parallel. After the first 2 hosts finish, the next 2 hosts will be executed. The example below will take approximately 10 seconds to complete, compared to approximately 5 seconds in the previous example.

```python
neighbors = AnsibleHosts(
    inventory="veos_vtb",
    pattern=['VM0100', 'VM0101', 'VM0102', 'VM0103'],
    options={'forks': 2},
    hostvars={
        'ansible_user': 'root',
        'ansible_password': '123456'
    }
)

neighbors.shell('sleep 5 && echo "Hello from $(hostname)"')
```


There are multiple ways to customize the fork value:
* Ansible Config File
* Environment Variable
* Argument "options" when creating AnsibleHosts or AnsibleHost instances

## Customize Fork - Environment Variable

According to https://docs.ansible.com/projects/ansible/latest/reference_appendices/config.html#default-forks, the environment variable `ANSIBLE_FORKS` can be set to customize the default fork value.


## Customize Fork - Ansible Config File
According to https://docs.ansible.com/projects/ansible/latest/reference_appendices/config.html#default-forks, the Ansible config file can be used to customize the default fork value. For example, in the ansible.cfg file, set the following:

```
[defaults]
forks = 10
```

## Customize Fork - Argument "options" of Constructor

When creating AnsibleHosts or AnsibleHost instances, the "options" argument can be used to customize the fork value. For example:

```python
neighbors = AnsibleHosts(
    inventory="veos_vtb",
    pattern=['VM0100', 'VM0101', 'VM0102', 'VM0103'],
    options={'forks': 2},
    hostvars={
        'ansible_user': 'root',
        'ansible_password': '123456'
    }
)

neighbors.shell('sleep 5 && echo "Hello from $(hostname)"')
```

## Priority of Different Methods to Customize Fork Value

Priority | Method
--- | ---
Low | Ansible Config File
Medium | Environment Variable
High | Argument "options" of Constructor
