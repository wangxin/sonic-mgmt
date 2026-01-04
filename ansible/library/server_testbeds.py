#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: server_testbeds
short_description: Manage testbeds on a test server
description:
    - Manage testbed resources on a test server
    - Supports allocating testbed indices, querying testbeds, and managing testbed data
    - Uses file locking for atomic operations
version_added: "1.0.0"
options:
    operation:
        description:
            - The operation to perform
        required: true
        type: str
        choices: ['allocate', 'get', 'delete', 'add', 'update']
    testbeds_json_file:
        description:
            - Path to the testbeds.json file
        required: false
        type: str
        default: /var/run/sonic/testbeds.json
    testbed_name:
        description:
            - Testbed name (required for operation=allocate)
            - Testbed name to filter by (used with operation=get)
            - Testbed name to delete (used with operation=delete)
        required: false
        type: str
    testbed_index:
        description:
            - Testbed index to filter by (used with operation=get)
            - Testbed index to delete (used with operation=delete)
        required: false
        type: int
    testbed_info:
        description:
            - Testbed information to add (used with operation=add)
            - Testbed information to update (used with operation=update)
            - Must contain at least testbed_name or testbed_index to identify the testbed
        required: false
        type: dict
    lock_timeout:
        description:
            - Maximum time in seconds to wait for acquiring the file lock
            - Only used for operations that modify the file
        required: false
        type: int
        default: 60
author:
    - SONiC Team
notes:
    - This module uses fcntl file locking for atomic operations
    - Safe for concurrent execution from multiple processes
'''

EXAMPLES = r'''
- name: Allocate a testbed index (reuses index if incomplete deployment exists)
  server_testbeds:
    operation: allocate
    testbed_name: vms-t1-lab
  register: result

- name: Get all testbeds
  server_testbeds:
    operation: get
  register: all_testbeds

- name: Get testbed by name
  server_testbeds:
    operation: get
    testbed_name: vms-t1-lab
  register: testbed_info

- name: Get testbed by index
  server_testbeds:
    operation: get
    testbed_index: 2
  register: testbed_info

- name: Delete testbed by name
  server_testbeds:
    operation: delete
    testbed_name: vms-t1-lab

- name: Delete testbed by index
  server_testbeds:
    operation: delete
    testbed_index: 2

- name: Delete testbed by both name and index
  server_testbeds:
    operation: delete
    testbed_name: vms-t1-lab
    testbed_index: 2

- name: Add testbed with full information
  server_testbeds:
    operation: add
    testbed_info:
      name: vms-t1-lab
      index: 2
      topology: t1
      server: server-01

- name: Update testbed by name and index
  server_testbeds:
    operation: update
    testbed_info:
      name: vms-t1-lab
      index: 2
      topology: t1-lag
      server: server-02
      status: active
'''

RETURN = r'''
testbed_index:
    description: The allocated testbed index (operation=allocate)
    returned: when operation is allocate
    type: int
    sample: 2
testbeds:
    description: List of testbeds (operation=get)
    returned: when operation is get
    type: list
    sample: [{"index": 0, "name": "vms-t1-lab"}]
count:
    description: Number of testbeds returned (operation=get)
    returned: when operation is get
    type: int
    sample: 1
delete_count:
    description: Number of testbeds deleted (operation=delete)
    returned: when operation is delete
    type: int
    sample: 1
added_testbed:
    description: The testbed information that was added (operation=add)
    returned: when operation is add
    type: dict
    sample: {"name": "vms-t1-lab", "index": 2}
updated_testbed:
    description: The testbed information that was updated (operation=update)
    returned: when operation is update
    type: dict
    sample: {"name": "vms-t1-lab", "index": 2, "topology": "t1-lag"}
msg:
    description: Status message
    returned: always
    type: str
    sample: "Successfully allocated testbed index 2"
'''

from ansible.module_utils.basic import AnsibleModule
import json
import fcntl
import os
import time
from contextlib import contextmanager


def read_testbeds_file(testbeds_file):
    """
    Read and parse the testbeds.json file.

    Args:
        testbeds_file: Path to the testbeds.json file

    Returns:
        dict: Parsed testbeds data with structure {"testbeds": [...]}
    """
    deployed = {"testbeds": []}
    if os.path.exists(testbeds_file):
        try:
            with open(testbeds_file, 'r') as f:
                deployed = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            # If file is corrupt or doesn't exist, start fresh
            pass
    return deployed


@contextmanager
def acquire_testbeds_lock(testbeds_file, lock_timeout):
    """
    Context manager for acquiring an exclusive lock on the testbeds file.

    Args:
        testbeds_file: Path to the testbeds.json file
        lock_timeout: Maximum time in seconds to wait for the lock

    Yields:
        None

    Raises:
        Exception: If lock cannot be acquired within timeout
    """
    lock_file = f"{testbeds_file}.lock"

    # Ensure directory exists
    os.makedirs(os.path.dirname(testbeds_file), exist_ok=True)

    # Open lock file
    lock_fd = open(lock_file, 'w')
    try:
        start_time = time.time()

        # Try to acquire lock with timeout
        while True:
            try:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break  # Lock acquired successfully
            except BlockingIOError:
                elapsed = time.time() - start_time
                if elapsed >= lock_timeout:
                    raise Exception(
                        f"Failed to acquire lock within {lock_timeout} seconds. "
                        "Another process may be modifying testbeds."
                    )
                time.sleep(5)  # Wait 5 seconds before retrying

        # Lock acquired, yield control to caller
        yield

    finally:
        # Release lock and close file
        try:
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
        except:
            pass
        lock_fd.close()


def allocate_testbed_index(testbeds_file, lock_timeout, testbed_name):
    """
    Allocate a unique testbed index atomically using file locking.

    If a testbed with matching name and status="deploying" exists,
    reuses that index (for resuming incomplete deployments). Otherwise, allocates a new index.

    Args:
        testbeds_file: Path to the testbeds.json file
        lock_timeout: Maximum time in seconds to wait for the lock
        testbed_name: Testbed name (required for tracking and reuse logic)

    Returns:
        tuple: (success: bool, testbed_index: int, message: str)
    """
    try:
        # Validate testbed_name
        if not testbed_name:
            return False, None, "testbed_name is required for allocate operation"

        with acquire_testbeds_lock(testbeds_file, lock_timeout):
            # Read current testbeds
            deployed = read_testbeds_file(testbeds_file)
            testbeds_list = deployed.get("testbeds", [])

            # Check if testbed with matching name and status="deploying" exists
            existing_deploying_index = None
            for testbed_info in testbeds_list:
                if isinstance(testbed_info, dict):
                    if (testbed_info.get("name") == testbed_name and
                        testbed_info.get("status") == "deploying"):
                        existing_deploying_index = testbed_info.get("index")
                        break

            # If found existing deploying testbed, reuse its index
            if existing_deploying_index is not None:
                return (
                    True,
                    existing_deploying_index,
                    f"Reusing existing testbed index {existing_deploying_index} for incomplete deployment"
                )

            # Otherwise, allocate a new index
            # Collect used indices
            used_indices = set()
            for testbed_info in testbeds_list:
                if isinstance(testbed_info, dict):
                    index = testbed_info.get("index")
                    if index is not None:
                        used_indices.add(index)

            # Find first available index
            testbed_index = 0
            while testbed_index in used_indices:
                testbed_index += 1

            # Append new testbed entry with name and status
            new_testbed = {
                "index": testbed_index,
                "name": testbed_name,
                "status": "deploying"
            }
            testbeds_list.append(new_testbed)
            deployed["testbeds"] = testbeds_list

            # Write back to file
            with open(testbeds_file, 'w') as f:
                json.dump(deployed, f, indent=2)

        return True, testbed_index, f"Successfully allocated testbed index {testbed_index}"

    except Exception as e:
        return False, None, f"Failed to allocate testbed index: {str(e)}"


def get_testbeds(testbeds_file, testbed_name=None, testbed_index=None):
    """
    Get testbeds from the testbeds.json file.

    Args:
        testbeds_file: Path to the testbeds.json file
        testbed_name: Optional testbed name to filter by
        testbed_index: Optional testbed index to filter by

    Returns:
        tuple: (success: bool, testbeds: list, count: int, message: str)
    """
    try:
        # Read testbeds file
        deployed = read_testbeds_file(testbeds_file)
        testbeds_list = deployed.get("testbeds", [])

        # Filter testbeds based on criteria
        filtered_testbeds = []
        for testbed_info in testbeds_list:
            if not isinstance(testbed_info, dict):
                continue

            # Check if matches filter criteria
            match = True
            if testbed_name is not None:
                if testbed_info.get("name") != testbed_name:
                    match = False

            if testbed_index is not None:
                if testbed_info.get("index") != testbed_index:
                    match = False

            if match:
                filtered_testbeds.append(testbed_info)

        return True, filtered_testbeds, len(filtered_testbeds), f"Found {len(filtered_testbeds)} testbed(s)"

    except Exception as e:
        return False, [], 0, f"Failed to get testbeds: {str(e)}"


def delete_testbed(testbeds_file, lock_timeout, testbed_name=None, testbed_index=None):
    """
    Delete testbeds from the testbeds.json file.

    Args:
        testbeds_file: Path to the testbeds.json file
        lock_timeout: Maximum time in seconds to wait for the lock
        testbed_name: Optional testbed name to delete
        testbed_index: Optional testbed index to delete

    Returns:
        tuple: (success: bool, delete_count: int, message: str)
    """
    try:
        with acquire_testbeds_lock(testbeds_file, lock_timeout):
            # Read current testbeds
            deployed = read_testbeds_file(testbeds_file)
            testbeds_list = deployed.get("testbeds", [])

            # Filter out testbeds that match the criteria
            original_count = len(testbeds_list)
            filtered_testbeds = []

            for testbed_info in testbeds_list:
                if not isinstance(testbed_info, dict):
                    filtered_testbeds.append(testbed_info)
                    continue

                # Check if this testbed should be deleted
                should_delete = True

                # If testbed_name is specified, it must match
                if testbed_name is not None:
                    if testbed_info.get("name") != testbed_name:
                        should_delete = False

                # If testbed_index is specified, it must match
                if testbed_index is not None:
                    if testbed_info.get("index") != testbed_index:
                        should_delete = False

                # Keep testbed if it should not be deleted
                if not should_delete:
                    filtered_testbeds.append(testbed_info)

            delete_count = original_count - len(filtered_testbeds)

            # Update the testbeds list
            deployed["testbeds"] = filtered_testbeds

            # Write back to file
            with open(testbeds_file, 'w') as f:
                json.dump(deployed, f, indent=2)

        return True, delete_count, f"Successfully deleted {delete_count} testbed(s)"

    except Exception as e:
        return False, 0, f"Failed to delete testbed: {str(e)}"


def add_testbed(testbeds_file, lock_timeout, testbed_info):
    """
    Add a testbed to the testbeds.json file.

    Args:
        testbeds_file: Path to the testbeds.json file
        lock_timeout: Maximum time in seconds to wait for the lock
        testbed_info: Dictionary containing testbed information

    Returns:
        tuple: (success: bool, added_testbed: dict, message: str)
    """
    try:
        # Validate testbed_info
        if not isinstance(testbed_info, dict):
            return False, None, "testbed_info must be a dictionary"

        if "name" not in testbed_info and "index" not in testbed_info:
            return (
                False,
                None,
                "testbed_info must contain at least 'name' or 'index'"
            )

        with acquire_testbeds_lock(testbeds_file, lock_timeout):
            # Read current testbeds
            deployed = read_testbeds_file(testbeds_file)
            testbeds_list = deployed.get("testbeds", [])

            # Add the new testbed
            testbeds_list.append(testbed_info)
            deployed["testbeds"] = testbeds_list

            # Write back to file
            with open(testbeds_file, 'w') as f:
                json.dump(deployed, f, indent=2)

        return True, testbed_info, f"Successfully added testbed"

    except Exception as e:
        return False, None, f"Failed to add testbed: {str(e)}"


def update_testbed(testbeds_file, lock_timeout, testbed_info):
    """
    Update a testbed in the testbeds.json file.

    Args:
        testbeds_file: Path to the testbeds.json file
        lock_timeout: Maximum time in seconds to wait for the lock
        testbed_info: Dictionary containing testbed information with identifiers

    Returns:
        tuple: (success: bool, updated_testbed: dict, message: str)
    """
    try:
        # Validate testbed_info
        if not isinstance(testbed_info, dict):
            return False, None, "testbed_info must be a dictionary"

        if "name" not in testbed_info and "index" not in testbed_info:
            return (
                False,
                None,
                "testbed_info must contain at least 'name' or 'index'"
            )

        with acquire_testbeds_lock(testbeds_file, lock_timeout):
            # Read current testbeds
            deployed = read_testbeds_file(testbeds_file)
            testbeds_list = deployed.get("testbeds", [])

            # Find and update the matching testbed
            testbed_name = testbed_info.get("name")
            testbed_index = testbed_info.get("index")
            found = False

            for i, testbed in enumerate(testbeds_list):
                if not isinstance(testbed, dict):
                    continue

                # Check if this testbed matches the criteria
                match = True

                # If testbed_name is specified in testbed_info, it must match
                if testbed_name is not None:
                    if testbed.get("name") != testbed_name:
                        match = False

                # If testbed_index is specified in testbed_info, it must match
                if testbed_index is not None:
                    if testbed.get("index") != testbed_index:
                        match = False

                # Update the testbed if it matches
                if match:
                    testbeds_list[i] = testbed_info
                    found = True
                    break

            if not found:
                return False, None, "No matching testbed found to update"

            deployed["testbeds"] = testbeds_list

            # Write back to file
            with open(testbeds_file, 'w') as f:
                json.dump(deployed, f, indent=2)

        return True, testbed_info, f"Successfully updated testbed"

    except Exception as e:
        return False, None, f"Failed to update testbed: {str(e)}"


def main():
    module = AnsibleModule(
        argument_spec=dict(
            operation=dict(type='str', required=True, choices=['allocate', 'get', 'delete', 'add', 'update']),
            testbeds_json_file=dict(type='str', required=False, default='/var/run/sonic/testbeds.json'),
            testbed_name=dict(type='str', required=False, default=None),
            testbed_index=dict(type='int', required=False, default=None),
            testbed_info=dict(type='dict', required=False, default=None),
            lock_timeout=dict(type='int', required=False, default=60),
        ),
        supports_check_mode=False
    )

    operation = module.params['operation']
    testbeds_file = module.params['testbeds_json_file']
    testbed_name = module.params['testbed_name']
    testbed_index = module.params['testbed_index']
    testbed_info = module.params['testbed_info']
    lock_timeout = module.params['lock_timeout']

    if operation == 'allocate':
        # testbed_name is required for allocate operation
        if testbed_name is None:
            module.fail_json(msg="testbed_name is required for allocate operation")

        success, testbed_idx, message = allocate_testbed_index(testbeds_file, lock_timeout, testbed_name)
        if success:
            module.exit_json(
                changed=True,
                testbed_index=testbed_idx,
                msg=message
            )
        else:
            module.fail_json(msg=message)

    elif operation == 'get':
        success, testbeds, count, message = get_testbeds(testbeds_file, testbed_name, testbed_index)
        if success:
            module.exit_json(
                changed=False,
                testbeds=testbeds,
                count=count,
                msg=message
            )
        else:
            module.fail_json(msg=message)

    elif operation == 'delete':
        # At least one of testbed_name or testbed_index must be provided
        if testbed_name is None and testbed_index is None:
            module.fail_json(
                msg="At least one of testbed_name or testbed_index must be provided for delete operation"
            )

        success, delete_count, message = delete_testbed(testbeds_file, lock_timeout, testbed_name, testbed_index)
        if success:
            module.exit_json(
                changed=delete_count > 0,
                delete_count=delete_count,
                msg=message
            )
        else:
            module.fail_json(msg=message)

    elif operation == 'add':
        # testbed_info must be provided
        if testbed_info is None:
            module.fail_json(msg="testbed_info must be provided for add operation")

        success, added_testbed, message = add_testbed(testbeds_file, lock_timeout, testbed_info)
        if success:
            module.exit_json(
                changed=True,
                added_testbed=added_testbed,
                msg=message
            )
        else:
            module.fail_json(msg=message)

    elif operation == 'update':
        # testbed_info must be provided
        if testbed_info is None:
            module.fail_json(msg="testbed_info must be provided for update operation")

        success, updated_testbed, message = update_testbed(testbeds_file, lock_timeout, testbed_info)
        if success:
            module.exit_json(
                changed=True,
                updated_testbed=updated_testbed,
                msg=message
            )
        else:
            module.fail_json(msg=message)


if __name__ == '__main__':
    main()
