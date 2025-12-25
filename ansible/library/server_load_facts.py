#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: server_load_facts
short_description: Gather server load metrics from /proc filesystem
description:
    - Collects important server load metrics from /proc filesystem
    - Returns CPU, memory, disk I/O, network, and process statistics
    - Provides load averages and uptime information
version_added: "1.0.0"
options: {}
author:
    - Xin Wang (xiwang5@microsoft.com)
notes:
    - This module reads from /proc filesystem
    - Requires Linux operating system
'''

EXAMPLES = r'''
- name: Gather server load facts
  server_load_facts:
  register: load_info

- name: Display CPU usage
  debug:
    msg: "CPU usage: {{ load_info.server_load.cpu.usage_percent }}%"

- name: Display memory usage
  debug:
    msg: "Memory usage: {{ load_info.server_load.memory.used_percent }}%"
'''

RETURN = r'''
server_load:
    description: Dictionary containing server load metrics
    returned: always
    type: dict
    contains:
        cpu:
            description: CPU statistics
            type: dict
            contains:
                usage_percent:
                    description: Overall CPU usage percentage
                    type: float
                user:
                    description: Time spent in user mode
                    type: int
                system:
                    description: Time spent in system mode
                    type: int
                idle:
                    description: Time spent idle
                    type: int
                iowait:
                    description: Time spent waiting for I/O
                    type: int
                cores:
                    description: Number of CPU cores
                    type: int
        memory:
            description: Memory statistics
            type: dict
            contains:
                total_mb:
                    description: Total memory in MB
                    type: float
                available_mb:
                    description: Available memory in MB
                    type: float
                used_mb:
                    description: Used memory in MB
                    type: float
                used_percent:
                    description: Memory usage percentage
                    type: float
                swap_total_mb:
                    description: Total swap in MB
                    type: float
                swap_used_mb:
                    description: Used swap in MB
                    type: float
        load_average:
            description: System load averages
            type: dict
            contains:
                one_min:
                    description: 1-minute load average
                    type: float
                five_min:
                    description: 5-minute load average
                    type: float
                fifteen_min:
                    description: 15-minute load average
                    type: float
        disk_io:
            description: Disk I/O statistics
            type: dict
        network:
            description: Network statistics per interface
            type: dict
        processes:
            description: Process statistics
            type: dict
            contains:
                total:
                    description: Total number of processes
                    type: int
                running:
                    description: Number of running processes
                    type: int
                sleeping:
                    description: Number of sleeping processes
                    type: int
        uptime:
            description: System uptime information
            type: dict
            contains:
                uptime_seconds:
                    description: Uptime in seconds
                    type: float
                uptime_days:
                    description: Uptime in days
                    type: float
'''

from ansible.module_utils.basic import AnsibleModule
import os
import re


def read_proc_file(filepath):
    """Safely read a /proc file."""
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except Exception as e:
        return None


def get_cpu_stats():
    """Get CPU statistics from /proc/stat."""
    cpu_stats = {}
    content = read_proc_file('/proc/stat')
    if not content:
        return cpu_stats

    lines = content.split('\n')
    cpu_line = None
    cpu_count = 0

    for line in lines:
        if line.startswith('cpu '):
            cpu_line = line
        elif line.startswith('cpu'):
            cpu_count += 1

    if cpu_line:
        parts = cpu_line.split()
        user = int(parts[1])
        nice = int(parts[2])
        system = int(parts[3])
        idle = int(parts[4])
        iowait = int(parts[5]) if len(parts) > 5 else 0
        irq = int(parts[6]) if len(parts) > 6 else 0
        softirq = int(parts[7]) if len(parts) > 7 else 0
        steal = int(parts[8]) if len(parts) > 8 else 0

        total = user + nice + system + idle + iowait + irq + softirq + steal
        total_active = total - idle - iowait

        cpu_stats = {
            'user': user,
            'nice': nice,
            'system': system,
            'idle': idle,
            'iowait': iowait,
            'irq': irq,
            'softirq': softirq,
            'steal': steal,
            'total': total,
            'usage_percent': round((total_active / total * 100) if total > 0 else 0, 2),
            'cores': cpu_count
        }

    return cpu_stats


def get_memory_stats():
    """Get memory statistics from /proc/meminfo."""
    mem_stats = {}
    content = read_proc_file('/proc/meminfo')
    if not content:
        return mem_stats

    meminfo = {}
    for line in content.split('\n'):
        if ':' in line:
            key, value = line.split(':', 1)
            # Extract numeric value (remove 'kB' and whitespace)
            value = value.strip().split()[0]
            meminfo[key.strip()] = int(value)

    # Convert kB to MB
    total = meminfo.get('MemTotal', 0) / 1024.0
    free = meminfo.get('MemFree', 0) / 1024.0
    available = meminfo.get('MemAvailable', meminfo.get('MemFree', 0)) / 1024.0
    buffers = meminfo.get('Buffers', 0) / 1024.0
    cached = meminfo.get('Cached', 0) / 1024.0

    used = total - available
    used_percent = (used / total * 100) if total > 0 else 0

    swap_total = meminfo.get('SwapTotal', 0) / 1024.0
    swap_free = meminfo.get('SwapFree', 0) / 1024.0
    swap_used = swap_total - swap_free

    mem_stats = {
        'total_mb': round(total, 2),
        'free_mb': round(free, 2),
        'available_mb': round(available, 2),
        'used_mb': round(used, 2),
        'used_percent': round(used_percent, 2),
        'buffers_mb': round(buffers, 2),
        'cached_mb': round(cached, 2),
        'swap_total_mb': round(swap_total, 2),
        'swap_free_mb': round(swap_free, 2),
        'swap_used_mb': round(swap_used, 2),
        'swap_used_percent': round((swap_used / swap_total * 100) if swap_total > 0 else 0, 2)
    }

    return mem_stats


def get_load_average():
    """Get load average from /proc/loadavg."""
    load_avg = {}
    content = read_proc_file('/proc/loadavg')
    if not content:
        return load_avg

    parts = content.strip().split()
    if len(parts) >= 3:
        load_avg = {
            'one_min': float(parts[0]),
            'five_min': float(parts[1]),
            'fifteen_min': float(parts[2])
        }

        if len(parts) >= 4:
            # Format: running/total
            proc_info = parts[3].split('/')
            if len(proc_info) == 2:
                load_avg['running_processes'] = int(proc_info[0])
                load_avg['total_processes'] = int(proc_info[1])

    return load_avg


def get_disk_io_stats():
    """Get disk I/O statistics from /proc/diskstats."""
    disk_stats = {}
    content = read_proc_file('/proc/diskstats')
    if not content:
        return disk_stats

    for line in content.split('\n'):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) < 14:
            continue

        device = parts[2]

        # Skip loop devices and partitions (only main devices like sda, nvme0n1)
        if 'loop' in device or re.search(r'\d+$', device):
            continue

        disk_stats[device] = {
            'reads_completed': int(parts[3]),
            'reads_merged': int(parts[4]),
            'sectors_read': int(parts[5]),
            'time_reading_ms': int(parts[6]),
            'writes_completed': int(parts[7]),
            'writes_merged': int(parts[8]),
            'sectors_written': int(parts[9]),
            'time_writing_ms': int(parts[10]),
            'io_in_progress': int(parts[11]),
            'time_doing_io_ms': int(parts[12]),
            'weighted_time_doing_io_ms': int(parts[13])
        }

    return disk_stats


def get_network_stats():
    """Get network statistics from /proc/net/dev."""
    net_stats = {}
    content = read_proc_file('/proc/net/dev')
    if not content:
        return net_stats

    lines = content.split('\n')
    # Skip the first two header lines
    for line in lines[2:]:
        if ':' not in line:
            continue

        iface, data = line.split(':', 1)
        iface = iface.strip()

        # Skip loopback
        if iface == 'lo':
            continue

        parts = data.split()
        if len(parts) >= 16:
            net_stats[iface] = {
                'rx_bytes': int(parts[0]),
                'rx_packets': int(parts[1]),
                'rx_errors': int(parts[2]),
                'rx_dropped': int(parts[3]),
                'tx_bytes': int(parts[8]),
                'tx_packets': int(parts[9]),
                'tx_errors': int(parts[10]),
                'tx_dropped': int(parts[11])
            }

    return net_stats


def get_process_stats():
    """Get process statistics by reading /proc/[pid]/stat files."""
    proc_stats = {
        'total': 0,
        'running': 0,
        'sleeping': 0,
        'stopped': 0,
        'zombie': 0,
        'other': 0
    }

    try:
        # Count processes and their states
        proc_dir = '/proc'
        for entry in os.listdir(proc_dir):
            if not entry.isdigit():
                continue

            stat_file = os.path.join(proc_dir, entry, 'stat')
            content = read_proc_file(stat_file)
            if not content:
                continue

            # Extract state (third field)
            # Format: pid (comm) state ...
            match = re.search(r'\)\s+(\S)', content)
            if match:
                state = match.group(1)
                proc_stats['total'] += 1

                if state == 'R':
                    proc_stats['running'] += 1
                elif state == 'S' or state == 'D':
                    proc_stats['sleeping'] += 1
                elif state == 'T':
                    proc_stats['stopped'] += 1
                elif state == 'Z':
                    proc_stats['zombie'] += 1
                else:
                    proc_stats['other'] += 1
    except Exception:
        pass

    return proc_stats


def get_uptime():
    """Get system uptime from /proc/uptime."""
    uptime_info = {}
    content = read_proc_file('/proc/uptime')
    if not content:
        return uptime_info

    parts = content.strip().split()
    if len(parts) >= 1:
        uptime_seconds = float(parts[0])
        uptime_info = {
            'uptime_seconds': round(uptime_seconds, 2),
            'uptime_minutes': round(uptime_seconds / 60, 2),
            'uptime_hours': round(uptime_seconds / 3600, 2),
            'uptime_days': round(uptime_seconds / 86400, 2)
        }

        if len(parts) >= 2:
            uptime_info['idle_seconds'] = round(float(parts[1]), 2)

    return uptime_info


def get_system_info():
    """Get basic system information."""
    sys_info = {}

    # Kernel version
    content = read_proc_file('/proc/version')
    if content:
        sys_info['kernel_version'] = content.strip()

    # Hostname
    content = read_proc_file('/proc/sys/kernel/hostname')
    if content:
        sys_info['hostname'] = content.strip()

    return sys_info


def main():
    """Main module execution."""
    module = AnsibleModule(
        argument_spec={},
        supports_check_mode=True
    )

    # Gather all server load metrics
    server_load = {
        'cpu': get_cpu_stats(),
        'memory': get_memory_stats(),
        'load_average': get_load_average(),
        'disk_io': get_disk_io_stats(),
        'network': get_network_stats(),
        'processes': get_process_stats(),
        'uptime': get_uptime(),
        'system': get_system_info()
    }

    # Return the results
    module.exit_json(
        changed=False,
        ansible_facts={'server_load': server_load},
        server_load=server_load
    )


if __name__ == '__main__':
    main()
