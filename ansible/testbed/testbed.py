import json
import logging
import os
import yaml
from enum import Enum


logger = logging.getLogger(__name__)


class TestbedType(Enum):
    PHYSICAL = "physical"
    KVM = "kvm"


# Base class to model a testbed
class Testbed(object):
    def __init__(
            self,
            name: str,
            duts: list[str],
            topology: str,
            testbed_type: str,
            group: str,
            server: str=None,
            ptf_image="docker-ptf",
        ):
        ################################################################################################################
        #### Below testbed attributes are from testbed definition                                                   ####
        ################################################################################################################

        # Unique testbed name
        self.name = name

        # Topology name of the testbed
        self.topology = topology

        self.type = testbed_type

        # Devices Under Test (DUTs) in the testbed
        self.duts = duts

        # The convention is to organize testbeds by root fanout switch.
        # For devices connected to the same root fanout switch, we can give them a common group name.
        # Reference: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/README.testbed.Overview.md#physical-topology
        self.group = group

        # Name of the server for deploying testbed.
        self.server = server

        # PTF docker image name. If specified, PTF container will be deployed using this image.
        self.ptf_image = ptf_image

        ################################################################################################################
        #### Below are dynamic or runtime attributes                                                                ####
        ################################################################################################################
        self.index = None
        self.neighbor_type = "ceos"
        self.remote_neighbor = False
        self.neighbors = {}
        self.ptf = None


def get_testbed(testbed_src, testbed_name):
    """Get testbed from testbed definition source.

    Testbed definition source could be a yaml file or an API.

    Old testbed schema:
        - conf-name: vms-kvm-t0
          group-name: vms6-1
          topo: t0
          type: kvm
          ptf_image_name: docker-ptf
          ptf: ptf-01
          ptf_ip: 10.250.0.102/24
          ptf_ipv6: fec0::ffff:afa:2/64
          server: server_1
          vm_base: VM0100
          dut:
              - vlab-01
          inv_name: veos_vtb
          auto_recover: 'False'
          comment: Tests virtual switch vm

    New testbed schema:
        - name: vms-kvm-t0
          topology: t0
          type: kvm
          duts:
              - vlab-01
          group: lab
          server:
          ptf_image: docker-ptf

    Args:
        testbed_src (str): Source of testbed definition. It could be a yaml file path or an API endpoint.
        testbed_name (str): Name of the testbed to be retrieved.

    Returns:
        Testbed: Testbed object.
"""

    testbed_definition = {}

    # Testbed source is a yaml file
    if os.path.isfile(testbed_src):
        if testbed_src.endswith(".yaml") or testbed_src.endswith(".yml"):
            with open(testbed_src) as f:
                yaml_testbeds = yaml.safe_load(f.read())

            for _testbed in yaml_testbeds:
                name = _testbed.get("name", None)
                if name is None:
                    name = _testbed.get("conf-name")    # for compatible with legacy testbed.yaml schema

                if name == testbed_name:

                    topology = _testbed.get("topology", None)
                    if topology is None:
                        topology = _testbed.get("topo")     # for compatible with legacy testbed.yaml schema

                    duts = _testbed.get("duts", None)
                    if duts is None:
                        duts = _testbed.get("dut", [])      # for compatible with legacy testbed.yaml schema

                    testbed_type = _testbed.get("type", "physical")

                    group = _testbed.get("group", None)
                    if group is None:
                        group = _testbed.get("inv_name")    # for compatible with legacy testbed.yaml schema

                    ptf_image = _testbed.get("ptf_image", None)
                    if ptf_image is None:
                        ptf_image = _testbed.get("ptf_image_name", None)  # for compatible with legacy schema
                    if ptf_image is None:
                        ptf_image = "docker-ptf"  # default ptf image name

                    server = _testbed.get("server", None)

                    testbed_definition = {
                        "name": name,
                        "topology": topology,
                        "testbed_type": testbed_type,
                        "duts": duts,
                        "group": group,
                        "server": server,
                        "ptf_image": ptf_image,
                    }

                    break

    if testbed_definition:
        return Testbed(
            name=testbed_definition["name"],
            topology=testbed_definition["topology"],
            testbed_type=testbed_definition["testbed_type"],
            duts=testbed_definition["duts"],
            group=testbed_definition["group"],
            server=testbed_definition["server"],
            ptf_image=testbed_definition["ptf_image"],
        )
    else:
        return None
