import logging
import os
import yaml

from .settings import CONSTANTS as C


logger = logging.getLogger(__name__)


def get_topology_definition(topology: str) -> dict:
    """
    Read topology definition from ansible/vars directory.

    Args:
        topology: Name of the topology (e.g., 't0', 't1', 'dualtor')

    Returns:
        dict: Topology definition loaded from the YAML file

    Raises:
        FileNotFoundError: If the topology file does not exist
        ValueError: If the topology file is invalid or cannot be parsed
    """
    # Determine vars directory
    vars_dir = os.path.join(C.ANSIBLE_DIR, 'vars')

    # Construct topology file path
    topology_filename = f"topo_{topology}.yml"
    topology_file = os.path.join(vars_dir, topology_filename)

    logger.debug(f"Reading topology definition from '{topology_file}'")

    # Check if file exists
    if not os.path.exists(topology_file):
        raise FileNotFoundError(
            f"Topology file '{topology_filename}' not found in '{vars_dir}'. "
            f"Available topology files should follow the pattern 'topo_{{topology}}.yml'"
        )

    # Read and parse the YAML file
    try:
        with open(topology_file, 'r') as f:
            topology_definition = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Failed to parse topology file '{topology_file}': {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to read topology file '{topology_file}': {str(e)}")

    if topology_definition is None:
        raise ValueError(f"Topology file '{topology_file}' is empty")

    logger.info(f"Successfully loaded topology definition for '{topology}'")
    return topology_definition
