#!/usr/bin/env python3
"""
Testbed CLI tool for managing SONiC testbed deployment and configuration.
"""

import logging
import os
from enum import Enum
from typing import Annotated

import typer

from testbed.deploy import deploy_testbed, undeploy_testbed
from testbed.configure import configure_duts


__version__ = "1.0.0"

logger = logging.getLogger("testbed-cli")

app = typer.Typer(
    name="testbed-cli",
    help="SONiC testbed management CLI tool",
    add_completion=False
)


def setup_logging(verbosity: int):
    """
    Configure logging for the application and Ansible library.

    Args:
        verbosity: Verbosity level (0-4+)
            0: WARNING level CLI logging, Ansible verbosity=0 (silent)
            1: INFO level CLI logging, Ansible verbosity=2 (default detail)
            2: DEBUG level CLI logging, Ansible verbosity=3 (formatted)
            3+: DEBUG level CLI logging, Ansible verbosity=4 (full stats)
    """
    # Map verbosity to CLI logging level
    if verbosity == 0:
        cli_log_level = logging.WARNING
    elif verbosity == 1:
        cli_log_level = logging.INFO
    else:  # 2+
        cli_log_level = logging.DEBUG

    # Configure root logger to capture all logs from all modules
    root_logger = logging.getLogger()
    root_logger.setLevel(cli_log_level)

    # Clear any existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(cli_log_level)

    # Use detailed format with filename and line number for better debugging
    # formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')

    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Configure Ansible library logging via environment variable
    # Only set if not already configured by user
    existing_ansible_verbosity = os.environ.get('ANSIBLE_PYAPI_VERBOSITY')

    if existing_ansible_verbosity:
        # Respect user's environment variable
        logger.debug(f"Using existing ANSIBLE_PYAPI_VERBOSITY={existing_ansible_verbosity}")
    else:
        # Map CLI verbosity to Ansible verbosity:
        # 0 -> 0 (silent)
        # 1 -> 2 (default with args/results)
        # 2 -> 3 (formatted)
        # 3+ -> 4 (full stats)
        if verbosity == 0:
            ansible_verbosity = 0
        elif verbosity == 1:
            ansible_verbosity = 1
        elif verbosity == 2:
            ansible_verbosity = 2
        else:
            ansible_verbosity = 3

        os.environ['ANSIBLE_PYAPI_VERBOSITY'] = str(ansible_verbosity)
        logger.debug(f"Set ANSIBLE_PYAPI_VERBOSITY={ansible_verbosity}")

    logger.debug(f"CLI logging level: {logging.getLevelName(cli_log_level)}")


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        typer.echo(f"testbed-cli version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=version_callback, is_eager=True, help="Show version and exit")
    ] = None,
    verbose: Annotated[
        int,
        typer.Option("--verbose", "-v", count=True, help="Increase verbosity (-v, -vv, -vvv for more detail)")
    ] = 0,
):
    """
    SONiC testbed management CLI tool.

    Verbosity levels:
    - (none): Minimal output, warnings and errors only
    - -v: Show progress and important information
    - -vv: Debug CLI operations with detailed Ansible output
    - -vvv or more: Full debug including Ansible internals
    """
    setup_logging(verbose)


@app.command()
def deploy(
    testbed_file: Annotated[
        str,
        typer.Option("--testbed-file", help="Path to the testbed configuration file")
    ],
    testbed_name: Annotated[
        str,
        typer.Option("--testbed-name", help="Name of the testbed to deploy")
    ],
    neighbor_type: Annotated[
        str,
        typer.Option("--neighbor-type", help="Type of neighbor devices (e.g., 'ceos')")
    ] = "ceos",
    server: Annotated[
        str | None,
        typer.Option("--server", help="Target server name (optional, will auto-select if not provided). Overrides server in testbed definition")
    ] = None,
):
    """
    Deploy testbed.
    """
    try:
        deploy_testbed(testbed_file, testbed_name, neighbor_type=neighbor_type, server=server)
    except (ValueError, RuntimeError, FileNotFoundError) as e:
        # Expected errors - show clean message
        logger.error(f"{e}")
        # Show traceback in debug mode
        if logger.level <= logging.DEBUG:
            logger.exception("Exception details:")
        raise typer.Exit(code=1)
    except Exception:
        # Unexpected errors - always show traceback
        logger.exception("Unexpected error occurred:")
        raise typer.Exit(code=1)


@app.command()
def configure(
    testbed_file: Annotated[
        str,
        typer.Option("--testbed-file", help="Path to the testbed configuration file")
    ],
    testbed_name: Annotated[
        str,
        typer.Option("--testbed-name", help="Name of the testbed to configure")
    ],
):
    """
    Configure testbed.
    """
    logger.info(f"Configuring testbed '{testbed_name}' from '{testbed_file}'")
    configure_duts(
        testbed_file=testbed_file,
        testbed_name=testbed_name
    )


@app.command()
def undeploy(
    testbed_file: Annotated[
        str,
        typer.Option("--testbed-file", help="Path to the testbed configuration file")
    ],
    testbed_name: Annotated[
        str,
        typer.Option("--testbed-name", help="Name of the testbed to undeploy")
    ],
    neighbor_type: Annotated[
        str,
        typer.Option("--neighbor-type", help="Type of neighbor devices (e.g., 'ceos')")
    ] = "ceos",
    server: Annotated[
        str | None,
        typer.Option("--server", help="Target server name (optional, will auto-detect if not provided)")
    ] = None,
):
    """
    Undeploy testbed.
    """
    logger.info(f"Undeploying testbed '{testbed_name}' from '{testbed_file}'")
    undeploy_testbed(
        testbed_file=testbed_file,
        testbed_name=testbed_name,
        neighbor_type=neighbor_type,
        server=server
    )


if __name__ == '__main__':
    app()
