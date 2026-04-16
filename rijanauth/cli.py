# -*- encoding: utf-8 -*-
"""
RijanAuth CLI - Main Entry Point
"""

import sys
import os
import click

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rijanauth.commands.doctor import doctor
from rijanauth.commands.realm import realm
from rijanauth.commands.client import client
from rijanauth.commands.user import user
from rijanauth.commands.role import role
from rijanauth.commands.group_cmd import group as group_cmd
from rijanauth.commands.backup import backup
from rijanauth.commands.smtp import smtp
from rijanauth.commands.federation import federation
from rijanauth.commands.export import export


@click.group()
@click.version_option(version="1.0.0", prog_name="rijanauth")
def cli():
    """RijanAuth CLI - Command Line Interface for RijanAuth
    
    Manage realms, users, clients, roles, groups, backups, and more.
    """
    pass


cli.add_command(doctor)
cli.add_command(realm)
cli.add_command(client)
cli.add_command(user)
cli.add_command(role)
cli.add_command(group_cmd)
cli.add_command(backup)
cli.add_command(smtp)
cli.add_command(federation)
cli.add_command(export)


if __name__ == "__main__":
    cli()
