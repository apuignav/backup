#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
# @file   backup.py
# @author Albert Puig (albert.puig@cern.ch)
# @date   03.07.2019
# =============================================================================
"""Backup directories."""

import sys
import os

import subprocess

import yaml
import click


# require Python interpreter > v.3.5
assert sys.version_info >= (3, 5)


RSYNC_OPTS = {'archive': '-a',
              'compress': '-z',
              'human-readable': '-h',
              'progress': '--info=progress2',
              'delete-excluded': '--delete-excluded',
              'delete-from-dest': '--delete'}


def load_config(config_file):
    """Load config file.

    Arguments
    ---------
    config_file : str
        File to open.

    Return
    ------
    tuple:
        rsync config and configured profiles.

    Raise
    -----
    KeyError:
        If parts of the configuration are missing.

    """
    if not os.path.exists(config_file):
        raise OSError(f"Cannot find config file {config_file}")
    with open(config_file, 'r') as config_:
        config = yaml.safe_load(config_)
    return config['rsync-config'], config['profiles']


def process_rsync_config(config_list):
    """Convert rsync config to flags for command line.

    If elements of the configuration list start with a hyphen, they are
    used verbatim. Otherwise, they are replaced by the correct flag from `RSYNC_OPTS`.

    Arguments
    ---------
    config_list : list
        Options to configure.

    Return
    ------
    list

    Raise
    -----
    KeyError:
        If some configuration flags are unknown.

    """
    processed_config = []
    for config_element in config_list:
        if config_element.startswith('-'):
            processed_config.append(config_element)
        else:
            try:
                processed_config.append(RSYNC_OPTS[config_element])
            except KeyError:
                raise KeyError(f"Unknown configuration -> {config_element}")
    return processed_config


@click.group()
@click.option('-c', '--config', type=str, default=os.path.expanduser('~/.backuprc'),
              help='Configuration file')
@click.pass_context
def cli(ctx, config):
    """Command line interface."""
    ctx.ensure_object(dict)
    # Load config and validate ad-hoc
    rsync_config, ctx.obj['profiles'] = load_config(config)
    try:
        ctx.obj['rsync_config'] = process_rsync_config(rsync_config)
    except KeyError as error:
        ctx.exit(1, f"Unknow rsync config key -> {error}")


@cli.command()
@click.option('-n', '--dry-run', is_flag=True, default=False, help='Dry-run?')
@click.argument('profiles_to_backup', nargs=-1, required=True)
@click.pass_context
def backup(ctx, dry_run, profiles_to_backup):
    """Run the backup procedure."""
    rsync_config = ctx.obj['rsync_config']
    profile_config = ctx.obj['profiles']

    def do_backup(profile, rsync_flags):
        """Execute backup."""
        if 'extra-config' in profile:
            try:
                rsync_flags.extend(process_rsync_config(profile['extra-config']))
            except KeyError as error:
                ctx.exit(1, f"Unknow rsync config key -> {error}")
        if dry_run:
            try:
                rsync_flags.pop(rsync_flags.index('--info=progress2'))
            except IndexError:
                pass
            rsync_flags.append('--dry-run')
            rsync_flags.append('-v')
        profile_config = ' '.join(rsync_flags)
        origin = profile['origin']
        if isinstance(origin, list):
            origin = ' '.join(origin)
        dest = profile['dest']
        excludes = ' '.join(f'--exclude "{exclude}"' for exclude in profile.get('excludes', []))
        cmd = f"rsync {origin} {dest} {profile_config} {excludes}"
        print(cmd)
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as error:
            print(error.stdout)
            ctx.exit(error.stderr)
            ctx.exit(1, f"rsync failed")
        if not dry_run and 'post-run-cmd' in profile:
            try:
                subprocess.run(profile['post-run-cmd'], shell=True, check=True)
            except subprocess.CalledProcessError as error:
                print(f"Post-rsync cmd failed")
                print(error.stdout)
                print(error.stderr)
                return False
        return True

    for profile_name in profiles_to_backup:
        print(f"rsync profile {profile_name}")
        try:
            profile = profile_config[profile_name]
        except KeyError:
            ctx.exit(1, f"Unknown profile {profile_name}")
        if not do_backup(profile, rsync_config):
            print(f"rsync for profile {profile_name} unsuccessful")
        else:
            print(f"rsync for profile {profile_name} successful")


@cli.command()
@click.pass_context
def profiles(ctx):
    """List existing profiles."""
    profile_list = ', '.join(ctx.obj['profiles'])
    print(f"Available profiles: {profile_list}")


@cli.command()
@click.argument('profiles_to_describe', nargs=-1, required=False)
@click.pass_context
def describe(ctx, profiles_to_describe):
    """Describe the profiles."""
    profile_defs = ctx.obj['profiles']
    if not profiles_to_describe:
        profiles_to_describe = tuple(profile_defs)
    for profile in profiles_to_describe:
        if profile not in profile_defs:
            print(f"Unknown profile -> {profile}")
        print("{} => {}".format(profile, profile_defs[profile].get('info', '')))


if __name__ == "__main__":
    # pylint: disable=E1123,E1120
    cli(obj={})

# EOF
