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
import logging

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
        rsync_flags = list(rsync_flags)
        if 'extra-config' in profile:
            try:
                rsync_flags.extend(process_rsync_config(profile['extra-config']))
                rsync_flags = list(set(rsync_flags))
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
        logging.info("Executing -> %s", cmd)
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as error:
            logging.error(error.stdout)
            ctx.exit(error.stderr)
            ctx.exit(1, f"rsync failed")
        if not dry_run and 'post-run-cmd' in profile:
            cmds = profile['post-run-cmd']
            if not isinstance(cmds, list):
                cmds = [cmds]
            for cmd in cmds:
                try:
                    cmd_to_run = cmd.format(**profile)
                    logging.info("Running post run command -> %s", cmd_to_run)
                    subprocess.run(cmd_to_run, shell=True, check=True)
                except subprocess.CalledProcessError as error:
                    logging.error("Post-rsync cmd failed")
                    logging.error(error.stdout)
                    logging.error(error.stderr)
                    return False
        return True

    # Handle composed profiles
    profile_list = []
    for profile_name in profiles_to_backup:

        def unfold_profile(profile_name):
            prof_list = []
            try:
                profile = profile_config[profile_name]
            except KeyError:
                ctx.exit(1, f"Unknown profile {profile_name}")
            if 'compose' in profile:
                for comp_profile in profile['compose']:
                    prof_list.extend(unfold_profile(comp_profile))
            else:
                prof_list.append(profile_name)
            return prof_list

        profile_list.extend(unfold_profile(profile_name))

    logging.info("Finished config, running the following profiles -> {}"
          .format(', '.join(profile_list)))
    for profile_name in profile_list:
        logging.info(f"rsync profile {profile_name}")
        try:
            profile_from_config = profile_config[profile_name]
            if 'inherit-from' in profile_from_config:
                profile = profile_config[profile_from_config['inherit-from']].copy()
                profile.update(profile_from_config)
            else:
                profile = profile_from_config
        except KeyError:
            ctx.exit(1, f"Unknown profile {profile_name}")
        if not do_backup(profile, rsync_config):
            logging.error(f"rsync for profile {profile_name} unsuccessful")
        else:
            logging.info(f"rsync for profile {profile_name} successful")


@cli.command()
@click.pass_context
def profiles(ctx):
    """List existing profiles."""
    profile_list = ', '.join([prof for prof in ctx.obj['profiles'] if not prof.startswith('_')])
    logging.info(f"Available profiles: {profile_list}")


@cli.command()
@click.argument('profiles_to_describe', nargs=-1, required=False)
@click.pass_context
def describe(ctx, profiles_to_describe):
    """Describe the profiles."""
    profile_defs = [prof for prof in ctx.obj['profiles'] if not prof.startswith('_')]

    def get_description(profile):
        output = []
        if 'composed' in ctx.obj['profiles'][profile]:
            for sub_profile in ctx.obj['profiles'][profile]['composed']:
                output.extend(get_description(sub_profile))
        else:
            output.append("{} => {}".format(profile, ctx.obj['profiles'][profile].get('info', '')))
        return output

    if not profiles_to_describe:
        profiles_to_describe = tuple(profile_defs)
    for profile in profiles_to_describe:
        if profile not in profile_defs:
            logger.warning(f"Unknown profile -> {profile}")
        description_lines = get_description(profile)
        if len(description_lines) > 1:
            for i in range(len(description_lines)):
                description_lines[i] = " - " + description_lines[i]
            description_lines.insert(0, "{} => Composed profile".format(profile))
        logging.info("\n".join(description_lines))


if __name__ == "__main__":
    import coloredlogs
    coloredlogs.install("INFO")
    # pylint: disable=E1123,E1120
    cli(obj={})

# EOF
