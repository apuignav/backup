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

def scan_nobackupdelete_files(source_dir, dest_dir=None, tree_depth=3):
    """Scan for .nobackupdelete files and generate both filter rules and post commands.
    
    Arguments
    ---------
    source_dir : str
        Source directory to scan
    dest_dir : str, optional
        Destination directory for Archive.txt commands
    tree_depth : int, optional
        Depth for tree command
        
    Return
    ------
    tuple
        (filter_rules, post_commands)
    """
    if not os.path.isdir(source_dir):
        return [], []
    
    filter_rules = []
    post_commands = []
    
    # Remove trailing slashes for consistent path handling
    source_dir = source_dir.rstrip('/')
    
    # Helper function to recursively scan directories using scandir
    def scan_recursive(current_dir, base_dir):
        try:
            has_nobackupdelete = False
            subdirs = []
            
            # Scan the directory once
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    if entry.is_file() and entry.name == '.nobackupdelete':
                        has_nobackupdelete = True
                    elif entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry.path)
            
            if has_nobackupdelete:
                # Get the relative path from source_dir
                rel_path = os.path.relpath(current_dir, base_dir)
                
                # Generate filter rule
                if rel_path == '.':
                    # If .nobackupdelete is in the root directory
                    filter_rules.append("--filter='protect ***'")
                else:
                    # Convert backslashes to forward slashes for rsync
                    filter_rel_path = rel_path.replace('\\', '/')
                    filter_rules.append(f"--filter='protect {filter_rel_path}/***'")
                
                # Generate post command for Archive.txt if dest_dir is provided
                if dest_dir and rel_path != '.':
                    # Create command to generate Archive.txt
                    dest_path = os.path.join(dest_dir, rel_path)
                    # Escape spaces in paths
                    escaped_dest_path = dest_path.replace(' ', '\\ ')
                    escaped_rel_path = rel_path.replace(' ', '\\ ')
                    escaped_source_path = os.path.join(base_dir, escaped_rel_path)
                    
                    # Command to generate tree listing and copy back to source
                    cmd = (f"cd {escaped_dest_path} && "
                           f"tree -d -L {tree_depth} -N >| Archive.txt && "
                           f"cp -a Archive.txt {escaped_source_path}/Archive.txt && cd -")
                    
                    post_commands.append(cmd)
            
            # Recursively scan subdirectories
            for subdir in subdirs:
                scan_recursive(subdir, base_dir)
        except PermissionError:
            # Skip directories we don't have permission to access
            pass
        except Exception as e:
            # Handle other exceptions that might occur
            print(f"Error scanning {current_dir}: {e}")
    
    # Start recursive scan
    scan_recursive(source_dir, source_dir)
    
    # Include .nobackupdelete files themselves in the rsync
    filter_rules.append("--filter='+ .nobackupdelete'")
    return filter_rules, post_commands


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
                ctx.exit(1, f"Unknown rsync config key -> {error}")

        # Scan for .nobackupdelete files if enabled in profile
        archive_commands = []
        nobackupdelete_dirs = profile.get('use-nobackupdelete', [])

        if nobackupdelete_dirs:
            for dir_ in nobackupdelete_dirs:
                origin = profile['origin']
                dest = profile['dest'] 
                tree_depth = profile.get('tree-depth', 3)
                # Get filter rules and post-run commands
                filter_rules, commands = scan_nobackupdelete_files(
                    origin + dir_,
                    dest + dir_ if not dry_run else None,
                    tree_depth
                )
                rsync_flags.extend(filter_rules)
                archive_commands.extend(commands)

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

        # Execute Archive.txt generation commands
        if not dry_run:
            for cmd in archive_commands:
                try:
                    logging.info("Running auto-generated Archive.txt command -> %s", cmd)
                    subprocess.run(cmd, shell=True, check=True)
                except subprocess.CalledProcessError as error:
                    logging.error("Archive.txt generation failed")
                    logging.error(error.stdout)
                    logging.error(error.stderr)
                    # Continue with other commands even if one fails
        
        # Execute any explicitly configured post-run commands
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
