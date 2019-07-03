#!/usr/bin/python
"""Backup directories."""

import shutil
import sys
import os

import argparse

import subprocess

import yaml


# require Python interpreter > v.3.5
assert sys.version_info >= (3, 5)


def load_config(config_file):
    """Load config file.

    Arguments:
        config_file (str): File to open.

    Return:
        tuple: rsync config and configured profiles.

    Raise:
        KeyError: If parts of the configuration are missing.

    """
    with open(config_file, 'r') as config_:
        config = yaml.safe_load(config_)
    return config['rsync-config'], config['profiles']


def do_backup(config, rsync_config, dry_run):
    """Run the backup procedure.

    Arguments:
        config (dict): Backup configuration.
        rsync_config (list): General rsync configuration.
        dry_run (bool): Perform a dry run?

    Return:
        bool

    """
    rsync_config_str = ' '.join(rsync_config)
    if 'extra-config' in config:
        rsync_config_str += ' '
        rsync_config_str += ' '.join(config['extra-config'])
    if dry_run:
        rsync_config_str += ' --dry-run'
    origin = config['origin']
    if isinstance(origin, list):
        origin = ' '.join(origin)
    dest = config['dest']
    excludes = ' '.join(f'--exclude "{exclude}"' for exclude in config.get('excludes', []))
    cmd = f"rsync {origin} {dest} {rsync_config_str} {excludes}"
    print(cmd)
    try:
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as error:
        print(error.stdout)
        print(error.stderr)
        parser.exit(1, f"rsync failed")
    if not dry_run and 'post-run-cmd' in config:
        try:
            subprocess.run(config['post-run-cmd'], shell=True, check=True)
        except subprocess.CalledProcessError as error:
            print(f"Post-rsync cmd failed")
            print(error.stdout)
            print(error.stderr)
            return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', action='store', type=str, default=os.path.expanduser('~/.backuprc'),
                        help='Configuration file')
    parser.add_argument('-n', '--dry-run', action='store_true', help='Dry-run?')
    parser.add_argument('profiles', action='store', type=str, nargs='+',
                        help="Backup profile to run")
    # Check if rsync is available
    if not shutil.which('rsync'):
        parser.exit(1, "rsync executable not found in PATH")
    args = parser.parse_args()
    # Load config
    rsync_config_dict, profiles = load_config(args.config)
    for profile_name in args.profiles:
        print(f"rsync profile {profile_name}")
        try:
            profile = profiles[profile_name]
        except KeyError:
            parser.exit(1, f"Unknown profile {profile_name}")
        if not do_backup(profile, rsync_config_dict, args.dry_run):
            print(f"rsync for profile {profile_name} unsuccessful")
        else:
            print(f"rsync for profile {profile_name} successful")

# EOF
