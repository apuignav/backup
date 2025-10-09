#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.8"
# dependencies = [
#   "click",
#   "pyyaml",
#   "coloredlogs"
# ]
# ///
"""Backup directories."""

from __future__ import annotations

import contextlib
import logging
import os
import shlex
import subprocess
from pathlib import Path

import click
import yaml

RSYNC_OPTS = {
    "archive": "-a",
    "compress": "-z",
    "human-readable": "-h",
    "progress": "--info=progress2",
    "delete-excluded": "--delete-excluded",
    "delete-from-dest": "--delete",
}


def load_config(config_file: str | Path) -> tuple[list[str], dict]:
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
    if not Path(config_file).exists():
        raise OSError(f"Cannot find config file {config_file}")
    with Path(config_file).open() as config_:
        config = yaml.safe_load(config_)
    return config["rsync-config"], config["profiles"]


def process_rsync_config(config_list: list[str]) -> list[str]:
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
        if config_element.startswith("-"):
            processed_config.append(config_element)
        else:
            try:
                processed_config.append(RSYNC_OPTS[config_element])
            except KeyError as error:
                raise KeyError(f"Unknown configuration -> {config_element}") from error
    return processed_config


def scan_nobackupdelete_files(
    source_dir: Path,
    dir_to_backup: Path,
    dest_dir: Path | None = None,
    tree_depth: int = 3,
) -> tuple[list, list]:
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
    if not Path(source_dir).is_dir():
        return [], []

    filter_rules = []

    # Remove trailing slashes for consistent path handling
    # source_dir = source_dir.rstrip("/")

    # Helper function to recursively scan directories using scandir
    def scan_recursive(current_dir: Path, base_dir: Path) -> list:
        post_commands = []
        try:
            has_nobackupdelete = False
            subdirs = []

            current_path = Path(current_dir)
            base_path = Path(base_dir)

            # Scan the directory once
            with os.scandir(current_path) as entries:
                for entry in entries:
                    if entry.is_file() and entry.name == ".nobackupdelete":
                        has_nobackupdelete = True
                    elif entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry.path)

            if has_nobackupdelete:
                # Get the relative path from source_dir
                rel_path = current_path.relative_to(base_path)

                # Generate filter rule
                if str(rel_path) == ".":
                    # If .nobackupdelete is in the root directory
                    filter_rules.append("--filter='protect ***'")
                else:
                    # Convert to forward slashes for rsync (pathlib handles this)
                    filter_rel_path = rel_path.as_posix()
                    filter_rules.append(f"--filter='protect {filter_rel_path}/***'")

                # Generate post command for Archive.txt if dest_dir is provided
                if dest_dir and str(rel_path) != ".":
                    # Create command to generate Archive.txt
                    dest_path = (
                        Path(dest_dir) / source_dir.stem / dir_to_backup / rel_path
                    )
                    source_path = base_path / rel_path / "Archive.txt"

                    # Use shlex.quote for proper shell escaping (handles spaces and special chars)
                    escaped_dest_path = shlex.quote(str(dest_path))
                    escaped_source_path = shlex.quote(str(source_path))

                    # Command to generate tree listing and copy back to source
                    cmd = (
                        f"cd {escaped_dest_path} && "
                        f"tree -d -L {tree_depth} -N >| Archive.txt && "
                        f"cp -a Archive.txt {escaped_source_path} && cd -"
                    )

                    post_commands.append(cmd)

            # Recursively scan subdirectories
            for subdir in subdirs:
                post_commands.extend(scan_recursive(subdir, base_path))
        except PermissionError:
            # Skip directories we don't have permission to access
            pass
        except Exception as e:
            # Handle other exceptions that might occur
            print(f"Error scanning {current_path}: {e}")
        return post_commands

    # Start recursive scan
    post_commands = scan_recursive(
        source_dir / dir_to_backup, source_dir / dir_to_backup
    )

    # Include .nobackupdelete files themselves in the rsync
    filter_rules.append("--filter='+ .nobackupdelete'")
    return filter_rules, post_commands


def scan_norestore_files(backup_dir: Path) -> list:
    """Scan for .norestore files and generate exclude rules.

    Directories containing .norestore files (and their subdirectories) will be
    excluded from restore operations.

    Arguments
    ---------
    backup_dir : Path
        Backup directory to scan

    Return
    ------
    list
        List of exclude rules for rsync
    """
    if not backup_dir.is_dir():
        return []

    def scan_recursive(current_dir: Path, base_dir: Path) -> list:
        exclude_rules = []
        try:
            has_norestore = False
            subdirs = []

            current_path = Path(current_dir)
            base_path = Path(base_dir)

            # Scan the directory once
            with os.scandir(current_path) as entries:
                for entry in entries:
                    if entry.is_file() and entry.name == ".norestore":
                        has_norestore = True
                    elif entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry.path)

            if has_norestore:
                # Get the relative path from backup_dir
                rel_path = current_path.relative_to(base_path)

                # Generate exclude rule
                if str(rel_path) == ".":
                    # If .norestore is in the root directory, exclude everything
                    logging.warning(
                        ".norestore found in root backup directory - "
                        "this would exclude all files from restore!"
                    )
                    exclude_rules.append("--exclude='*'")
                else:
                    # Exclude this directory and all its contents
                    filter_rel_path = rel_path.as_posix()
                    exclude_rules.append(f"--exclude='{filter_rel_path}'")

                # Don't scan subdirectories since we're excluding the whole tree
                return []

            # Recursively scan subdirectories only if no .norestore found
            for subdir in subdirs:
                exclude_rules.extend(scan_recursive(subdir, base_path))
        except PermissionError:
            # Skip directories we don't have permission to access
            pass
        except Exception as e:
            # Handle other exceptions that might occur
            logging.warning(f"Error scanning {current_path}: {e}")
        return exclude_rules

    # Start recursive scan
    return scan_recursive(backup_dir, backup_dir)


@click.group()
@click.option(
    "-c",
    "--config",
    type=str,
    default=Path("~/.backuprc").expanduser(),
    help="Configuration file",
)
@click.pass_context
def cli(ctx: click.Context, config: str) -> None:
    """Command line interface."""
    ctx.ensure_object(dict)
    # Load config and validate ad-hoc
    rsync_config, ctx.obj["profiles"] = load_config(config)
    try:
        ctx.obj["rsync_config"] = process_rsync_config(rsync_config)
    except KeyError as error:
        ctx.exit(1, f"Unknow rsync config key -> {error}")


@cli.command()
@click.option("-n", "--dry-run", is_flag=True, default=False, help="Dry-run?")
@click.argument("profiles_to_backup", nargs=-1, required=True)
@click.pass_context
def backup(ctx: click.Context, dry_run: bool, profiles_to_backup: list[str]) -> None:
    """Run the backup procedure."""
    rsync_config = ctx.obj["rsync_config"]
    profile_config = ctx.obj["profiles"]

    def do_backup(profile: str, rsync_flags: list | str) -> bool:
        """Execute backup."""
        rsync_flags = list(rsync_flags)
        if "extra-config" in profile:
            try:
                rsync_flags.extend(process_rsync_config(profile["extra-config"]))
                rsync_flags = list(set(rsync_flags))
            except KeyError as error:
                ctx.exit(1, f"Unknown rsync config key -> {error}")

        # Scan for .nobackupdelete files if enabled in profile
        archive_commands = []
        nobackupdelete_dirs = profile.get("use-nobackupdelete", [])
        origin = profile["origin"]
        if isinstance(origin, list):
            origin = " ".join(origin)
        origin = Path(origin)
        dest = Path(profile["dest"])

        if nobackupdelete_dirs:
            for dir_ in nobackupdelete_dirs:
                tree_depth = profile.get("tree-depth", 3)
                # Get filter rules and post-run commands
                filter_rules, commands = scan_nobackupdelete_files(
                    origin, dir_, dest_dir=dest, tree_depth=tree_depth
                )
                rsync_flags.extend(filter_rules)
                archive_commands.extend(commands)

        if dry_run:
            with contextlib.suppress(IndexError):
                rsync_flags.pop(rsync_flags.index("--info=progress2"))
            rsync_flags.append("--dry-run")
            rsync_flags.append("-v")
        profile_config = " ".join(rsync_flags)
        excludes = " ".join(
            f'--exclude "{exclude}"' for exclude in profile.get("excludes", [])
        )
        cmd = f"rsync {origin} {dest} {profile_config} {excludes}"
        logging.info("Executing -> %s", cmd)
        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as error:
            logging.error(error.stdout)
            ctx.exit(error.stderr)
            ctx.exit(1, "rsync failed")

        # Execute Archive.txt generation commands
        for cmd in archive_commands:
            try:
                logging.info("Running auto-generated Archive.txt command -> %s", cmd)
                if not dry_run:
                    subprocess.run(cmd, shell=True, check=True)
            except subprocess.CalledProcessError as error:
                logging.error("Archive.txt generation failed")
                logging.error(error.stdout)
                logging.error(error.stderr)
                # Continue with other commands even if one fails

        # Execute any explicitly configured post-run commands
        if "post-run-cmd" in profile:
            cmds = profile["post-run-cmd"]
            if not isinstance(cmds, list):
                cmds = [cmds]
            for cmd in cmds:
                try:
                    cmd_to_run = cmd.format(**profile)
                    logging.info("Running post run command -> %s", cmd_to_run)
                    if not dry_run:
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

        def unfold_profile(profile_name: str) -> list[str]:
            prof_list = []
            try:
                profile = profile_config[profile_name]
            except KeyError:
                ctx.exit(1, f"Unknown profile {profile_name}")
            if "compose" in profile:
                for comp_profile in profile["compose"]:
                    prof_list.extend(unfold_profile(comp_profile))
            else:
                prof_list.append(profile_name)
            return prof_list

        profile_list.extend(unfold_profile(profile_name))

    logging.info(
        "Finished config, running the following profiles -> {}".format(
            ", ".join(profile_list)
        )
    )
    for profile_name in profile_list:
        logging.info(f"rsync profile {profile_name}")
        try:
            profile_from_config = profile_config[profile_name]
            if "inherit-from" in profile_from_config:
                profile = profile_config[profile_from_config["inherit-from"]].copy()
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
def profiles(ctx: click.Context) -> None:
    """List existing profiles."""
    profile_list = ", ".join(
        [prof for prof in ctx.obj["profiles"] if not prof.startswith("_")]
    )
    logging.info(f"Available profiles: {profile_list}")


@cli.command()
@click.argument("profiles_to_describe", nargs=-1, required=False)
@click.pass_context
def describe(ctx: click.Context, profiles_to_describe: list[str]) -> None:
    """Describe the profiles."""
    profile_defs = [prof for prof in ctx.obj["profiles"] if not prof.startswith("_")]

    def get_description(profile: str) -> list[str]:
        output = []
        if "composed" in ctx.obj["profiles"][profile]:
            for sub_profile in ctx.obj["profiles"][profile]["composed"]:
                output.extend(get_description(sub_profile))
        else:
            output.append(
                "{} => {}".format(profile, ctx.obj["profiles"][profile].get("info", ""))
            )
        return output

    if not profiles_to_describe:
        profiles_to_describe = tuple(profile_defs)
    for profile in profiles_to_describe:
        if profile not in profile_defs:
            logging.warning(f"Unknown profile -> {profile}")
        description_lines = get_description(profile)
        if len(description_lines) > 1:
            for i in range(len(description_lines)):
                description_lines[i] = " - " + description_lines[i]
            description_lines.insert(0, f"{profile} => Composed profile")
        logging.info("\n".join(description_lines))


@cli.command()
@click.option("-n", "--dry-run", is_flag=True, default=False, help="Dry-run?")
@click.option(
    "--ignore-norestore-flag",
    is_flag=True,
    default=False,
    help="Ignore .norestore markers and restore all backed up data",
)
@click.option(
    "--delete/--no-delete",
    default=False,
    help="Delete files at destination not in backup (DANGEROUS! default: no)",
)
@click.argument("profiles_to_restore", nargs=-1, required=True)
@click.pass_context
def restore(
    ctx: click.Context,
    dry_run: bool,
    ignore_norestore_flag: bool,
    delete: bool,
    profiles_to_restore: list[str],
) -> None:
    """Run the restore procedure.

    CAUTION: This will overwrite files at the original location with backed up versions.
    Use --dry-run first to verify what will be restored.

    Directories in the backup containing .norestore files will be excluded from restore
    unless --ignore-norestore-flag is specified.
    """
    rsync_config = ctx.obj["rsync_config"]
    profile_config = ctx.obj["profiles"]

    def do_restore(profile: str, rsync_flags: str | list[str]) -> None:
        """Execute restore."""
        rsync_flags = list(rsync_flags)

        # Remove delete flags by default for safety
        with contextlib.suppress(ValueError):
            rsync_flags.remove("--delete")
        with contextlib.suppress(ValueError):
            rsync_flags.remove("--delete-excluded")

        if "extra-config" in profile:
            try:
                extra_flags = process_rsync_config(profile["extra-config"])
                # Remove delete flags from extra config unless explicitly requested
                if not delete:
                    extra_flags = [
                        f
                        for f in extra_flags
                        if f not in ["--delete", "--delete-excluded"]
                    ]
                rsync_flags.extend(extra_flags)
                rsync_flags = list(set(rsync_flags))
            except KeyError as error:
                ctx.exit(1, f"Unknown rsync config key -> {error}")

        # Add delete flags if explicitly requested
        if delete:
            if "--delete" not in rsync_flags:
                rsync_flags.append("--delete")
            logging.warning(
                "!!! DELETE mode enabled - files not in backup will be removed !!!"
            )

        # Swap origin and dest for restore
        original_origin = Path(profile["origin"])
        if isinstance(profile["origin"], list):
            original_origin = Path(" ".join(profile["origin"]))

        original_dest = Path(profile["dest"])

        # For restore: source is dest/origin_basename/, destination is origin
        # The trailing slash on source is crucial - it copies contents, not the directory itself
        restore_source = original_dest / original_origin.name
        restore_dest = original_origin

        # Add trailing slash to source to copy contents
        restore_source_str = str(restore_source) + "/"

        # Verify backup source exists
        if not restore_source.exists():
            logging.error(f"Backup source not found: {restore_source}")
            ctx.exit(1, "Cannot restore -> backup directory does not exist")

        # Scan for .norestore files unless flag is set to ignore them
        if not ignore_norestore_flag:
            norestore_excludes = scan_norestore_files(restore_source)
            if norestore_excludes:
                logging.info(
                    f"Found {len(norestore_excludes)} .norestore marker(s) - "
                    "excluding marked directories from restore"
                )
                logging.info(
                    "Use --ignore-norestore-flag to restore all data including marked directories"
                )
                rsync_flags.extend(norestore_excludes)
        else:
            logging.info("Ignoring .norestore markers - restoring all backed up data")

        if dry_run:
            with contextlib.suppress(IndexError):
                rsync_flags.pop(rsync_flags.index("--info=progress2"))
            rsync_flags.append("--dry-run")
            rsync_flags.append("-v")

        profile_config_str = " ".join(rsync_flags)
        excludes = " ".join(
            f'--exclude "{exclude}"' for exclude in profile.get("excludes", [])
        )

        cmd = (
            f"rsync {restore_source_str} {restore_dest} {profile_config_str} {excludes}"
        )

        if dry_run:
            logging.info("DRY RUN - no changes will be made")
        logging.info("Restoring from: %s", restore_source)
        logging.info("Restoring to: %s", restore_dest)
        logging.info("Executing -> %s", cmd)

        try:
            subprocess.run(cmd, shell=True, check=True)
        except subprocess.CalledProcessError as error:
            logging.error(error.stdout)
            ctx.exit(error.stderr)
            ctx.exit(1, "rsync restore failed")

    # Handle composed profiles (same logic as backup)
    profile_list = []
    for profile_name in profiles_to_restore:

        def unfold_profile(profile_name: str) -> list:
            prof_list = []
            try:
                profile = profile_config[profile_name]
            except KeyError:
                ctx.exit(1, f"Unknown profile {profile_name}")
            if "compose" in profile:
                for comp_profile in profile["compose"]:
                    prof_list.extend(unfold_profile(comp_profile))
            else:
                prof_list.append(profile_name)
            return prof_list

        profile_list.extend(unfold_profile(profile_name))

    logging.info(
        "Finished config, running restore for the following profiles -> {}".format(
            ", ".join(profile_list)
        )
    )

    for profile_name in profile_list:
        logging.info(f"Restoring profile {profile_name}")
        try:
            profile_from_config = profile_config[profile_name]
            if "inherit-from" in profile_from_config:
                profile = profile_config[profile_from_config["inherit-from"]].copy()
                profile.update(profile_from_config)
            else:
                profile = profile_from_config
        except KeyError:
            ctx.exit(1, f"Unknown profile {profile_name}")

        if not do_restore(profile, rsync_config):
            logging.error(f"Restore for profile {profile_name} unsuccessful")
        else:
            logging.info(f"Restore for profile {profile_name} successful")


if __name__ == "__main__":
    import coloredlogs

    coloredlogs.install("INFO")
    # pylint: disable=E1123,E1120
    cli(obj={})

# EOF
