# backup

Backup script. An rsync wrapper driven by a YAML config (`~/.backuprc` by default, or `-c FILE`).

```sh
backup profiles                 # list profiles
backup backup [-n] PROFILE...   # run (or dry-run) profiles
backup restore [-n] PROFILE...  # restore from the backup
```

## Profile keys

| Key | Meaning |
| --- | --- |
| `origin`, `dest` | Source and destination passed to rsync. |
| `info` | Description shown by `describe`. |
| `excludes`, `includes` | rsync `--exclude` / `--include` patterns. |
| `extra-config` | Extra rsync options (names from the `rsync-config` list or raw flags). |
| `use-nobackupdelete` | Folders of `origin` scanned for `.nobackupdelete` markers. A folder holding the marker is never pruned on the destination. |
| `only` | Allowlist, see below. |
| `skip` | Globs of top-level entries that are deliberately not copied, see below. |
| `pre-run-cmd` | String or list, run before rsync, see below. |
| `post-run-cmd` | String or list, run after rsync. |
| `inherit-from`, `compose` | Reuse another profile, or run several profiles. |

## Allowlist (`only`)

A list of top-level entries of `origin` to copy, for example `Arxiu` or `.claude`.
`origin` is given without a trailing slash, so rsync sees paths as `<origin name>/<entry>/...`.

When `only` is set, the rsync rules are emitted in this order, because rsync uses the first rule that matches:

1. The profile's `excludes`, so `**/.venv` and similar still apply inside allowed folders.
2. The profile's `includes`.
3. An anchored include for the transfer root and for each `only` entry (`/<root>/<entry>/***`).
4. A final `--exclude "*"` for everything else.

`.nobackupdelete` protection keeps working. Profiles without `only` behave as before (includes, then excludes).

### Unlisted directories (`skip`)

When `only` is set, the script logs one warning listing the top-level **directories** of `origin` that match neither `only` nor any `skip` glob (matched against the entry name). Files are ignored. It is a warning, never an error. Use `skip` to record what is left out on purpose, so a new folder stands out.

## Pre-run commands (`pre-run-cmd`)

A string or a list of shell commands, run before rsync and formatted like `post-run-cmd` (`cmd.format(**profile)`, so write literal braces as `{{` and `}}`).
With `--dry-run` the commands are logged and not run.
If one fails, an error is logged and rsync is skipped for that profile (other profiles still run).

## Example

```yaml
profiles:
    user:
        origin: "/Users/me"
        dest: "/Volumes/Backup"
        only: [Arxiu, Documents, .claude]
        skip: [Library, "*.app"]
        excludes: ["**/.venv", "**/.DS_Store"]
        use-nobackupdelete: [Arxiu]
        pre-run-cmd: docker-volumes-export
        extra-config: [delete-from-dest, delete-excluded]
```
