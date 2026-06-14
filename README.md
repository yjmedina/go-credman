# credman

A small command-line credential manager. Credentials live in a single
password-locked vault stored locally as a SQLite database. Every read or
write prompts for the master password.

## Install

Requires Go 1.26+.

```sh
./install.sh                  # build and install to /usr/local/bin
sudo ./install.sh             # if /usr/local/bin needs elevation
./install.sh --uninstall      # remove the binary (leaves ~/.credman intact)
```

The build is pure Go (no CGO required).

## Getting started

Initialize the vault once. This creates `~/.credman/` (mode 0700) and sets
your master password.

```sh
credman init
```

From there:

```sh
credman add <name>            # add a credential (see flags below)
credman get <name>            # show a credential (secrets masked by default)
credman search -p <pattern>   # list credential names matching a pattern
credman delete <name>         # remove a credential
```

Every command prompts for the master password.

## Adding credentials

A credential is a named bag of fields. Fields come in two flavors:

- `-v key=value` — plain field, value given on the command line.
- `-s key`       — sensitive field, value prompted for and stored as a secret.

Both flags are repeatable. Field names within one credential must be unique.

```sh
credman add github \
  -v user=alice \
  -v url=https://github.com \
  -s password

credman add api -v owner=team -s token -s backup_token
```

## Reading credentials

```sh
credman get github            # sensitive fields shown as ***********
credman get github -s         # reveal sensitive fields
```

## Searching

```sh
credman search -p dev         # names containing "dev"
credman search                # all names (empty pattern)
```

## Deleting

```sh
credman delete github
```

## Data location

| Path                   | What it is                          |
|------------------------|-------------------------------------|
| `~/.credman/`          | Vault directory (created at 0700)   |
| `~/.credman/.credman.db` | SQLite database                   |

To fully wipe credman, remove the binary and delete `~/.credman/`.

## Project layout

- `main.go` — entry point.
- `cmd/` — Cobra commands (`init`, `add`, `get`, `search`, `delete`).
- `internal/vault/` — vault manager, encryption, persistence.
- `install.sh` — build + install + uninstall helper.
