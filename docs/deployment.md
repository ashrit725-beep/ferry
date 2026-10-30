# Deployment guide and production readiness

This guide covers installing Ferry's receiving side on a Linux host inside a
disconnected network, and the connected-side tools on an engineer's machine.
The status table at the end says which of these steps have been exercised.

## 1. Connected side (packer's machine)

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
```

`ferry preflight`, `pack`, `sign`, `verify` and `rehearse` run from here. On
Linux the preflight needs `unshare` and `ip` (util-linux, iproute2) and
benefits from `strace`; on macOS it uses `sandbox-exec`. Signing keys
(`ferry keygen`) belong on this side only; protect them with a passphrase
(`--passphrase-file`) and file permissions, and plan for an HSM later.

## 2. Build the installation media

On a connected machine with the target's Python minor version:

```bash
deploy/offline-install.sh build --out wheelhouse --platform manylinux_2_28_x86_64 --python 3.11
```

This produces the Ferry wheel, every dependency wheel for that platform and a
`SHA256SUMS` file. Add `llama.cpp` for the target (a release archive or a
distro package) and the model bundles. Move everything through the approved
transfer process.

## 3. Install on the receiving host

```bash
sudo useradd --system --home /var/lib/ferry --shell /usr/sbin/nologin ferry
```

```bash
sudo deploy/offline-install.sh install --wheelhouse /media/transfer/wheelhouse --dest /opt/ferry
```

```bash
sudo -u ferry /opt/ferry/bin/ferry --data-dir /var/lib/ferry init
```

`init` writes `/var/lib/ferry/ferry.toml`, the database, and the `inbox`,
`store`, `trust` and `secrets` directories (mode 0700). Review the file:
`required_roles`, `allowed_licenses`, size limits, and `[server]` if the
gateway must listen beyond loopback (then set `tls_cert_file` and
`tls_key_file`; plain HTTP is only acceptable on 127.0.0.1).

Trust anchors are host-only. For each signer, obtain the public key and its
fingerprint through separate channels:

```bash
sudo -u ferry /opt/ferry/bin/ferry --data-dir /var/lib/ferry trust add publisher.pub.pem --name "Vendor build" --role publisher --expect-fingerprint <16+ hex>
```

Create the first console user (the password comes from stdin, never a flag):

```bash
sudo -u ferry /opt/ferry/bin/ferry --data-dir /var/lib/ferry admin create-user admin --role admin --password-stdin
```

## 4. Services

Copy `deploy/systemd/*.service` to `/etc/systemd/system/`, then:

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now ferry
```

After importing a model bundle (`ferry import /var/lib/ferry/inbox/<bundle>` or
the console), start its runtime:

```bash
sudo systemctl enable --now ferry-llamacpp@<model-name>
```

The runtime unit denies all network except loopback at the cgroup level
(`IPAddressDeny=any`, `IPAddressAllow=localhost`) in addition to llama-server's
`--offline`. Both units run as the `ferry` user with a read-only system view
and write access only to `/var/lib/ferry`. On GPU hosts add `DeviceAllow=`
lines for the GPU devices to the runtime unit.

## 5. Reverse proxies and TLS

Prefer terminating TLS in Ferry (`[server] tls_cert_file`, `tls_key_file`).
If a reverse proxy terminates TLS instead, it must preserve the `Host` header
and send `X-Forwarded-Proto`, or the console's CSRF `Origin` check and the
`Secure` cookie logic reject requests. Verify a login through the proxy before
handing the system over.

## 6. Backups and restore

Everything lives in the data directory: `ferry.db` (registry, policies, keys
as hashes, audit chain), `store/` (model files, content-addressed), `trust/`,
`secrets/` (runtime tokens) and `ferry.toml`. To back up without stopping the
service, snapshot the database with SQLite's online backup and copy the rest:

```bash
sudo -u ferry sqlite3 /var/lib/ferry/ferry.db ".backup /var/lib/ferry-backup/ferry.db" && sudo rsync -a --exclude ferry.db /var/lib/ferry/ /var/lib/ferry-backup/
```

Restore by stopping the services, replacing the data directory, and running
`ferry store verify` and `ferry audit verify`. Export signed audit checkpoints
regularly to a location the gateway host cannot write
(`ferry audit checkpoint --sign-key <site key> --out ...`); they are what make
truncation of the audit log detectable.

## 7. Upgrades

Build a new wheelhouse, transfer it, install into a fresh prefix
(`--dest /opt/ferry-<version>`), stop the services, switch the symlink or unit
paths, start them. Database migrations run on start and are idempotent; a
newer schema than the installed Ferry supports is refused rather than
downgraded. Keep the previous prefix until the new one has served traffic.

## 8. Monitoring

`GET /healthz` is unauthenticated and returns only `{"status":"ok"}`. The
console overview shows backend health, route provenance, 24-hour traffic from
the audit log and the audit chain head. `ferry doctor` checks permissions,
trust problems, backend addresses, TLS, proxy variables and the console assets.
Run `ferry audit verify` and `ferry store verify` from a timer.

## 9. Production readiness status (2026-10-29)

| Area | Status | What would change it |
|---|---|---|
| Core workflow (preflight, pack, verify, import, gateway, audit) | Working and tested on macOS; demo passes end to end with a real model | Run the same on a Linux host |
| Linux network isolation | Written, never executed | A Linux host or the CI workflow in `.github/workflows/ci.yml`; hardened hosts may need `bwrap` or a root-created namespace instead of unprivileged `unshare` |
| Offline install path | `deploy/offline-install.sh build` + `install` exercised on macOS into a fresh venv with `--no-index` | Build for `manylinux` and install on the real target OS |
| systemd units | Written, not run | `systemd-analyze verify`, start both units on a test host, confirm hardening does not block the runtime |
| TLS | Supported by configuration, exercised only in tests | Deploy with real certificates |
| Backups and restore | Documented, not rehearsed | Rehearse a restore on a test host |
| CI | Workflow written, never run | Push to GitHub |
| Independent security assessment | None; internal AI-assisted review only | Third-party review before any classified or regulated use |
| Supply chain of Ferry itself | Five direct dependencies, versions recorded in evidence; no signed wheelhouse or reproducible build | Sign `SHA256SUMS` with a release key; pin dependency hashes |
| Customers | None | The pilot in `docs/company/pilot.md` |

Ferry produces evidence that can support controls such as NIST SP 800-53
SI-7(15), CM-14 and SR-4(3); it does not make a system compliant and has not
been assessed or authorized for any classification level.
