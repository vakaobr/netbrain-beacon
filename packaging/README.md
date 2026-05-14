# Packaging

This directory holds the per-distribution packaging artifacts for the
netbrain-beacon binary.

## Status

| Format            | Status        | Owner             |
|-------------------|---------------|-------------------|
| Tarball + systemd | ✅ Ready      | `tarball/install.sh` + `systemd/netbrain-beacon.service` |
| Docker (distroless) | ✅ Ready    | `../Dockerfile` (Phase 1) |
| deb               | 🟡 Skeleton   | follow-up `add-beacon-deb-packaging` |
| rpm               | 🟡 Skeleton   | follow-up `add-beacon-rpm-packaging` |
| Arch (PKGBUILD)   | 🟡 Skeleton   | follow-up `add-beacon-arch-packaging` |
| Windows MSI (WiX) | 🟡 Skeleton   | follow-up `add-beacon-windows-installer` |

## Build commands (reference)

### Tarball

```bash
mkdir -p dist
cp ../bin/netbrain-beacon-linux-amd64 dist/netbrain-beacon
cp tarball/install.sh systemd/netbrain-beacon.service dist/
tar -C dist -czf netbrain-beacon-linux-amd64.tar.gz .
```

### Docker

```bash
docker build -t netbrain-beacon:$(cat ../VERSION 2>/dev/null || echo dev) ..
```

### deb (skeleton)

Land in `deb/DEBIAN/control` + `deb/postinst` + `deb/prerm`. Build:

```bash
# placeholder — full skeleton in the follow-up issue
dpkg-deb --build deb netbrain-beacon_$(cat ../VERSION)_amd64.deb
```

### rpm (skeleton)

Land in `rpm/netbrain-beacon.spec`. Build via `rpmbuild -ba`.

### Arch PKGBUILD (skeleton)

Land in `arch/PKGBUILD`. Build via `makepkg -si`.

### Windows MSI (skeleton)

Land in `windows/installer.wxs`. Build via WiX `candle` + `light`.

## What each platform needs to wire

Every package format must, at install time:

1. Drop the binary at the platform's standard location (`/usr/local/bin`
   on Linux, `C:\Program Files\netbrain-beacon\` on Windows).
2. Create a service user (`netbrain-beacon` on Linux, `NETWORK SERVICE`
   on Windows).
3. Provision the state directory at `0700` perms owned by the service
   user.
4. Register the service (systemd unit / Windows service / launchd).
5. NOT auto-start the service — enrollment must happen first.

## Runtime prerequisites

The beacon binary is self-contained for telemetry collection but
depends on Cloudflare's `warp-cli` at enrollment time when the
platform's Cloudflare mesh integration is active (bundle v2 carries
WARP credentials). Packagers should:

- **NOT** depend on `cloudflare-warp` at package-install time —
  customers using direct LAN/VPN ingress run the beacon without WARP.
- **DO** call this out in package documentation: "If your bundle is
  marked mesh-enabled, install Cloudflare WARP from
  <https://pkg.cloudflareclient.com/> before running `enroll`."
- The beacon detects a missing `warp-cli` and exits with
  `ErrWARPCLINotFound` — see `docs/runbooks/beacon-operations.md`
  § "Cloudflare WARP mesh prerequisite (bundle v2)".

## Documentation

Operator-facing docs live at `../docs/runbooks/beacon-operations.md`.
