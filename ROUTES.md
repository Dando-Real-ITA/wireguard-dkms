# Allowedroutes Follow-Up Roadmap

This document is the starting point for userspace and cross-project work that follows the kernel-side `allowedroutes` implementation in this repository.

## Scope

The kernel module now has a receive-only `allowedroutes` policy model distinct from `allowedips`.

- `allowedips` remains the transmit peer-selection mechanism.
- `allowedroutes` evaluates decrypted packets against ordered `(source CIDR, destination CIDR, action)` rules.
- The first matching rule wins.
- Supported actions are `allow` and `deny`.
- If a peer has no configured `allowedroutes`, the kernel defaults to allow-all.

## Why This Is Not Just nftables

`nftables` can filter on the decrypted packet addresses and on the WireGuard interface, but it does not inherently know which WireGuard peer produced a packet on a shared interface.

That means `nftables` can implement global policy for `wg0`, but it cannot cleanly express per-peer source/destination policy without extra metadata exported by the WireGuard receive path. `allowedroutes` keeps that policy attached to peer identity inside the module.

## Netlink Spec Source

The generated files in this repository reference the upstream WireGuard netlink spec:

- `https://git.zx2c4.com/wireguard-linux/tree/Documentation/netlink/specs/wireguard.yaml`

If this repository does not carry a local copy of that YAML, fetch or mirror it before regenerating the generated netlink files.

## wireguard-tools

Source to obtain:

- WireGuard tools source tree from the upstream `wireguard-tools` repository.

Expected work areas:

- Add userspace syntax for ordered `allowedroutes` rules with source CIDR, destination CIDR, and action.
- Preserve the existing `AllowedIPs` syntax and behavior.
- Extend netlink marshalling so `wg` can send and receive the new nested peer attribute and nested allowedroute records.
- Make sure rule order is preserved exactly as configured.
- Decide on configuration syntax that makes ordering explicit and does not overload `AllowedIPs`.

Questions to resolve there:

- Command-line and config-file syntax for `allow` versus `deny`.
- Replace semantics versus incremental update semantics.
- Output formatting for `wg showconf` or equivalent tools so rule order remains stable.

## systemd-networkd

Source to obtain:

- systemd source tree.

Likely files and components:

- `src/network/netdev/wireguard.c`
- `src/network/netdev/wireguard.h`
- `src/network/netdev/netdev-gperf.gperf`
- `src/libsystemd/sd-netlink/netlink-types-genl.c`
- `man/systemd.netdev.xml`

Expected work areas:

- Add a new peer setting such as `AllowedRoutes=` without changing `AllowedIPs=`.
- Parse ordered rules with source, destination, and action.
- Marshal the new nested netlink peer attribute and preserve rule order.
- Document that the feature is receive-only and additive.

## netplan

Source to obtain:

- netplan source tree.

Likely files and components:

- `src/types-internal.h`
- `src/types.c`
- `src/parse.c`
- `src/networkd.c`
- `src/nm.c`
- `doc/netplan-yaml.md`

Expected work areas:

- Add a new structured `allowed-routes` schema instead of extending `allowed-ips`.
- Represent ordered rules with `source`, `destination`, and `action`.
- Render them for the networkd backend.
- Decide whether NetworkManager support is implemented immediately or deferred.

## Compatibility Goals

- New module with older standard clients must keep working for ordinary WireGuard interface configuration.
- `allowedroutes` is optional and additive.
- Older clients that never send the new attributes should continue to function unchanged.
- Newer clients talking to older kernels or older modules will need feature detection or clear fallback behavior.

## Suggested Order Of Work

1. Keep the kernel UAPI and generated netlink definitions stable.
2. Update `wireguard-tools` first so there is a reference userspace implementation for ordered rules.
3. Update systemd-networkd next so native systemd deployments can configure the new feature.
4. Update netplan after that so YAML-based system configuration can expose the same rule model.
5. Add integration tests in each userspace project to confirm rule ordering is preserved and the new action enum is encoded correctly.