# wireguard-dkms

This repository contains the out-of-tree WireGuard kernel module source and
the metadata required to install it through DKMS.

## DKMS install

Install the prerequisites for your distribution first:

```sh
sudo apt update
sudo apt install dkms build-essential linux-headers-$(uname -r)
```

This installs:

- `dkms`
- `build-essential`
- `linux-headers-$(uname -r)`

Then register and build the module from this source tree:

```sh
sudo dkms add .
sudo dkms build wireguard/1.0.0
sudo dkms install wireguard/1.0.0
```

Or do it in one step:

```sh
sudo dkms install .
```

Useful follow-up commands:

```sh
dkms status
modinfo wireguard
sudo modprobe wireguard
```

## Routing Behavior

Current phase:

- Outbound peer selection still uses AllowedIPs, but IPv6 transmit lookup now tries the route's gateway or nexthop first and falls back to the packet destination when no peer matches the routed nexthop.
- Inbound packet processing can now apply an ordered per-peer `allowedroutes` policy after decryption.

This phase is intended to allow routed IPv6 traffic through when the kernel has already resolved a gateway or nexthop that belongs to a peer. If the route was chosen from ECMP or a nexthop group, WireGuard follows the concrete member already selected for that packet instead of trying to reason about the whole group.

## Allowedroutes

`allowedroutes` is a receive-only policy mechanism.

- `allowedips` still controls transmit peer selection.
- `allowedroutes` evaluates decrypted packets against ordered `(source CIDR, destination CIDR, action)` rules on the receiving peer.
- The first matching rule wins.
- Supported actions are `allow` and `deny`.
- If a peer has no configured `allowedroutes`, receive behavior defaults to allow-all.

The new receive policy is additive from a netlink perspective. Existing standard clients that only configure ordinary WireGuard interfaces remain compatible with this module, but they will not configure `allowedroutes` until userspace support is added.

## Planned Allowedroutes Follow-Up

The next phase is to add userspace support for `allowedroutes`.

- `wireguard-tools` needs syntax and netlink marshalling support for ordered rules with source, destination, and action.
- `systemd-networkd` needs parser, netlink, and documentation support for the new peer attribute.
- `netplan` needs schema, parser, renderer, and documentation support for the new rule model.

See [ROUTES.md](ROUTES.md) for the cross-project implementation roadmap.

## Notes

The DKMS package version is derived from [version.h](version.h).
