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
- Inbound packet processing temporarily bypasses the current AllowedIPs-based source ownership check after decryption.

This phase is intended to allow routed IPv6 traffic through when the kernel has already resolved a gateway or nexthop that belongs to a peer. If the route was chosen from ECMP or a nexthop group, WireGuard follows the concrete member already selected for that packet instead of trying to reason about the whole group.

## Planned Allowedroutes Follow-Up

The next phase is to add a separate inbound policy concept named `allowedroutes`.

- `allowedips` remains focused on transmit peer selection.
- `allowedroutes` is planned to validate inbound packet flow per peer.
- The intended model is to match both source and destination with their own CIDRs, including broad matches such as `::/0`, so receive-side filtering is separated from send-side routing decisions.

The current receive path will keep the old AllowedIPs verification logic commented in place as the insertion point for that future work.

## Notes

The DKMS package version is derived from [version.h](version.h).
