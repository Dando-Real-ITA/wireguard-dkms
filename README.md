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

## Notes

The DKMS package version is derived from [version.h](version.h).
