# simplefirewall

# Overview
A simple firewall aiming to filter network packages, impletemented by hooking netfilter mechanism and loaded by kernel module and ebpf.  You can choose one running mechanism depending on your run kernel version. Reconmmend kernel module for low version, versus ebpf for high kernel version.

# Features
## IP filter
- IP blacklist
- IP whitelist
- CIDR format support
- Single IP address support

## Port filter
- Port blacklist
- Port whitelist
- Port range support, e.g.[4-55]
- Single port support

## Flexible configure
- Runtime configure firewall by writing to file under /proc/net/simplefirwall/
- File names including ip_blacklist, ip_whitelist, port_whitelist, port_blacklist, as the function hinted by the file name.
- Runtime switch to disable firewall by commit "echo 0 > /proc/net/simplefirwall/enable"

## Log
- Realtime filter action is displayed by /proc/net/simplefirewall/log file

# Principle
## Kernel module
### hook location
Firewall filter is hooked in Netfilter **INPUT** chain
IP address is organized under a radix tree, port number is mapped into a bitmap structure.

## Ebpf
todo



