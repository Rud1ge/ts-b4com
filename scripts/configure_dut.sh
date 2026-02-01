#!/bin/sh
set -e

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.fib_multipath_hash_policy=0

ip route replace 172.16.0.254/32 nexthop via 10.0.1.3 weight 1 nexthop via 10.0.2.3 weight 1 nexthop via 10.0.3.3 weight 1 nexthop via 10.0.4.3 weight 1