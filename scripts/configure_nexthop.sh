#!/bin/sh
set -e

ip link add name lo1 type dummy
ip addr add 172.16.0.254/32 dev lo1
ip link set lo1 up
