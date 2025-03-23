#!/bin/bash

# Run this script if `fanctl down -e` fails with weird errors
# about table X or chain Y not being available.
# After running this script, you can run `fanctl down -e` again.

host_ip=$(ip route get 1.1.1.1 | awk '{print $7; exit}')
fan_overlay="240.0.0.0/8"
fan_bridge="fan-240"
IFS='.' read -r a b c d <<< "$host_ip"
fan_subnet="240.${c}.${d}.0/8"
fan_gateway="240.${c}.${d}.1/8"

iptables -t nat -N fan-egress
iptables -t nat -A POSTROUTING --source $fan_subnet -j fan-egress
iptables -t nat -A fan-egress -j SNAT --source $fan_subnet --to $host_ip
iptables -t nat -A fan-egress --dest $fan_overlay -j RETURN
iptables -t nat -A fan-egress -o lo0 -j RETURN
ip link add $fan_bridge type bridge
ip addr add $fan_gateway dev $fan_bridge
ip link add ftun0 type vxlan id 655360 dev eth0 dstport 0
ip link set ftun0 up
