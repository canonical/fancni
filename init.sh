#!/bin/bash

host_ip=$(ip route get 1.1.1.1 | awk '{print $7; exit}')
fan_bridge="fan-240"
IFS='.' read -r a b c d <<< "$host_ip"
pod_network="240.${c}.${d}.0/24"

# Allow pod to pod communication
iptables -A FORWARD -s $pod_network -j ACCEPT
iptables -A FORWARD -d $pod_network -j ACCEPT

# Allow communication across hosts
# Need to be updated with the IP of other hosts
ip route add 240.72.117.0/24 via 10.97.72.117 dev eth0

# Allow outgoing internet 
iptables -t nat -A POSTROUTING -s $pod_network ! -o $fan_bridge -j MASQUERADE
