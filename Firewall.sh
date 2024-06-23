#!/bin/sh

# Ensure iptables and ip6tables chains are clear and counters are reset
iptables -t nat -F
iptables -t mangle -F
iptables -F
iptables -X
ip6tables -t nat -F
ip6tables -t mangle -F
ip6tables -F
ip6tables -X

# Define default gateway IPs for IPv4
default_gw_wg0="x.x.x.x  # Replace with your wg0 IPv4 gateway IP
default_gw_tunplus="y.y.y.y"    # Replace with your tunplus IPv4 gateway IP

# Define default gateway IPs for IPv6
default_gw_wg0_v6="2a0e:1c80:61:x:x"  # Replace with your wg0 IPv6 gateway IP
#default_gw_tunplus_v6="fe80::80cd:f17:63e1:2f9f"      # Replace with your tunplus IPv6 gateway IP

# Add custom routing tables if not already present
if ! grep -q "^100 wg0$" /etc/iproute2/rt_tables; then
  echo "100 wg0" >> /etc/iproute2/rt_tables
fi
if ! grep -q "^200 tunplus$" /etc/iproute2/rt_tables; then
  echo "200 tunplus" >> /etc/iproute2/rt_tables
fi

# Add custom routing tables for IPv6 if not already present
if ! grep -q "^101 wg0-v6$" /etc/iproute2/rt_tables; then
  echo "101 wg0-v6" >> /etc/iproute2/rt_tables
fi
#if ! grep -q "^201 tunplus-v6$" /etc/iproute2/rt_tables; then
#  echo "201 tunplus-v6" >> /etc/iproute2/rt_tables
#fi

# Add routes to the custom tables
ip route flush table 100
ip route flush table 200
ip route add default via $default_gw_wg0 table 100
ip route add default via $default_gw_tunplus table 200

ip -6 route flush table 101
ip -6 route flush table 201
ip -6 route add default via $default_gw_wg0_v6 table 101
#ip -6 route add default via $default_gw_tunplus_v6 table 201

# Set FWMARK for random load balancing
ip rule add fwmark 1 table wg0
ip rule add fwmark 2 table tunplus

ip -6 rule add fwmark 1 table wg0-v6
ip -6 rule add fwmark 2 table tunplus-v6

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# Randomly mark outgoing packets for load balancing
iptables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 1
iptables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 2
ip6tables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 1
ip6tables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 2

# Default policies (more secure to DROP by default)
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP

# Allow localhost
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

# Allow communication with any DHCP server
iptables -A OUTPUT -d 255.255.255.255 -j ACCEPT
iptables -A INPUT -s 255.255.255.255 -j ACCEPT
ip6tables -A OUTPUT -d ff02::1:2 -j ACCEPT
ip6tables -A INPUT -s ff02::1:2 -j ACCEPT

# Allow communication within your own network
iptables -A INPUT -s 192.168.10.0/24 -d 192.168.10.0/24 -j ACCEPT
iptables -A OUTPUT -s 192.168.10.0/24 -d 192.168.10.0/24 -j ACCEPT
ip6tables -A INPUT -s fe80::/10 -d fe80::/10 -j ACCEPT
ip6tables -A OUTPUT -s fe80::/10 -d fe80::/10 -j ACCEPT

# Allow traffic from 192.168.10.0/24 to 192.168.10.254 (Pi-hole)
iptables -A INPUT -s 192.168.10.0/24 -d 192.168.10.254 -j ACCEPT
iptables -A OUTPUT -s 192.168.10.0/24 -d 192.168.10.254 -j ACCEPT
ip6tables -A INPUT -s fe80::/10 -d fe80::/10 -j ACCEPT
ip6tables -A OUTPUT -s fe80::/10 -d fe80::/10 -j ACCEPT

# Allow established sessions to receive traffic
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow outgoing traffic to the internet on eth0 (replace with your interface)
# Ensure you replace 'eth0' with your actual internet-facing interface
iptables -A OUTPUT -o eth0 -j ACCEPT
iptables -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -o eth0 -j ACCEPT
ip6tables -A INPUT -i eth0 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DNS queries to your DNS server (replace with Pi-hole IPv6 address)
# Replace 'fe80::dbbf:xxx:xxx:xxx' with the actual Pi-hole IPv6 address
ip6tables -A OUTPUT -p udp --dport 53 -d 2a01:586:83da:1:xxxx:xxxx:xxxx:xxxx -j ACCEPT
ip6tables -A INPUT -p udp --sport 53 -s 2a01:586:83da:1:xxxx:xxxx:xxxx:xxxx -j ACCEPT

# Allow traffic on both wg0 and tunplus interfaces
iptables -A INPUT -i wg0-de-ber -j ACCEPT
iptables -A INPUT -i tun0 -j ACCEPT
iptables -A FORWARD -i wg0-de-ber -j ACCEPT
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -o wg0-de-ber -j ACCEPT
iptables -A FORWARD -o tun0 -j ACCEPT
iptables -t nat -A POSTROUTING -o wg0-de-ber -j MASQUERADE
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
iptables -A OUTPUT -o wg0-de-ber -j ACCEPT
iptables -A OUTPUT -o tun0 -j ACCEPT

ip6tables -A INPUT -i wg0-de-ber -j ACCEPT
ip6tables -A INPUT -i tun0 -j ACCEPT
ip6tables -A FORWARD -i wg0-de-ber -j ACCEPT
ip6tables -A FORWARD -i tun0 -j ACCEPT
ip6tables -A FORWARD -o wg0-de-ber -j ACCEPT
ip6tables -A FORWARD -o tun0 -j ACCEPT
ip6tables -t nat -A POSTROUTING -o wg0-de-ber -j MASQUERADE
ip6tables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
ip6tables -A OUTPUT -o wg0-de-ber -j ACCEPT
ip6tables -A OUTPUT -o tun0 -j ACCEPT

# Allow VPN ports (update ports if needed)
iptables -I OUTPUT 1 -p udp --dport 1194 -m comment --comment "Allow OpenVPN" -j ACCEPT
iptables -I OUTPUT 2 -p udp --dport 51820 -m comment --comment "Allow WireGuard" -j ACCEPT
ip6tables -I OUTPUT 1 -p udp --dport 1194 -m comment --comment "Allow OpenVPN" -j ACCEPT
ip6tables -I OUTPUT 2 -p udp --dport 51820 -m comment --comment "Allow WireGuard" -j ACCEPT

# Split DNS: Route specific IP addresses outside VPN
# Define the list of IPs for services like Amazon and Netflix
split_dns_ips=$(curl -s https://lou.h4ck.me/vpn_bypass.txt)

for ip in $split_dns_ips; do
  ip rule add to $ip table main
  ip6 rule add to $ip table main
done

# Log dropped packets (for debugging) - Consider adjusting log level/limit
iptables -N logging
iptables -A INPUT -j logging
iptables -A OUTPUT -j logging
iptables -A logging -m limit --limit 5/minute -j LOG --log-prefix "IPTables general: " --log-level 4

ip6tables -N logging
ip6tables -A INPUT -j logging
ip6tables -A OUTPUT -j logging
ip6tables -A logging -m limit --limit 5/minute -j LOG --log-prefix "IP6Tables general: " --log-level 4

# Debugging: Create MARK_LOG chain and log marks
iptables -t mangle -N MARK_LOG
iptables -t mangle -A MARK_LOG -m mark --mark 1 -j LOG --log-prefix "Marked for wg0: " --log-level 4
iptables -t mangle -A MARK_LOG -m mark --mark 2 -j LOG --log-prefix "Marked for tunplus: " --log-level 4

ip6tables -t mangle -N MARK_LOG
ip6tables -t mangle -A MARK_LOG -m mark --mark 1 -j LOG --log-prefix "Marked for wg0: " --log-level 4
ip6tables -t mangle -A MARK_LOG -m mark --mark 2 -j LOG --log-prefix "Marked for tunplus: " --log-level 4

# Apply MARK_LOG chain to POSTROUTING
iptables -t mangle -A POSTROUTING -j MARK_LOG
ip6tables -t mangle -A POSTROUTING -j MARK_LOG

echo "iptables and ip6tables rules applied"
