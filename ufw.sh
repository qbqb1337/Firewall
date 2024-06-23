#!/bin/sh

# Reset UFW to clear all existing rules
ufw --force reset

# Enable UFW
ufw --force enable

# Define default gateway IPs for IPv4
default_gw_wg0="x.x.x.x"  # Replace with your wg0 IPv4 gateway IP
default_gw_tunplus="y.y.y.y"  # Replace with your tunplus IPv4 gateway IP

# Define default gateway IPs for IPv6
default_gw_wg0_v6="2a0e:1c80:61:x:x"  # Replace with your wg0 IPv6 gateway IP
# default_gw_tunplus_v6="fe80::80cd:f17:63e1:2f9f"  # Replace with your tunplus IPv6 gateway IP

# Add custom routing tables if not already present
if ! grep -q "^100 wg0$" /etc/iproute2/rt_tables; then
  echo "100 wg0" >> /etc/iproute2/rt_tables
fi
if ! grep -q "^200 tunplus$" /etc/iproute2/rt_tables; then
  echo "200 tunplus" >> /etc/iproute2/rt_tables
fi
if ! grep -q "^101 wg0-v6$" /etc/iproute2/rt_tables; then
  echo "101 wg0-v6" >> /etc/iproute2/rt_tables
fi
# if ! grep -q "^201 tunplus-v6$" /etc/iproute2/rt_tables; then
#   echo "201 tunplus-v6" >> /etc/iproute2/rt_tables
# fi

# Add routes to the custom tables
ip route flush table 100
ip route flush table 200
ip route add default via $default_gw_wg0 table 100
ip route add default via $default_gw_tunplus table 200

ip -6 route flush table 101
# ip -6 route flush table 201
ip -6 route add default via $default_gw_wg0_v6 table 101
# ip -6 route add default via $default_gw_tunplus_v6 table 201

# Set FWMARK for random load balancing
ip rule add fwmark 1 table wg0
ip rule add fwmark 2 table tunplus

ip -6 rule add fwmark 1 table wg0-v6
ip -6 rule add fwmark 2 table tunplus-v6

# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# UFW rules

# Set default policies (more secure to DROP by default)
ufw default deny outgoing
ufw default deny incoming
ufw default deny routed

# Allow localhost
ufw allow in on lo
ufw allow out on lo

# Allow communication with any DHCP server
ufw allow out to 255.255.255.255
ufw allow in from 255.255.255.255
ufw allow out to ff02::1:2
ufw allow in from ff02::1:2

# Allow communication within your own network
ufw allow from 192.168.10.0/24 to 192.168.10.0/24
ufw allow from fe80::/10 to fe80::/10

# Allow traffic from 192.168.10.0/24 to 192.168.10.254 (Pi-hole)
ufw allow from 192.168.10.0/24 to 192.168.10.254
ufw allow from fe80::/10 to fe80::/10

# Allow established sessions to receive traffic
ufw allow in on eth0 to any app "OpenSSH"
ufw allow out on eth0 to any app "OpenSSH"

# Allow outgoing traffic to the internet on eth0 (replace with your interface)
ufw allow out on eth0
ufw allow in on eth0 to any port 53

# Allow VPN ports (update ports if needed)
ufw allow out on eth0 proto udp to any port 1194 comment "Allow OpenVPN"
ufw allow out on eth0 proto udp to any port 51820 comment "Allow WireGuard"

# Allow traffic on both wg0 and tunplus interfaces
ufw allow in on wg0-de-ber
ufw allow out on wg0-de-ber
ufw allow in on tun0
ufw allow out on tun0
ufw route allow in on wg0-de-ber
ufw route allow out on wg0-de-ber
ufw route allow in on tun0
ufw route allow out on tun0

# Split DNS: Route specific IP addresses outside VPN
# Define the list of IPs for services like Amazon and Netflix
split_dns_ips=$(curl -s https://github.com/qbqb1337/Firewall/blob/main/vpn_bypass.txt)
for ip in $split_dns_ips; do
  ufw route allow to $ip
done

# Log dropped packets (for debugging) - Consider adjusting log level/limit
ufw logging on
ufw logging low

# Apply all rules
ufw reload

echo "ufw rules applied"
