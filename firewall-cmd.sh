#!/bin/sh

# Ensure the firewalld service is running
systemctl start firewalld

# Clear all existing zones, services, and direct rules
firewall-cmd --reload
firewall-cmd --complete-reload

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

# Randomly mark outgoing packets for load balancing
iptables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 1
iptables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 2
ip6tables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 1
ip6tables -t mangle -A POSTROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 2

# Ensure the firewalld service is running
systemctl start firewalld

# Clear all existing zones, services, and direct rules
firewall-cmd --reload
firewall-cmd --complete-reload

# Define interfaces (replace eth0 with your actual interface)
external_iface="eth0"
wg0_iface="wg0-de-ber"
tun0_iface="tun0"

# Add interfaces to the appropriate zones
firewall-cmd --permanent --zone=external --add-interface=${external_iface}
firewall-cmd --permanent --zone=trusted --add-interface=${wg0_iface}
firewall-cmd --permanent --zone=trusted --add-interface=${tun0_iface}

# Enable IP forwarding
firewall-cmd --permanent --add-masquerade

# Allow VPN ports (update ports if needed)
firewall-cmd --permanent --zone=trusted --add-port=1194/udp
firewall-cmd --permanent --zone=trusted --add-port=51820/udp

# Allow traffic on wg0 and tunplus interfaces
firewall-cmd --permanent --zone=trusted --add-interface=${wg0_iface}
firewall-cmd --permanent --zone=trusted --add-interface=${tun0_iface}

# Set default drop policies (more secure to DROP by default)
firewall-cmd --permanent --zone=drop --set-target=DROP
firewall-cmd --permanent --zone=drop --add-interface=${external_iface}

# Allow localhost
firewall-cmd --permanent --zone=trusted --add-source=127.0.0.1
firewall-cmd --permanent --zone=trusted --add-source=::1

# Allow communication with any DHCP server
firewall-cmd --permanent --zone=trusted --add-service=dhcp

# Allow communication within your own network
firewall-cmd --permanent --zone=trusted --add-source=192.168.10.0/24
firewall-cmd --permanent --zone=trusted --add-source=fe80::/10

# Allow traffic from 192.168.10.0/24 to 192.168.10.254 (Pi-hole)
firewall-cmd --permanent --zone=trusted --add-rich-rule="rule family=ipv4 source address=192.168.10.0/24 destination address=192.168.10.254 accept"
firewall-cmd --permanent --zone=trusted --add-rich-rule="rule family=ipv6 source address=fe80::/10 destination address=fe80::/10 accept"

# Allow established sessions to receive traffic
firewall-cmd --permanent --zone=trusted --add-rich-rule="rule family=ipv4 connection state=related,established accept"
firewall-cmd --permanent --zone=trusted --add-rich-rule="rule family=ipv6 connection state=related,established accept"

# Allow outgoing traffic to the internet on eth0 (replace with your interface)
firewall-cmd --permanent --zone=external --add-interface=${external_iface}
firewall-cmd --permanent --zone=trusted --add-interface=${external_iface}
firewall-cmd --permanent --zone=trusted --add-rich-rule="rule family=ipv4 destination address=2a01:586:83da:1::/64 protocol=udp port=53 accept"

# Allow VPN ports (update ports if needed)
firewall-cmd --permanent --zone=trusted --add-port=1194/udp
firewall-cmd --permanent --zone=trusted --add-port=51820/udp

# Split DNS: Route specific IP addresses outside VPN
# Define the list of IPs for services like Amazon and Netflix
split_dns_ips=$(curl -s https://github.com/qbqb1337/Firewall/blob/main/vpn_bypass.txt)
for ip in $split_dns_ips; do
  firewall-cmd --permanent --zone=trusted --add-rich-rule="rule family=ipv4 destination address=${ip} accept"
done

# Log dropped packets (for debugging) - Consider adjusting log level/limit
firewall-cmd --permanent --zone=drop --add-log

# Apply all rules
firewall-cmd --reload

echo "firewalld rules applied"
