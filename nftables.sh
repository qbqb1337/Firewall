#!/bin/sh

# Clear existing nftables rules
nft flush ruleset

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

# Create the nftables rules
nft -f - <<EOF
# Define tables
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ip saddr 192.168.10.0/24 ip daddr 192.168.10.0/24 accept
        ip6 saddr fe80::/10 ip6 daddr fe80::/10 accept
        ip saddr 192.168.10.0/24 ip daddr 192.168.10.254 accept
        ip6 saddr fe80::/10 ip6 daddr fe80::/10 accept
        ct state established,related accept
        ip daddr 255.255.255.255 accept
        ip6 daddr ff02::1:2 accept
        iif "wg0-de-ber" accept
        iif "tun0" accept
        iif "eth0" tcp dport 53 accept
        log prefix "INPUT drop: " limit rate 5/minute
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        iif "wg0-de-ber" accept
        iif "tun0" accept
        oif "wg0-de-ber" accept
        oif "tun0" accept
    }

    chain output {
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ip saddr 192.168.10.0/24 ip daddr 192.168.10.0/24 accept
        ip6 saddr fe80::/10 ip6 daddr fe80::/10 accept
        ip saddr 192.168.10.0/24 ip daddr 192.168.10.254 accept
        ip6 saddr fe80::/10 ip daddr fe80::/10 accept
        ip daddr 255.255.255.255 accept
        ip6 daddr ff02::1:2 accept
        oif "wg0-de-ber" accept
        oif "tun0" accept
        oif "eth0" accept
        udp dport 1194 accept comment "Allow OpenVPN"
        udp dport 51820 accept comment "Allow WireGuard"
        log prefix "OUTPUT drop: " limit rate 5/minute
    }

    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oif "wg0-de-ber" masquerade
        oif "tun0" masquerade
    }

    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
    }

    chain postrouting_mangle {
        type route hook postrouting priority mangle; policy accept;
        meta nfproto ipv4 random 0.5 mark set 0x1
        meta nfproto ipv4 random 0.5 mark set 0x2
        meta nfproto ipv6 random 0.5 mark set 0x1
        meta nfproto ipv6 random 0.5 mark set 0x2
    }

    chain mark_log {
        meta mark 1 log prefix "Marked for wg0: " limit rate 5/minute
        meta mark 2 log prefix "Marked for tunplus: " limit rate 5/minute
    }
}

# Split DNS: Route specific IP addresses outside VPN
split_dns_ips=$(curl -s https://github.com/qbqb1337/Firewall/blob/main/vpn_bypass.txt)
for ip in $split_dns_ips; do
    ip rule add to $ip table main
    ip -6 rule add to $ip table main
done
EOF

echo "nftables rules applied"
