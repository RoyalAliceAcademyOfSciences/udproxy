# udproxy
a simple proxy server for UDP

working with QUIC / VOIP / OICQ or any other udp connection

## Build
- Linux
````shell
cd src
make
````
- Openwrt
````shell
make menuconfig
make
````
- Android
````shell
ndk-build
````

## Usage
- as server side
````shell
./udproxy -p LISTEN_PORT
````
- as client side
````shell
./udproxy -c -a SERVER_IP -p SERVER_PORT -q NFQUEUE_NUMBER -d DNAT_SUBNET/CIDR:PORT-DEST_IP:DEST_PORT
````
- example for client side
````shell
# append NFQUEUE rule to OUTPUT chain, nfqueue number is 53443
iptables -A OUTPUT -p udp -m multiport --dport 53,443 -j NFQUEUE --queue-num 53443
# proxy server ip and port is 12.34.56.78:53443; nfqueue number is 53443; set DNAT, forward 0.0.0.0/0:53 packets to 8.8.8.8:53
./udproxy -c -a 12.34.56.78 -p 53443 -q 53443 -d 0.0.0.0/0:53-8.8.8.8:53
````
