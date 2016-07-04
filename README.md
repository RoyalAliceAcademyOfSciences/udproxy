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
./udproxy -c -a SERVER_IP -p SERVER_PORT -q NFQUEUE_NUMBER
````
