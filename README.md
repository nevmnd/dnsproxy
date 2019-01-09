dnsproxy
========

DNS proxy server with blacklist test task, based on dnsproxy from vietor (https://github.com/vietor/dnsproxy).

## Requirements

Requires libconfig to be installed in system.
```
$ sudo apt-get install libconfig-dev
```
## Build & Run

```bash
$ git clone https://github.com/nevmnd/dnsproxy.git
$ cd dnsproxy
$ git branch --set-upstream-to=origin/temporary
$ git pull
$ git submodule init
$ git submodule update
$ ./build.sh
$ cd build
$ ./dns_proxy
```
## Usage

DNS Proxy requires config file to work. Just copy proxy.cfg to directory of the executable and run.

```
$ cp proxy.cfg build/proxy.cfg
$ cd build
$ ./dns_proxy
```
You can check its work using dig:
```
$ dig -p 5300 google.ru
```
but be sure to turn off your local DNS server before that.

## Proxy configuration

Section "DNS" contains options of upstream DNS server (IP and port) and IP of server where proxy should redirect queries. If that address not specified, proxy will answer with empty response.
Section "Proxy" contains address of local port which it should be run on to.
List of domains which proxy should block are defined in section "Blacklist".
