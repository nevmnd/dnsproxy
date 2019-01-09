dnsproxy
========

DNS proxy server with blacklist test task, based on DNS Proxy from vietor (https://github.com/vietor/dnsproxy)

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
