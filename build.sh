#!/bin/bash
cd build
cmake -H. -Bbuild -DCMAKE_BUILD_TYPE=Release
cmake --build build --target dns_proxy
cmake --build build --target package