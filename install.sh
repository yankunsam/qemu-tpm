#!/bin/bash
#apt-get install libsdl-1.2-dev flex bison
apt-get install  flex bison
git submodule update --init pixman
git submodule update --init dtc
./configure --enable-kvm --enable-tpm  --enable-sdl
make -j4
make install


