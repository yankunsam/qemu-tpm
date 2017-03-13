#!/bin/bash
apt-get install libsdl-1.2-dev flex bison
git submodule update --init pixman
git submodule update --init dtc
make -j4
make install


