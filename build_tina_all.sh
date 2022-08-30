#!/bin/bash

# git pull
source ./build/envsetup.sh
lunch 44
make clean
make
pack
