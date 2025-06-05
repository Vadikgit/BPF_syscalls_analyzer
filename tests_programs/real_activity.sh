#!/bin/bash
#PATH_TO_REP="https://github.com/strace/strace.git"
#REP_NAME="strace"
PATH_TO_REP="https://github.com/libbpf/libbpf.git"
REP_NAME="libbpf"

git clone --quiet $PATH_TO_REP
#git clone $PATH_TO_REP
cd libbpf/src
make > /dev/null
#make
cd ../..
rm -r $REP_NAME

