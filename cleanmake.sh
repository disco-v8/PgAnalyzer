#!/bin/sh

clear
pkill -9 evs_pganalyzer
ps awux | grep evs_pganalyzer

make clean
./configure --prefix=/usr
make

rm -f /var/run/EvServer/.EvServer.sock
rm -f /var/run/EvServer/.EvServer.pid
rm -f /var/log/EvServer/EvServer.log
