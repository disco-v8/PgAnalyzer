#!/bin/sh

mkdir -p /var/log/EvServer/
mkdir -p /var/run/EvServer/
pkill -9 evs_pganalyzer
rm -f /var/run/EvServer/.EvServer.sock
rm -f /var/run/EvServer/.EvServer.pid
rm -f /var/log/EvServer/EvServer.log

./evs_pganalyzer ./evserver.ini
ps awux | grep evs_pganalyzer
tail -F /var/log/EvServer/EvServer.log
