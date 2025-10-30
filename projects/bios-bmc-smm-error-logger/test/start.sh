#!/usr/bin/env bash

export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --fork --config-file=/usr/share/dbus-1/session.conf --print-address`

exec bash