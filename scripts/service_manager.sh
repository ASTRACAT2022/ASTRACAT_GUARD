#!/bin/bash
#
# ASTRACAT_GUARD service management script
# Place in /etc/init.d/ or use with systemd

### BEGIN INIT INFO
# Provides:          astracat-guard
# Required-Start:    $local_fs $network $named $time $syslog
# Required-Stop:     $local_fs $network $named $time $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       ASTRACAT_GUARD DDoS Protection Service
### END INIT INFO

SCRIPT="astracat-guard-daemon"
RUNAS=root
PIDFILE=/var/run/astracat-guard.pid
LOGFILE=/var/log/astracat-guard.log

start() {
  if [ -f "$PIDFILE" ] && kill -0 $(cat "$PIDFILE"); then
    echo 'Service already running' >&2
    return 1
  fi
  echo 'Starting astracat-guard service...' >&2
  local CMD="python3 /opt/astracat_guard/lib/optimized_guard_daemon.py"
  su -c "$CMD" $RUNAS > $LOGFILE 2>&1 &
  echo $! > "$PIDFILE"
  echo "Service started" >&2
}

stop() {
  if [ ! -f "$PIDFILE" ] || ! kill -0 $(cat "$PIDFILE"); then
    echo 'Service not running' >&2
    return 1
  fi
  echo 'Stopping service...' >&2
  kill -15 $(cat "$PIDFILE") && rm -f "$PIDFILE"
  echo 'Service stopped' >&2
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    start
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
esac