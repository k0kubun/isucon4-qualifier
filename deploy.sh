#!/bin/sh

ssh_host=isucon
cwd=`dirname "${0}"`
expr "${0}" : "/.*" > /dev/null || cwd=`(cd "${cwd}" && pwd)`

rsync -av -e ssh "${cwd}/" "${ssh_host}:/home/isucon/webapp"

ssh -t -t $ssh_host <<-EOS
  cd /home/isucon/webapp/go
  /home/isucon/env.sh /home/isucon/webapp/go/build.sh
  sudo sysctl -p
  sudo service mysqld restart
  sudo service nginx stop
  sudo service supervisord reload
  sudo supervisorctl stop isucon_go
  sudo rm -f /tmp/app.sock
  sudo supervisorctl start isucon_go
  exit
EOS
