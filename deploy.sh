#!/bin/sh

ssh_host=isucon
cwd=`dirname "${0}"`
expr "${0}" : "/.*" > /dev/null || cwd=`(cd "${cwd}" && pwd)`

rsync -av -e ssh "${cwd}/" "${ssh_host}:/home/isucon/webapp"
# ssh $ssh_host "cd /home/isucon/webapp/ruby; /home/isucon/env.sh bundle install"
ssh -t $ssh_host "sudo sysctl -p"
ssh -t $ssh_host "sudo service mysqld restart"
ssh -t $ssh_host "sudo service nginx restart"
# ssh -t $ssh_host "sudo service redis restart"
# ssh -t $ssh_host "sudo supervisorctl restart isucon_ruby"
ssh -t $ssh_host "sudo supervisorctl restart isucon_go"
