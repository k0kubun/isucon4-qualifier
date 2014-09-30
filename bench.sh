#!/bin/sh

ssh_host=isucon

ssh $ssh_host "/home/isucon/benchmarker-v2 bench --init '/home/isucon/init.sh' --workload $@"
