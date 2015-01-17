#!/bin/bash
sudo tc qdisc del dev mesh0 root
sudo tc qdisc add dev mesh0 handle 1: root htb default 11
sudo tc class add dev mesh0 parent 1: classid 1:1 htb rate $1
sudo tc class add dev mesh0 parent 1:1 classid 1:11 htb rate $1
