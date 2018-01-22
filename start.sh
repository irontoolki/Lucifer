#!/bin/bash
sysctl -w net.ipv4.ip_forward=1
iptables-restore < rule.fw 
