#!/bin/bash

# Install OS dependencies
dnf install -y python3 python3-pip python3-netifaces

# Install Python dependencies
umask 022
pip3 install --user dnslib dnspython netaddr

# Open firewall ports
firewall-cmd --add-port=53/udp
firewall-cmd --add-port=53/udp --permanent

# Copy files
cp -v conditional-dns.py /usr/local/bin
cp -v conditional-dns.service /lib/systemd/system
cp -v conditional-dns.logrotate /etc/logrotate.d
cp -v conditional-dns.conf /etc
