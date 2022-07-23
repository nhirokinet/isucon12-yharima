#!/bin/bash

set -eux

# copy
sudo webapp/sql/competition-and-player.sql /home/isucon/webapp/sql/competition-and-player.sql
sudo webapp/sql/init.sh /home/isucon/webapp/sql/init.sh

# nginx
sudo cp etc/nginx/nginx.conf /etc/nginx/nginx.conf

# logrotation
gzip /var/log/nginx/access.log -c | sudo tee /var/log/nginx/access.`date +"%T"`.gz > /dev/null
sudo cp /dev/null /var/log/nginx/access.log

# reload
sudo systemctl restart nginx