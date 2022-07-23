#!/bin/bash

set -eux

# nginx
sudo cp etc/nginx/nginx.conf /etc/nginx/nginx.conf

# logrotation
gzip /var/log/nginx/access.log -c | sudo tee /var/log/nginx/access.`date +"%T"`.gz > /dev/null
sudo cp /dev/null /var/log/nginx/access.log

# reload
sudo systemctl restart nginx