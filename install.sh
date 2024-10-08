#!/bin/bash

# Create the folder inside /etc
sudo mkdir -p /etc/haproxy-dashboard

# Copy files to the 'haproxy-dashboard' folder

# sudo cp -r __pycache__/ /etc/haproxy-dashboard/
# sudo cp -r .venv/ /etc/haproxy-dashboard/
sudo cp -r admin/ /etc/haproxy-dashboard/
sudo cp -r openssl/ /etc/haproxy-dashboard/
sudo cp -r ssl/ /etc/haproxy-dashboard/
sudo cp -r static/ /etc/haproxy-dashboard/
sudo cp -r templates/ /etc/haproxy-dashboard/
sudo cp app.py /etc/haproxy-dashboard/
sudo cp Makefile /etc/haproxy-dashboard/
sudo cp requirements.txt /etc/haproxy-dashboard/
sudo cp ssl.ini /etc/haproxy-dashboard/


# Create the service file for 'haproxy-dashboard'
cat << EOF | sudo tee /etc/systemd/system/haproxy-dashboard.service
[Unit]
Description=Haproxy-Dashboard

[Service]
ExecStart=/usr/bin/python3 /etc/haproxy-dashboard/app.py
Restart=always
RestartSec=3
StandardOutput=/var/log/haproxy-dashboard_std_output.log
StandardError=/var/log/haproxy-dashboard_error.log
[Install]
WantedBy=multi-user.target
EOF

# Reload systemd to load the new service
sudo systemctl daemon-reload

# Enable and start the service
sudo systemctl enable haproxy-dashboard.service
sudo systemctl start haproxy-dashboard.service