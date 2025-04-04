#!/bin/bash

# This should work probably. It's super janky though and I should probably learn how to do it for real lol
# Make edits to the service to serve out of the copied directory. It's currently serving from the testing directory.

# This is designed to be run in the project directory. It does not install any dependencies or configure anything beyond the account and service file. You will likely need to edit both.  

# build the source
cargo build --release

# Create a user for the server to run under
# Set up as service account with no shell/login
useradd -r infectorapi -s /bin/false

# make a directory for the server executable
mkdir /opt/infectorapi

# copy the built 
cp ./target/release/infector_api /opt/infectorapi/infector_api

# give service account access to the file
chown -R infectorapi:infectorapi /opt/infectorapi

# copy service file into systemd services
cp infector_api.service /etc/systemd/system/infector_api.service

# start server
systemctl start infector_api