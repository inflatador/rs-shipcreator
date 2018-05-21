#!/usr/bin/env python3
# # -*- coding: UTF-8 -*-
# shipcreator. Given a Rackspace Cloud Network and IP, makes a Shared IP on that network.
#Note: Shared IP is in limited availabilty and must be manually enabled on your account!
# version - 0.0.2a
# © 2018 Brian King,
##Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import base64
import logging
import plac
import json
import keyring
import os
import requests
import time
import sys

requests.packages.urllib3.disable_warnings()

def getset_keyring_credentials(username=None, password=None):
    """Method to retrieve credentials from keyring."""
    username = keyring.get_password("raxcloud", "username")
    if username is None:
        if sys.version_info.major < 3:
            username = raw_input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username', username)
            print ("Username value saved in keychain as raxcloud username.")
        elif creds == "username":
            username = input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username', username)
            print ("Username value saved in keychain as raxcloud username.")
    else:
        print ("Authenticating to Rackspace cloud as %s" % username)
    password = keyring.get_password("raxcloud", "password")
    if password is None:
        password = getpass("Enter Rackspace API key:")
        keyring.set_password("raxcloud", 'password' , password)
        print ("API key value saved in keychain as raxcloud password.")
    return username, password

def wipe_keyring_credentials(username, password):
    """Wipe credentials from keyring."""
    try:
        keyring.delete_password('raxcloud', 'username')
        keyring.delete_password('raxcloud', 'password')
    except:
        pass

    return True

# Request to authenticate using password
def get_auth_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}
    payload2 = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username': username,'apiKey': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()


    if r.status_code != 200:
        r = requests.post(url, headers=headers, json=payload2)
        if r.status_code != 200:
            print ("Error! API responds with %d" % r.status_code)
            print("Rerun the script and you will be prompted to re-enter username/password.")
            wipe_keyring_credentials(username, password)
            sys.exit()
        else:
            print("Authentication was successful!")
    elif r.status_code == 200:
        print("Authentication was successful!")

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    auth_token = data["access"]["token"]["id"]
    tenant_id = data["access"]["token"]["tenant"]["id"]
    return auth_token, tenant_id

def find_endpoints(auth_token, region, desired_service="cloudNetworks"):

    url = ("https://identity.api.rackspacecloud.com/v2.0/tokens/%s/endpoints" % auth_token)
    headers = {'content-type': 'application/json', 'Accept': 'application/json',
               'X-Auth-Token': auth_token}
    #region is always uppercase in the service catalog
    region =region.upper()
    raw_service_catalog = requests.get(url, headers=headers)
    raw_service_catalog.raise_for_status()
    the_service_catalog = raw_service_catalog.json()
    endpoints = the_service_catalog["endpoints"]
    for service in range(len(endpoints)):
        if desired_service == endpoints[service]["name"] and region == endpoints[service]["region"]:
            desired_endpoint = endpoints[service]["publicURL"]
    return desired_endpoint, headers

def create_neutron_ports(auth_token, headers, neutron_endpoint, net_id):
    ports_uri = "ports"
    networks_url = ("%s/%s" % (neutron_endpoint, ports_uri))
    #before we can make a shared IP, we have to make neutron ports.
    neutron_port_ids = []
    for port in '1', '2':
    	portname = ("port%s" % (port))
    	payload = {'port': {'name': portname, 'network_id': net_id} }
    	raw_port_create_req = requests.post(url=networks_url, headers=headers, json=payload)
    	port_create_req = raw_port_create_req.json()
    	neutron_port_ids.append(port_create_req["port"]["id"])
    return neutron_port_ids
    
def create_shared_ip(auth_token, headers, neutron_endpoint, net_id, shared_ip, neutron_port_ids):
 	ips_uri = "ip_addresses"
 	ips_url = ("%s/%s" % (neutron_endpoint, ips_uri))
 	print (neutron_port_ids)
 	payload = ({'ip_address': { 'network_id': net_id,
 				'version': '4',
 				'ip_address': shared_ip,
				'port_ids': neutron_port_ids}
 				})
 	raw_ship_create_req = requests.post(url=ips_url, headers=headers, json=payload)
 	ship_create_req = raw_ship_create_req.json()
 	print (ship_create_req)
 	
#begin main function
@plac.annotations(
    region=plac.Annotation("Rackspace Cloud Servers region"),
    net_id=plac.Annotation("Cloud Network ID"),
    shared_ip=plac.Annotation("Desired IP to be shared")
                )
def main(region, net_id, shared_ip):
    username,password = getset_keyring_credentials()

    auth_token,tenant_id = get_auth_token(username, password)

    find_endpoints(auth_token, region)

    desired_endpoint, headers = find_endpoints(auth_token, region)

    #this might violate DRY, I will fix later.

    neutron_endpoint = desired_endpoint
    
    neutron_port_ids = create_neutron_ports(auth_token, headers, neutron_endpoint, net_id)
    
    create_shared_ip(auth_token, headers, neutron_endpoint, net_id, shared_ip, neutron_port_ids)

if __name__ == '__main__':
    import plac
    plac.call(main)