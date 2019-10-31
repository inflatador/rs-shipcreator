#!/usr/bin/env python3
# shipcreator.py:
# given at least 2 cloud server IDs and a network,
# provisions shared IP on that network

from getpass import getpass
import json
import keyring
import logging
import os
import plac
import requests
import sys
import time

def find_endpoints(auth_token, headers, region, desired_service="cloudServersOpenStack"):

    url = ("https://identity.api.rackspacecloud.com/v2.0/tokens/%s/endpoints" % auth_token)
    #region is always uppercase in the service catalog
    region = region.upper()
    raw_service_catalog = requests.get(url, headers=headers)
    raw_service_catalog.raise_for_status()
    the_service_catalog = raw_service_catalog.json()
    endpoints = the_service_catalog["endpoints"]

    for service in endpoints:
        if desired_service == service["name"] and region == service["region"]:
            desired_endpoint = service["publicURL"]

    return desired_endpoint

def getset_keyring_credentials(username=None, password=None):
    #Method to retrieve credentials from keyring.
    print (sys.version_info.major)
    username = keyring.get_password("raxcloud", "username")
    if username is None:
        if sys.version_info.major < 3:
            username = raw_input("Enter Rackspace Username: ")
            keyring.set_password("raxcloud", 'username', username)
            print ("Username value saved in keychain as raxcloud username.")
        elif sys.version_info.major >= 3:
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

    headers = ({'content-type': 'application/json', 'Accept': 'application/json',
    'X-Auth-Token': auth_token})

    return auth_token, headers

def validate_cs_ids(cloud_network, cs_endpoint, cs_ids, headers):
    #some validation for Cloud Server IDs
    if "," in cs_ids:
        cs_list = []
        cs_list = cs_ids.split(',')
        cs_details = []
        provisioning_zones = []
        for cs_id in cs_list:
            cs_url = "{}/servers/{}".format(cs_endpoint, cs_id)
            cs_check = requests.get(url=cs_url, headers=headers)
            #validate that the server exists
            if cs_check.status_code != 200:
                print(f"Could not validate server {cs_id}! Cloud Servers "
                      f"API returns code {cs_check.status_code}. Exiting!")
                exit(1)
            cs_details.append(cs_check.json())
        for cs_detail in cs_details:
            if cloud_network == "public":
                print("Server {} is in provisioning zone {}".format(cs_detail["server"]["name"], cs_detail["server"]["RAX-PUBLIC-IP-ZONE-ID:publicIPZoneId"]))
                provisioning_zones.append(cs_detail["server"]["RAX-PUBLIC-IP-ZONE-ID:publicIPZoneId"])
        # validate that servers are in the same provisioning zone
        if len(set(provisioning_zones)) != 1 and cloud_network == "public":
            print (f"Error! Shared Public IP requires servers to be in the same"
                  f" provisioning zone!")
            exit(1)
        return cs_details, cs_list
    else:
        print ("Could not validate input. Exiting!")
        sys.exit()

def get_port_ids(cloud_network, cn_endpoint, cs_list, headers):
    # verify the Cloud Network exists, and is currently connected
    # to the servers

    shared_ip_ports = []
    for cs in cs_list:
        # querystuff = {'device_id': cs}
        if cloud_network == "public":
            querystuff = { 'network_id': '00000000-0000-0000-0000-000000000000',
                          'device_id': cs }
        else:
            querystuff = {'network_id': cloud_network,
                          'device_id': cs }
        ports_url = "{}/ports".format(cn_endpoint)
        print("Checking if server {} has a port on network {}...".format(cs, cloud_network))
        port_check = requests.get(url=ports_url, params=querystuff, headers=headers)
        port_check.raise_for_status()
        port_list = port_check.json()["ports"]
        for port in port_list:
            if cs == port["device_id"]:
                print ("Found port {} on network {} attached to server {}!".format(port["id"], cloud_network, cs))
            shared_ip_ports.append(port["id"])
        # print (shared_ip_ports)
        print ("Finished loop, and ports are at {}".format(shared_ip_ports))
    if len(cs_list) != len(shared_ip_ports):
        print ("Error! At least one Cloud Server has no port on network {}".format(cloud_network))
        sys.exit(1)
    return shared_ip_ports

def create_shared_ip(cloud_network, cn_endpoint, headers, ip_version,
                    shared_ip_ports):
    if cloud_network == "public":
        net_id = "00000000-0000-0000-0000-000000000000"
    else:
        net_id = cloud_network
    ips_url = "{}/ip_addresses".format(cn_endpoint)
    payload = ({'ip_address': { 'network_id': net_id,
 				'version': '6',
				'port_ids': shared_ip_ports}
 				})
    print ("Provisioning Shared IP on network {}".format(cloud_network))
    ship_create_req = requests.post(url=ips_url, headers=headers, json=payload)
    print (ship_create_req.json())


        # if not ports:
        #     print ("Error! Could not find a port on network {} attached to server {}!".format(port["id"], cloud_network, cs))



        #validate that the Cloud Network exists
        # if port_check.status_code != 200:
        #     print(f"Could not validate server {cs_id}! Cloud Servers "
        #           f"API returns code {cs_check.status_code}. Exiting!")
        #     exit(1)

# def get_port_ids(cloud_network, cn_endpoint, cs_list, headers):
#     port_ids = []
#     for cs in cs_list:
#



#begin main function
@plac.annotations(
    region=plac.Annotation("Rackspace Cloud Servers region"),
    cs_ids=plac.Annotation("At least 2 Cloud Server IDs, separated by commas"),
    cloud_network=plac.Annotation("Cloud Network or 'public' for Public Network"),
    ip_version=plac.Annotation("IP version", choices=["4", "6"])
                )

def main(region, cs_ids, cloud_network, ip_version):
    username, password = getset_keyring_credentials()

    auth_token, headers = get_auth_token(username, password)

    cn_endpoint = find_endpoints(auth_token, headers, region,
              desired_service="cloudNetworks")

    cs_endpoint = find_endpoints(auth_token, headers, region,
              desired_service="cloudServersOpenStack")

    cs_details, cs_list = validate_cs_ids(cloud_network, cs_endpoint, cs_ids, headers)

    shared_ip_ports = get_port_ids(cloud_network, cn_endpoint, cs_list, headers)

    create_shared_ip(cloud_network, cn_endpoint, headers, ip_version,
                    shared_ip_ports)

if __name__ == '__main__':
    import plac
    plac.call(main)
