"""
Description: This script allow to backup remotely a config switch using Dell Enterprise SONiC
Author: Gerald PAQUIS
Date Created: November 2023
Date Last Modified: December, 2023
Version: 0.1
Python Version: 3.8.10
Dependencies: none
License: GPL-3.0 license
"""

import json
import argparse
import ast
import os.path
import requests
import configparser
import ipaddress
from datetime import datetime
from requests.exceptions import HTTPError
from requests.auth import HTTPBasicAuth
import base64
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def validate_ip_address(ip_string) -> bool:
    try:
        ip_object = ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False


def check_status(remote_sw):
    """
       Check Firmware Status Upgrade
    """

    switch_ip = remote_sw['switch_ip']
    user_name = remote_sw['sonic_username']
    password = remote_sw['sonic_password']

    request_data = {
        "openconfig-file-mgmt-private:input": {
            "folder-name": "config:/"
        }
    }

    try:
        response = requests.post(url=f"https://{switch_ip}/restconf/operations/openconfig-file-mgmt-private:dir",
                                 data=json.dumps(request_data),
                                 headers={'Content-Type': 'application/yang-data+json'},
                                 auth=HTTPBasicAuth(f"{user_name}", f"{password}"),
                                 verify=False
                                 )
        response.raise_for_status()

    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')
    else:
        # print (response.content)
        return_dict = dict()
        mystatus = json.loads(response.content)
        print(f'{mystatus}')
        # return_dict['myinstall-status'] = mystatus["openconfig-image-management:image-management"]["install"]["state"]["install-status"]
        return return_dict


def read_config(config_file):
    rem_config = dict()
    config = configparser.ConfigParser()
    config.read(config_file)

    rem_config['remote_server'] = config['Remote']['rem_server']
    rem_config['remote_login'] = config['Remote']['rem_login']
    rem_config['remote_passwd'] = config['Remote']['rem_passwd']
    rem_config['remote_path'] = config['Remote']['rem_path']
    print(f'{rem_config}')
    return rem_config


def backup_config(remote_sw, remote_srv):
    """
      source:  always "config://config.db.json"
      destination: method://rem_login:rem_passwd@rem_serv/rem_path/filename+timestamps.json
      copy-config-option: MERGE
    """
    switch_ip = remote_sw['switch_ip']
    user_name = remote_sw['sonic_username']
    password = remote_sw['sonic_password']

    method = remote_srv['method']
    rem_serv = remote_srv['remote_server']
    rem_login = remote_srv['remote_login']
    rem_passwd = remote_srv['remote_passwd']
    rem_path = remote_srv['remote_path']

    time_format = '%Y%m%d%H%M'
    timestamp = datetime.now().strftime(time_format)

    filename = switch_ip + '_' + timestamp + '.json'
    print(filename)
    full_path = method + "://" + rem_login + ":" + rem_passwd + "@" + rem_serv + rem_path + '/' + filename
    # f"://{rem_login}:{rem_passwd}@{rem_serv}{rem_path}/{filename}"
    # f"://{rem_login}:{rem_passwd}@{rem_serv}{rem_path}/{filename}"
    print(f'{full_path}')

    request_data = {
        "openconfig-file-mgmt-private:input": {
            "source": "config://config_db.json",
            "destination": full_path,
            "copy-config-option": "MERGE"
        }
    }

    try:
        response = requests.post(url=f"https://{switch_ip}/restconf/operations/openconfig-file-mgmt-private:copy",
                                 data=json.dumps(request_data),
                                 headers={'Content-Type': 'application/yang-data+json'},
                                 auth=HTTPBasicAuth(f"{user_name}", f"{password}"),
                                 verify=False
                                 )
        response.raise_for_status()

    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')
    else:
        mystatus = json.loads(response.content)
        myreturn = mystatus["openconfig-file-mgmt-private:output"]["status-detail"]
        return myreturn


def main():
    parser = argparse.ArgumentParser(description='Backup config file tools')
    parser.add_argument("--method", help="ftp or scp", type=str)
    parser.add_argument("--switch_ip", help="IP address of the switch", type=str)
    parser.add_argument("--sonic_username", help="SONiC Login", type=str)
    parser.add_argument("--sonic_password", help="SONiC Password", type=str)
    parser.add_argument("--remote_server", help="Remote server IP", type=str)
    parser.add_argument("--remote_login", help="Remote server login", type=str)
    parser.add_argument("--remote_password", help="Remote server Password", type=str)
    parser.add_argument("--remote_path", help="Remote path", type=str)
    parser.add_argument("--bulk", help="config filename for bulk backup", type=str)
    args = parser.parse_args()

    method = args.method.lower()

    config_file = args.bulk
    if config_file is None:

        switch_ip = args.switch_ip
        sonic_username = args.sonic_username
        sonic_password = args.sonic_password
        remote_server = args.remote_server
        remote_login = args.remote_login
        remote_passwd = args.remote_password
        remote_path = args.remote_path
        switch_ip = args.switch_ip
        print(f'{switch_ip}')
        remote_server = args.remote_server

        if validate_ip_address(switch_ip) is True and validate_ip_address(remote_server) is True:
            remote_sw = {'switch_ip': switch_ip, 'sonic_username': sonic_username, 'sonic_password': sonic_password}
            remote_srv = {'method': method, 'remote_server': remote_server, 'remote_login': remote_login,
                          'remote_passwd': remote_passwd, 'remote_path': remote_path}

        if method == "scp" or "ftp":
            result = backup_config(remote_sw, remote_srv)
            print(f'Backup {switch_ip} : {result}')

    else:
        check_file = os.path.exists(config_file)
        if check_file:
            myremote_config = read_config(config_file)
            remote_server = myremote_config['remote_server']
            remote_login = myremote_config['remote_login']
            remote_passwd = myremote_config['remote_passwd']
            remote_path = myremote_config['remote_path']

            config = configparser.ConfigParser()
            config.read(config_file)

            sw_list = []

            for each_section in config.sections():
                for (each_key, each_val) in config.items(each_section):
                    if each_key == "sw_ip":
                        sw_list.append(each_section)

            for switch_id in sw_list:
                switch_ip = config[f"{switch_id}"]['sw_ip']
                sonic_username = config[f"{switch_id}"]['sw_login']
                sonic_password = config[f"{switch_id}"]['sw_password']
                if validate_ip_address(switch_ip) is True and validate_ip_address(remote_server) is True:
                    remote_sw = {'switch_ip': switch_ip, 'sonic_username': sonic_username,
                                 'sonic_password': sonic_password}
                    remote_srv = {'method': method, 'remote_server': remote_server, 'remote_login': remote_login,
                                  'remote_passwd': remote_passwd, 'remote_path': remote_path}

                if method == "scp" or "ftp":
                    result = backup_config(remote_sw, remote_srv)
                    print(f'Backup {switch_ip} : {result}')


if __name__ == '__main__':
    main()
