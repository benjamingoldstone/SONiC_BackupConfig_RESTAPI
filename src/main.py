

import json
import sys
import requests
from requests.exceptions import HTTPError
from requests.auth import HTTPBasicAuth
import logging
import datetime


def parse_config_file_general(file_name):  # TODO: fill this out
    config_dict = []

    return config_dict


def backup_des_config_file(device_ip, device_name, device_username, device_password, file_to_backup, dst_server_ip, dst_server_port, dst_server_method, dst_server_path, dst_server_username=None, dst_server_password=None):
    """

    """

    current_time = datetime.datetime.strftime(datetime.datetime.utcnow(), format="%y%m%d-%H:%M:%S")

    if dst_server_username is not None and dst_server_password is not None:
        full_path = f"{dst_server_method}://{dst_server_username}:{dst_server_password}@{dst_server_ip}:{dst_server_port}{dst_server_path}/{file_to_backup}"
    else:
        full_path = f"{dst_server_method}://{dst_server_ip}:{dst_server_port}{dst_server_path}/{device_name}_{current_time}_{file_to_backup}"

    print(full_path)
    request_data = {
        "openconfig-file-mgmt-private:input": {
            "source": f"config://{file_to_backup}",
            "destination": full_path,
            "copy-config-option": "MERGE"
        }
    }

    try:
        response = requests.post(url=f"https://{device_ip}/restconf/operations/openconfig-file-mgmt-private:copy",
                                 data=json.dumps(request_data),
                                 headers={'Content-Type': 'application/yang-data+json'},
                                 auth=HTTPBasicAuth(f"{device_username}", f"{device_password}"),
                                 verify=False
                                 )
        response.raise_for_status()
    except HTTPError as http_err:
        logging.error(http_err)
        sys.exit()
    except Exception as e:
        logging.error(e)
        sys.exit()


def restore_des_config_file():  # TODO: fill this out
    return None


def read_info_json_file(filename) -> json:
    try:
        with open(filename, "r") as jsonfile:
            config_file = json.load(jsonfile)
            logging.info(f"Import of JSON formatted device config file '{filename}' was successful.")
        return config_file
    except Exception as e:  # TODO: obviously way to broad, clean this up
        logging.error(e)
        sys.exit()


def main():
    config = read_info_json_file("config.json")

    general_config = config.get("general_config")
    conf_dst_server_method = f'{general_config.get("dst_server_method")}'
    conf_dst_server_port = f'{general_config.get("dst_server_port")}'
    conf_dst_server_ip = f'{general_config.get("dst_server_ip")}'
    conf_dst_server_path = f'{general_config.get("dst_server_path")}'
    conf_file_to_backup = f'{general_config.get("file_to_backup")}'

    for i in config.get("switches"):
        print("abc")
        backup_des_config_file(device_ip=f'{i.get("switch_ip")}',
                               device_name=f'{i.get("name")}',
                               device_username=f'{i.get("username")}',
                               device_password=f'{i.get("password")}',
                               dst_server_method=conf_dst_server_method,
                               dst_server_port=conf_dst_server_port,
                               dst_server_ip=conf_dst_server_ip,
                               file_to_backup=conf_file_to_backup,
                               dst_server_path=conf_dst_server_path
                               )


if __name__ == "__main__":
    main()
