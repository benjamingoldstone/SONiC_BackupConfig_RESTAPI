# Remote backup tools for Dell Enterprise SONiC

[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg)](#-how-to-contribute)
[![License](https://img.shields.io/badge/license-GPL-blue.svg)](https://github.com/gpaquis/SONiC_BackupConfig_RESTAPI/blob/main/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/gpaquis/SONiC_FirmwareUpdater)](https://github.com/gpaquis/SONiC_BackupConfig_RESTAPI/issues)

Built and maintained by [Gerald PAQUIS](https://github.com/gpaquis) and [Contributors](https://github.com/gpaquis/SONiC_BackupConfig_RESTAPI/graphs/contributors)

--------------------
This Repo contains a Python script for backup remotly a config file and  store it on a scp/ftp server by using REST-API

## Contents

- [Description and Objective](#-Description-and-Objective)
- [Requirements](#-Requirements)
- [Usage and Configuration](#-Usage-and-Configuration)
- [Roadmap](#-Roadmap)
- [How to Contribute](#-How-to-Contribute)

## 🚀 Description and Objective

The script allow to backup config_db.json from Dell Enterprise SONiC. <br />
This script is for purpose test only and explain howto massively backup config file to a remote server. <br />

## 📋 Requirements
- Python 3.8.10 version minimum
- a SCP/FTP server hosting the config file

## 🏁 Usage and Configuration
The script support only backup to a remote SCP/FTP server, don't support local deployment or import config file.<br />
See [Roadmap](#-Roadmap) for more details and next feature.

**Runing the script and options:**

| Options         | Value            | Description                                 | Mandatory |
|-----------------|------------------|---------------------------------------------|-----------|
|--method         | http or https    | Remote web servers                          |   Yes     |
|--switch_ip      | IPV4             | IP address of the DES management interface  |           |
|--sonic_username | type string      | Login used to access to the DES             |           |
|--sonic_password | type string      | Password used to access to the DES          |           |
|--remote_server  | IPV4             | IP address of the remote Server             |           |
|--remote_login   | type string      | Login used to access to the remote server   |           |
|--remote_password| type string      | Password used to access to the remote server|           |
|--remote_path    | type string      | Remote directory name                       |           |


  `python3 BackupConfig_restapi.py --method scp --switch_ip 192.168.1.100 --sonic_username admin --sonic_password YourPaSsWoRd --remote_server 192.168.1.238 --remote_login dell --remote_password DellDell123 --remote_path /home/dell`

it's also possible to use the 'backup_list.conf'[https://github.com/gpaquis/SONiC_BackupConfig_RESTAPI/blob/main/src/backup_list.conf] file to backup multiple DES in one line

| Options         | Value            | Description                                 | Mandatory |
|-----------------|------------------|---------------------------------------------|-----------|
|--method         | http or https    | Remote web servers                          |   Yes     |
|--bulk           | type string      | config file name                            |           |

 `python3 BackupConfig_restapi.py --bulk backup_list.conf --method scp`


## 📅 Roadmap
NONE <br />

## 👏 How to Contribute
We welcome contributions to the project.
