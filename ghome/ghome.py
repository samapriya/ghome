__copyright__ = """

    Copyright 2021 Samapriya Roy

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

"""
__license__ = "Apache 2.0"

#! /usr/bin/env python

import argparse
import os
import sys
import requests
import time
import json
import nmap
import socket
import getpass
import configparser
from retrying import retry
from glocaltokens.client import GLocalAuthenticationTokens
from os.path import expanduser
from collections import defaultdict
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
os.chdir(os.path.dirname(os.path.realpath(__file__)))

lpath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(lpath)


def master_auth():
    config = configparser.ConfigParser()
    try:
        if not os.path.exists(os.path.join(expanduser("~"), ".ghome-config")):
            username = input("Google Username associated with Google Home Devices: ")
            password = getpass.getpass("Enter your password: ")
            client = GLocalAuthenticationTokens(username=username, password=password)
            mtoken = client.get_master_token()
            with open(os.path.join(expanduser("~"), ".ghome-config"), "w") as cfgfile:
                config.add_section("ghome")
                config.set("ghome", "master_token", mtoken)
                config.write(cfgfile)
                cfgfile.close()
        elif os.path.exists(os.path.join(expanduser("~"), ".ghome-config")):
            config.read(os.path.join(expanduser("~"), ".ghome-config"))
            mtoken = config["ghome"]["master_token"]
        return mtoken
    except Exception as e:
        print(e)


def auth_from_parser(args):
    master_auth()


def device_json():
    client = GLocalAuthenticationTokens(master_token=master_auth())
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    # Using sockets to get iprange
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    iprange = ".".join(s.getsockname()[0].split(".")[0:3])
    s.close()

    # Using nmap to get device list
    nm = nmap.PortScanner()
    scanner = nm.scan(iprange + ".*", arguments="-sn")
    device_list = []
    headers = {"content-type": "application/json"}

    google_devices = json.loads(client.get_google_devices_json())
    google_devices_list = []
    for items in google_devices:
        try:
            items.pop("google_device")
            # print(items)
            google_devices_list.append(items)
        except Exception as e:
            print(e)
    for stuff, value in scanner["scan"].items():
        try:
            response = requests.get(
                "https://{}:8443/setup/eureka_info".format(
                    str(value["addresses"]["ipv4"])
                ),
                headers=headers,
                verify=False,
                timeout=3,
            )
            if response.status_code == 200:
                print(
                    "{}: {}".format(
                        response.json()["name"], response.json()["ip_address"]
                    )
                )
                item = {
                    "device_name": response.json()["name"],
                    "ip": response.json()["ip_address"],
                }
                device_list.append(item)
        except requests.exceptions.ConnectionError:
            pass
        except Exception as e:
            pass
    d = defaultdict(dict)
    for l in (google_devices_list, device_list):
        for elem in l:
            d[elem["device_name"]].update(elem)
    combined_devices = d.values()
    combined_devices = [value for value in combined_devices]
    combined_devices = [i for i in combined_devices if "ip" in i]
    with open(os.path.join(expanduser("~"), "devices.json"), "w") as outfile:
        json.dump(combined_devices, outfile)
    return combined_devices


# Find google home devices
def ghome():
    try:
        if os.path.exists(os.path.join(expanduser("~"), "devices.json")):
            fullpath = os.path.join(expanduser("~"), "devices.json")
            file_mod_time = os.stat(fullpath).st_mtime
            if int((time.time() - file_mod_time) / 60) > 1440:
                print("Generating new device local tokens")
                combined_devices = device_json()
            else:
                print("Using existing local device tokens")
                with open(os.path.join(expanduser("~"), "devices.json")) as f:
                    combined_devices = json.load(f)
            return combined_devices
        elif not os.path.exists(os.path.join(expanduser("~"), "devices.json")):
            print("Generating new device local tokens")
            combined_devices = device_json()
            return combined_devices
    except Exception as e:
        print(e)


################################### Device info tools #####################################################
@retry(stop_max_attempt_number=2)
def device_info(ipadd, name):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0:
        try:
            response = requests.get(
                f"https://{ipadd}:8443/setup/eureka_info",
                headers=headers,
                verify=False,
            )
            if response.status_code == 200:
                response = response.json()
                print(json.dumps(response, indent=4, sort_keys=False))
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)


# device_info(name='KITCHEN speaker',ipadd=None)
def devinfo_from_parser(args):
    device_info(ipadd=args.ip, name=args.name)


def device_list():
    devlist = []
    if os.path.exists(os.path.join(expanduser("~"), "devices.json")):
        with open(os.path.join(expanduser("~"), "devices.json")) as f:
            combined_devices = json.load(f)
    elif not os.path.exists(os.path.join(expanduser("~"), "devices.json")):
        print("Device list not found now generating")
        combined_devices = device_json()
    for devices in combined_devices:
        item = {"name": devices["device_name"], "ip": devices["ip"]}
        devlist.append(item)
    print(json.dumps(devlist, indent=2, sort_keys=False))


def device_list_from_parser(args):
    device_list()


############################################# Device settings Tools ########################################
@retry(stop_max_attempt_number=2)
def reboot(ipadd, name, action):
    device_list = ghome()
    device_match = []
    if action == "reboot":
        payload = '{"params": "now"}'
    elif action == "reset":
        payload = '{"params": "fdr"}'
        check_reset = input("Are you sure you want to perform factory reset?")
        if check_reset == "n":
            sys.exit("Not performing factory reset")
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0 and action is not None:
        try:
            response = requests.post(
                f"https://{ipadd}:8443/setup/reboot",
                headers=headers,
                verify=False,
                data=payload,
            )
            if response.status_code == 200:
                print(f"Perfromed : {action} on {ipadd}")
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


# reboot(name='Living Room speaker',ipadd=None,action='reboot')
def reboot_from_parser(args):
    reboot(ipadd=args.ip, name=args.name, action=args.action)


# Get all alarms set on the devices
@retry(stop_max_attempt_number=2)
def alarm_list(ipadd, name):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0:
        try:
            response = requests.get(
                f"https://{ipadd}:8443/setup/assistant/alarms",
                headers=headers,
                verify=False,
            )
            if response.status_code == 200:
                response = response.json()
                if len(response["alarm"]) != 0:
                    for items in response["alarm"]:
                        print(
                            "Alarm set for: "
                            + str(
                                time.strftime(
                                    "%a, %d %b %Y %H:%M:%S %Z",
                                    time.localtime(float(items["fire_time"] / 1000)),
                                )
                            )
                        )
                else:
                    print("No alarms currently set")
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)


# alarm_list(name='KITCHEN speaker',ipadd=None)


def alarm_list_from_parser(args):
    alarm_list(ipadd=args.ip, name=args.name)


@retry(stop_max_attempt_number=2)
def alarm_volume(ipadd, name, volume):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0 and volume is not None and volume <= 1:
        url = f"https://{ipadd}:8443/setup/assistant/alarms/volume"
        payload = {"volume": volume}
        try:
            response = requests.post(
                url,
                headers=headers,
                verify=False,
                data=payload,
            )
            if response.status_code == 200:
                print(f"Alarm Volume set to: {volume}")
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


# alarm_volume(name='Living Room speaker',ipadd=None,volume = 0.5)
def alarm_volume_from_parser(args):
    alarm_volume(ipadd=args.ip, name=args.name, volume=args.volume)


@retry(stop_max_attempt_number=2)
def alarm_delete(ipadd, name):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0:
        del_url = f"https://{ipadd}:8443/setup/assistant/alarms/delete"
        payload = {"ids": []}
        try:
            response = requests.post(
                del_url,
                headers=headers,
                verify=False,
                data=payload,
            )
            if response.status_code == 200:
                print("Alarm deleted successfully")
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


def alarm_delete_from_parser(args):
    alarm_delete(ipadd=args.ip, name=args.name)


########################################## Bluetooth tools #########################################


@retry(stop_max_attempt_number=2)
def bstat(ipadd, name):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0:
        try:
            response = requests.get(
                f"https://{ipadd}:8443/setup/bluetooth/status",
                headers=headers,
                verify=False,
            )
            if response.status_code == 200:
                response = response.json()
                print("")  # add a little space
                for key, value in response.items():
                    print(key, value)
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


# bstat(name='KITCHEN speaker',ipadd=None)


def bstat_from_parser(args):
    bstat(ipadd=args.ip, name=args.name)


# # Get paired devices
@retry(stop_max_attempt_number=2)
def bpaired(ipadd, name):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0:
        try:
            response = requests.get(
                f"https://{ipadd}:8443/setup/bluetooth/get_bonded",
                headers=headers,
                verify=False,
            )
            if response.status_code == 200:
                response = response.json()
                if len(response) > 0:
                    for item in response:
                        print("Device Name: " + str(item["name"]))
                        print(
                            "Last connected: "
                            + str(
                                time.strftime(
                                    "%a, %d %b %Y %H:%M:%S %Z",
                                    time.localtime(
                                        float(item["last_connect_date"] / 1000)
                                    ),
                                )
                            )
                        )
                        print("")
                else:
                    print("No current Bluetooth device paired")
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


# bpaired(name='Living Room speaker',ipadd=None)
def bpaired_from_parser(args):
    bpaired(ipadd=args.ip, name=args.name)


# # Get paired devices
def bscan(ipadd, name):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0:
        scan_url = f"https://{ipadd}:8443/setup/bluetooth/scan"
        result_url = f"https://{ipadd}:8443/setup/bluetooth/scan_results"
        payload = '{"enable": true,"clear_results": false,"timeout": 60}'
        try:
            response = requests.post(
                scan_url,
                headers=headers,
                verify=False,
                data=payload,
            )
            if response.status_code == 200:
                print("Scan succeeded")
                response = requests.get(
                    result_url,
                    headers=headers,
                    verify=False,
                )
                response = response.json()
                for items in response:
                    if not len(items["name"]) == 0:
                        print(
                            str(
                                items["name"]
                                + " with mac id: "
                                + str(items["mac_address"])
                            )
                        )
                    else:
                        print(
                            "Unknown device with mac id: " + str(items["mac_address"])
                        )
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


# bscan(name='KITCHEN speaker',ipadd=None)
def bscan_from_parser(args):
    bscan(ipadd=args.ip, name=args.name)


@retry(stop_max_attempt_number=2)
def bdisc(ipadd, name, action):
    device_list = ghome()
    device_match = []
    if action == "enable":
        payload = '{"enable_discovery": true}'
    elif action == "disable":
        payload = '{"enable_discovery": false}'
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0 and action is not None:
        try:
            response = requests.post(
                f"https://{ipadd}:8443/setup/bluetooth/discovery",
                headers=headers,
                verify=False,
                data=payload,
            )
            if response.status_code == 200:
                print(f"Bluetooth Discovery: {action}d on {ipadd}")
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print(
                    "Bluetooth Discovery action Failed with status code {}".format(
                        response.status_code
                    )
                )
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


# bdisc(name='KITCHEN speaker',ipadd=None,action='disable')
def bdisc_from_parser(args):
    bdisc(ipadd=args.ip, name=args.name, action=args.action)


################################################ wireless tools #####################################

# Wifi scan and print available networks
@retry(stop_max_attempt_number=2)
def wscan(ipadd, name):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0:
        scan_url = f"https://{ipadd}:8443/setup/scan_wifi"
        result_url = f"https://{ipadd}:8443/setup/scan_results"
        payload = '{"enable": true,"clear_results": false,"timeout": 60}'
        try:
            response = requests.post(
                scan_url,
                headers=headers,
                verify=False,
                data=payload,
            )
            if response.status_code == 200:
                print("Scan succeeded")
                time.sleep(1)
                response = requests.get(
                    result_url,
                    headers=headers,
                    verify=False,
                )
                response = response.json()
                for items in response:
                    print("Wifi Name or SSID: " + str(items["ssid"]))
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


# wscan(name='Living Room speaker',ipadd=None)
def wscan_from_parser(args):
    wscan(ipadd=args.ip, name=args.name)


# Get saved network
@retry(stop_max_attempt_number=2)
def saved_network(ipadd, name):
    device_list = ghome()
    device_match = []
    for device in device_list:
        try:
            if ipadd is not None and device["ip"] == ipadd:
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                device_match.append(device["ip"])
            elif name is not None and device["device_name"].lower() == name.lower():
                headers = {
                    "content-type": "application/json",
                    "cast-local-authorization-token": device["local_auth_token"],
                }
                ipadd = device["ip"]
                device_match.append(device["ip"])
        except Exception as e:
            pass
    if len(device_match) > 0:
        try:
            response = requests.get(
                f"https://{ipadd}:8443/setup/configured_networks",
                headers=headers,
                verify=False,
            )
            if response.status_code == 200:
                response = response.json()
                print(json.dumps(response, indent=4, sort_keys=False))
                print("")  # add a little space
            elif response.status_code == 401:
                device_json()
                raise Exception("Unauthorized or Expired Local Token: Refreshing")
            else:
                print("Failed with status code {}".format(response.status_code))
        except Exception as e:
            print(e)
    else:
        print("No matching device name or IP address found")


# saved_network(name='KITCHEN speaker',ipadd=None)


def saved_network_from_parser(args):
    saved_network(ipadd=args.ip, name=args.name)


spacing = "                               "


def main(args=None):
    parser = argparse.ArgumentParser(description="Simple Google Home Mini Client")

    subparsers = parser.add_subparsers()

    parser_auth = subparsers.add_parser(
        "auth", help="Auth to get Master Token: Use only once"
    )
    parser_auth.set_defaults(func=auth_from_parser)

    parser_device_list = subparsers.add_parser(
        "device_list", help="Print device list for Google Home devices"
    )
    parser_device_list.set_defaults(func=device_list_from_parser)

    parser_devinfo = subparsers.add_parser(
        "devinfo", help="Provides Device Info based on device name or IP address"
    )
    optional_named = parser_devinfo.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_devinfo.set_defaults(func=devinfo_from_parser)

    parser_reboot = subparsers.add_parser(
        "reboot",
        help="Reboot or Factory Reset a google home device using IP address or Name",
    )
    required_named = parser_reboot.add_argument_group("Required named arguments.")
    required_named.add_argument(
        "--action", help="reboot or reset the device", default=None
    )
    optional_named = parser_reboot.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_reboot.set_defaults(func=reboot_from_parser)

    parser_alarm_list = subparsers.add_parser(
        "alarm_list",
        help="Get alarm list on a google home device using IP address or Name",
    )
    optional_named = parser_alarm_list.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_alarm_list.set_defaults(func=alarm_list_from_parser)

    parser_alarm_volume = subparsers.add_parser(
        "alarm_volume",
        help="Set alarm volume on a google home device using IP address or Name",
    )
    required_named = parser_alarm_volume.add_argument_group("Required named arguments.")
    required_named.add_argument(
        "--volume", help="between 0-1 represents 0-100", default=None
    )
    optional_named = parser_alarm_volume.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_alarm_volume.set_defaults(func=alarm_volume_from_parser)

    parser_alarm_delete = subparsers.add_parser(
        "alarm_delete",
        help="Delete all alarms on a google home device using IP address or Name",
    )
    optional_named = parser_alarm_delete.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_alarm_delete.set_defaults(func=alarm_delete_from_parser)

    parser_bstat = subparsers.add_parser(
        "bstat",
        help="Bluetooth status on a google home device using IP address or Name",
    )
    optional_named = parser_bstat.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_bstat.set_defaults(func=bstat_from_parser)

    parser_bscan = subparsers.add_parser(
        "bscan",
        help="Bluetooth scan for devices on a google home device using IP address or Name",
    )
    optional_named = parser_bscan.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_bscan.set_defaults(func=bscan_from_parser)

    parser_bpaired = subparsers.add_parser(
        "bpaired",
        help="Get Bluetooth paired devices on a google home device using IP address or Name",
    )
    optional_named = parser_bpaired.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_bpaired.set_defaults(func=bpaired_from_parser)

    parser_bdisc = subparsers.add_parser(
        "bdisc",
        help="Change Bluetooth discoverability on a google home device using IP address or Name",
    )
    required_named = parser_bdisc.add_argument_group("Required named arguments.")
    required_named.add_argument(
        "--action", help="enable or disable Bluetooth discoverability", default=None
    )
    optional_named = parser_bdisc.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_bdisc.set_defaults(func=bdisc_from_parser)

    parser_wscan = subparsers.add_parser(
        "wscan", help="Wireless scan on a google home device using IP address or Name"
    )
    optional_named = parser_wscan.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_wscan.set_defaults(func=wscan_from_parser)

    parser_saved_network = subparsers.add_parser(
        "saved_network",
        help="Get saved wifi networks on a google home device using IP address or Name",
    )
    optional_named = parser_saved_network.add_argument_group("Optional named arguments")
    optional_named.add_argument("--ip", help="Google Home IP Address", default=None)
    optional_named.add_argument("--name", help="Google Home Device Name", default=None)
    parser_saved_network.set_defaults(func=saved_network_from_parser)

    args = parser.parse_args()

    try:
        func = args.func
    except AttributeError:
        parser.error("too few arguments")
    func(args)


if __name__ == "__main__":
    main()
