__copyright__ = """

    Copyright 2019 Samapriya Roy

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

import argparse,os,sys,platform,requests,time,json
import nmap
import socket
os.chdir(os.path.dirname(os.path.realpath(__file__)))
from os.path import expanduser
lpath=os.path.dirname(os.path.realpath(__file__))
sys.path.append(lpath)

# Find google home devices
def ghome(result):
    # Using sockets to get iprange
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    iprange = '.'.join(s.getsockname()[0].split('.')[0:3])
    s.close()

    # Using nmap to get device list
    nm = nmap.PortScanner()
    scanner = nm.scan(iprange + '.*', '22-25')
    l = []
    for stuff, value in scanner['scan'].items():
        try:
            if str(value['addresses']['mac']).startswith('E4'):
                l.append(str(value['addresses']['ipv4']))
        except Exception as e:
            pass
    if result is not None and result == 'verbose':
        for stuff in l:
            url = "http://"+str(stuff)+":8008/setup/eureka_info"
            querystring = {"{options}":"detail","{params}":"version,audio,name,build_info,detail,device_info,net,wifi,setup,settings,opt_in,opencast,multizone,proxy,night_mode_params,user_eq,room_equalizer","options":"detail"}

            payload = "{\r\n  \"connect\": true\r\n}"
            headers = {
                'Content-Type': "application/json",
                'Cache-Control': "no-cache",
                }

            response = requests.request("GET", url, data=payload, headers=headers, params=querystring)

            resp=response.json()
            print('Device Name: '+str(resp['name']))
            print('Device Locale: '+resp['locale'])
            print('Device build_version: '+str(resp['build_version']))
            print('Device timezone: '+str(resp['timezone']))
            print('Device model_name: '+str(resp['detail']['model_name']))
            print('Device manufacturer: '+str(resp['detail']['manufacturer']))
            print('Device cast_build_revision: '+str(resp['cast_build_revision']))
            print('Device Mac address: '+str(resp['mac_address']))
            print('Device IPv4 address: '+str(resp['ip_address']))
            print('Wifi Name: '+str(resp['ssid']))
            #print('Device uptime: '+str(resp['uptime']))
            print('')
    else:
        for stuff in l:
            url = "http://"+str(stuff)+":8008/setup/eureka_info"
            querystring = {"{options}":"detail","{params}":"version,audio,name,build_info,detail,device_info,net,wifi,setup,settings,opt_in,opencast,multizone,proxy,night_mode_params,user_eq,room_equalizer","options":"detail"}

            payload = "{\r\n  \"connect\": true\r\n}"
            headers = {
                'Content-Type': "application/json",
                'Cache-Control': "no-cache",
                }

            response = requests.request("GET", url, data=payload, headers=headers, params=querystring)

            resp=response.json()
            print('Device Name: '+str(resp['name'])+' : '+str(resp['ip_address']))

def ghome_from_parser(args):
    ghome(result=args.format)

#Get all alarms set on the devices
def alarm(ip):
  url = "http://"+str(ip)+":8008/setup/assistant/alarms"
  try:
    response = requests.request("GET", url).json()
    if len(response['alarm']) !=0:
      for items in response['alarm']:
          print('Alarm set for: '+str(time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime(float(items['fire_time']/1000)))))
    else:
      print('No alarms currently set')
  except Exception as e:
    print(e)

def alarm_from_parser(args):
    alarm(ip=args.ip)

#Get bluetooth status
def bstat(ip):
  url = "http://"+str(ip)+":8008/setup/bluetooth/status"
  try:
    response = requests.request("GET", url).json()
    for key, value in response.items():
        print key, value
  except Exception as e:
    print(e)

def bstat_from_parser(args):
    bstat(ip=args.ip)

#Get paired devices
def bpair(ip):
  url = "http://"+str(ip)+":8008/setup/bluetooth/get_bonded"
  try:
    response = requests.request("GET", url).json()
    for item in response:
        print('Device Name: '+str(item['name']))
        print('Item currently connected: '+str(item['connected']))
        print('Last connected: '+str(time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime(float(item['last_connect_date']/1000)))))
        print('')
  except Exception as e:
    print(e)

def bpair_from_parser(args):
    bpair(ip=args.ip)

#Get paired devices
def bscan(ip):
  scan_url = "http://"+str(ip)+":8008/setup/bluetooth/scan"
  result_url="http://"+str(ip)+":8008/setup/bluetooth/scan_results"
  payload='{"enable": true,"clear_results": false,"timeout": 60}'
  headers = {'Content-Type': "application/json"}
  try:
    response = requests.request("POST", scan_url, data=payload, headers=headers)
    if response.status_code==200:
        print('\n'+'Scan for Bluetooth devices succeeded')
        r = requests.request("GET", result_url).json()
        for items in r:
            if not len(items['name'])==0:
                print(str(items['name']+' with mac id: '+str(items['mac_address'])))
            else:
                print('Unknown device with mac id: '+str(items['mac_address']))
        #print(response['name'])
  except Exception as e:
    print(e)

def bscan_from_parser(args):
    bscan(ip=args.ip)

# Bluetooth discovery enable or disable
def bdisc(ip,action):
  if action=="enable":
    payload = '{"enable_discovery": true}'
  if action=="disable":
    payload = '{"enable_discovery": false}'
  url = "http://"+str(ip)+":8008/setup/bluetooth/discovery"
  headers = {
      'Content-Type': "application/json",
      'Cache-Control': "no-cache",
      }
  try:
    response = requests.request("POST", url, data=payload, headers=headers)
    if response.status_code==200:
      print("Bluetooth Discovery: "+str(action)+"d")
    else:
      print("Bluetooth Discovery: "+str(action)+"d failed with error: "+str(response.status_code))
  except Exception as e:
    print(e)

def bdisc_from_parser(args):
    bdisc(ip=args.ip,action=args.action)

# Reboot device
def reboot(ip):
  url = "http://"+str(ip)+":8008/setup/reboot"
  headers = {
      'Content-Type': "application/json",
      'Cache-Control': "no-cache",
      }
  payload={"params": "now"}
  try:
    response = requests.request("POST", url, data=payload, headers=headers)
    if response.status_code==200:
      print("Device Rebooting")
    else:
      print("Device reboot failed with error: "+str(response.status_code))
  except Exception as e:
    print(e)

def reboot_from_parser(args):
    reboot(ip=args.ip)

# DND device
def dnd(ip,action):
  url = "http://"+str(ip)+":8008/setup/assistant/notifications"
  headers = {
      'Content-Type': "application/json",
      'Cache-Control': "no-cache",
      }
  if action=="enable":
    payload='{"notifications_enabled": true}'
  if action=="disable":
    payload='{"notifications_enabled": false}'

  try:
    response = requests.request("POST", url, data=payload, headers=headers)
    if response.status_code==200:
      r=response.json()
      print("Notification status: "+str(action)+"d")
    else:
      print("DND action failed with action code : "+str(response.status_code))
  except Exception as e:
    print(e)

def dnd_from_parser(args):
    dnd(ip=args.ip,action=args.action)

#Wifi scan
def wscan(ip):
  scan_url = "http://"+str(ip)+":8008/setup/scan_wifi"
  result_url="http://"+str(ip)+":8008/setup/scan_results"
  headers = {'Content-Type': "application/json"}
  try:
    response = requests.request("POST", scan_url, headers=headers)
    if response.status_code==200:
        print('\n'+'Scan for Wifi succeeded')
        r = requests.request("GET", result_url).json()
        for items in r:
            print('Wifi Name or SSID: '+str(items['ssid']))
        #print(response['name'])
  except Exception as e:
    print(e)

def wscan_from_parser(args):
    wscan(ip=args.ip)

spacing="                               "

def main(args=None):
    parser = argparse.ArgumentParser(description='Simple Google Home Mini Client')

    subparsers = parser.add_subparsers()

    parser_ghome = subparsers.add_parser('list', help='Lists all google home mini devices & IP address')
    optional_named = parser_ghome.add_argument_group('Optional named arguments')
    optional_named.add_argument('--format', help='User "verbose" to get details', default=None)
    parser_ghome.set_defaults(func=ghome_from_parser)

    parser_reboot = subparsers.add_parser('reboot', help='Reboot a google home mini using IP address')
    required_named = parser_reboot.add_argument_group('Required named arguments.')
    required_named.add_argument('--ip', help='Use "ip" for Google Home Mini device', default=None)
    parser_reboot.set_defaults(func=reboot_from_parser)

    parser_alarm = subparsers.add_parser('alarm', help='Print out the current alarms setup on your google home mini')
    required_named = parser_alarm.add_argument_group('Required named arguments.')
    required_named.add_argument('--ip', help='Use "ip" for Google Home Mini device', default=None)
    parser_alarm.set_defaults(func=alarm_from_parser)

    parser_dnd = subparsers.add_parser('dnd', help='Enable or disable <Do not Disturb mode> for a google home mini using IP address')
    required_named = parser_dnd.add_argument_group('Required named arguments.')
    required_named.add_argument('--ip', help='Use "ip" for Google Home Mini device', default=None)
    required_named.add_argument('--action', help='enable|disable do not disturb mode', default=None)
    parser_dnd.set_defaults(func=dnd_from_parser)

    parser_bstat = subparsers.add_parser('bstat', help='Print current bluetooth status for a google home mini using IP address')
    required_named = parser_bstat.add_argument_group('Required named arguments.')
    required_named.add_argument('--ip', help='Use "ip" for Google Home Mini device', default=None)
    parser_bstat.set_defaults(func=bstat_from_parser)

    parser_bscan = subparsers.add_parser('bscan', help='Scan for Bluetooth devices near a google home mini using IP address')
    required_named = parser_bscan.add_argument_group('Required named arguments.')
    required_named.add_argument('--ip', help='Use "ip" for Google Home Mini device', default=None)
    parser_bscan.set_defaults(func=bscan_from_parser)

    parser_bpair = subparsers.add_parser('bpair', help='Print current paired bluetooth devices for a google home mini using IP address')
    required_named = parser_bpair.add_argument_group('Required named arguments.')
    required_named.add_argument('--ip', help='Use "ip" for Google Home Mini device', default=None)
    parser_bpair.set_defaults(func=bpair_from_parser)

    parser_bdisc = subparsers.add_parser('bdisc', help='Enable or disable bluetooth discovery for a google home mini using IP address')
    required_named = parser_bdisc.add_argument_group('Required named arguments.')
    required_named.add_argument('--ip', help='Use "ip" for Google Home Mini device', default=None)
    required_named.add_argument('--action', help='enable|disable bluetooth discovery', default=None)
    parser_bdisc.set_defaults(func=bdisc_from_parser)

    parser_wscan = subparsers.add_parser('wscan', help='Scan for Wifi networks near a google home mini using IP address')
    required_named = parser_wscan.add_argument_group('Required named arguments.')
    required_named.add_argument('--ip', help='Use "ip" for Google Home Mini device', default=None)
    parser_wscan.set_defaults(func=wscan_from_parser)

    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()
