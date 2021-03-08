[![PyPI version](https://badge.fury.io/py/ghome.svg)](https://badge.fury.io/py/ghome)
[![Downloads](https://pepy.tech/badge/ghome/month)](https://pepy.tech/project/ghome)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)


# ghome: Simple CLI for Google Home & Mini
This is an application of the google home API Blueprint reported [here](https://github.com/rithvikvibhu/GHLocalApi). While a lot of the end points maybe of interest to quite a few people, I used the ones I use most and I thought would be most useful and created a command line tool for you to search for a Google home mini device and then use this tool to interact with it and perform actions as needed. A large thanks goes to both [rithvikvibhu](https://github.com/rithvikvibhu) for the blueprint and finally to [leikoilja](https://github.com/leikoilja) for excellent work on implementing [glocaltokens](https://github.com/leikoilja/glocaltokens).

## Table of contents
* [Installation](#installation)
* [Getting started](#getting-started)
* [ghome Simple CLI for Earth Engine Uploads](#ghome-simple-cli-for-earth-engine-uploads)
    * [auth](#auth)
    * [device_list](#device_list)
    * [devce_info](#device_info)
    * [reboot](#reboot)
    * [alarm_list](#alarm_list)
    * [alarm_volume](#alarm_volume)
    * [alarm_delete](#alarm_delete)
    * [bluetooth_status](#bluetooth_status)
    * [bluetooth_scan](#bluetooth_scan)
    * [bluetooth_paired](#bluetooth_paired)
    * [bluetooth_discovery](#bluetooth_discovery)
    * [wifi scan](#wifi-scan)
    * [saved_network](#saved_network)

## Installation
This assumes that you have native python & pip installed in your system, you can test this by going to the terminal (or windows command prompt) and trying

```python``` and then ```pip list```

If you get no errors and you have python 3.6 or higher you should be good to go

To install **ghome: Simple CLI for Google Home & Mini** you can install using two methods.

```pip install ghome```

or you can also try

```
git clone https://github.com/samapriya/ghome.git
cd ghome
python setup.py install
```
For Linux use sudo or try ```pip install ghome --user```.

The advantage of having it installed is that ghome can be executed as any command line tool. I recommend installation within a virtual environment. .


## Getting started

As usual, to print help:

```
usage: ghome [-h]
             {auth,device_list,devinfo,reboot,alarm_list,alarm_volume,alarm_delete,bstat,bscan,bpaired,bdisc,wscan,saved_network}
             ...

Simple Google Home Mini Client

positional arguments:
  {auth,device_list,devinfo,reboot,alarm_list,alarm_volume,alarm_delete,bstat,bscan,bpaired,bdisc,wscan,saved_network}
    auth                Auth to get Master Token: Use only once
    device_list         Print device list for Google Home devices
    devinfo             Provides Device Info based on device name or IP
                        address
    reboot              Reboot or Factory Reset a google home device using IP
                        address or Name
    alarm_list          Get alarm list on a google home device using IP
                        address or Name
    alarm_volume        Set alarm volume on a google home device using IP
                        address or Name
    alarm_delete        Delete all alarms on a google home device using IP
                        address or Name
    bstat               Bluetooth status on a google home device using IP
                        address or Name
    bscan               Bluetooth scan for devices on a google home device
                        using IP address or Name
    bpaired             Get Bluetooth paired devices on a google home device
                        using IP address or Name
    bdisc               Change Bluetooth discoverability on a google home
                        device using IP address or Name
    wscan               Wireless scan on a google home device using IP address
                        or Name
    saved_network       Get saved wifi networks on a google home device using
                        IP address or Name

optional arguments:
  -h, --help            show this help message and exit

```

To obtain help for specific functionality, simply call it with _help_ switch, e.g.: `ghome wscan -h`. If you didn't install ghome, then you can run it just by going to *ghome* directory and running `python ghome.py [arguments go here]`

## ghome Simple CLI for Earth Engine Uploads
The tool is based on currently unofficial API blueprint published for the device and is subject to change in the future.

### auth
This tool is originally based on the implementation of glocaltokens from the [gist](https://gist.github.com/rithvikvibhu/952f83ea656c6782fbd0f1645059055d). This should be used only once as suggested on the [glocaltokens site](https://github.com/leikoilja/glocaltokens) and is to avoid Google delinking devices or anything else. The auth tool create a config-file and write a master authentication token which can be used by the tool to then generate local device tokens as they expire every 24 hours.

``` ghome auth ```

### device_list
This tool generates a list of all google home devices connected to your network and prints the name and ip address of each. This is a quick way to check specific name or ip address to use for a device.

``` ghome device_list ```

### device_info
This tool uses device name or ip addrss to get all information available for said device and prints it out as a json object.

```
(venv3) λ ghome devinfo -h
usage: ghome devinfo [-h] [--ip IP] [--name NAME]

optional arguments:
  -h, --help   show this help message and exit

Optional named arguments:
  --ip IP      Google Home IP Address
  --name NAME  Google Home Device Name
```

Simple usage
``` ghome devinfo --ip 192.168.1.10 ```

or
``` ghome devinfo --name "Kitchen Speaker" ```

### reboot
This is a powerful tool since the only current way of rebooting a device is to physically unplug and plug the device back in. This also allows you to do a factory reset so **Use reset with CAUTION**.

```
usage: ghome reboot [-h] [--ip IP]

optional arguments:usage: ghome reboot [-h] [--action ACTION] [--ip IP] [--name NAME]

optional arguments:
  -h, --help       show this help message and exit

Required named arguments.:
  --action ACTION  reboot or reset the device

Optional named arguments:
  --ip IP          Google Home IP Address
  --name NAME      Google Home Device Name
```

Simple usage to reboot
``` ghome reboot --action reboot --ip 192.168.1.10 ```
``` ghome reboot --action reboot --name "Kitchen Speaker" ```

or to factory reset
``` ghome reboot --action reset --ip 192.168.1.10 ```
``` ghome reboot --action reset --name "Kitchen Speaker" ```


### alarm_list
This tool will simply list all alarms currently on your device including date , time and time zone.

```
usage: ghome alarm_list [-h] [--ip IP] [--name NAME]

optional arguments:
  -h, --help   show this help message and exit

Optional named arguments:
  --ip IP      Google Home IP Address
  --name NAME  Google Home Device Name
```

Simple usage
``` ghome alarm_list --ip 192.168.1.10 ```

or
``` ghome alarm_list --name "Kitchen Speaker" ```

### alarm_volume
Set the alarm volume for a device, this only changes the alarm volume and nothing else. Alarm volumes can be set for values 0-1 which represents volume from 0-100% so 0.1 means 10% volume and so on.

```
usage: ghome alarm_volume [-h] [--volume VOLUME] [--ip IP] [--name NAME]

optional arguments:
  -h, --help       show this help message and exit

Required named arguments.:
  --volume VOLUME  between 0-1 represents 0-100

Optional named arguments:
  --ip IP          Google Home IP Address
  --name NAME      Google Home Device Name

```

Simple usage
``` ghome alarm_volume --volume 0.1 --ip 192.168.1.10 ```

or
``` ghome alarm_volume --volume 0.1 --name "Kitchen Speaker" ```

### alarm_delete
Delete all alarms on a google home device based on ip or name.

```
usage: ghome alarm_delete [-h] [--ip IP] [--name NAME]

optional arguments:
  -h, --help   show this help message and exit

Optional named arguments:
  --ip IP      Google Home IP Address
  --name NAME  Google Home Device Name
```

Simple usage
``` ghome alarm_delete --ip 192.168.1.10 ```

or
``` ghome alarm_delete --name "Kitchen Speaker" ```

### bluetooth_status
The bluetooth status prints whether the device discovery is enabled, whether scanning is enabled and whether it is connected to a device.

```
usage: ghome bstat [-h] [--ip IP] [--name NAME]

optional arguments:
  -h, --help   show this help message and exit

Optional named arguments:
  --ip IP      Google Home IP Address
  --name NAME  Google Home Device Name
```

Simple usage
``` ghome bstat --ip 192.168.1.10 ```

or
``` ghome bstat --name "Kitchen Speaker" ```

### bluetooth scan
This prints bluetooth status, including is possible bluetooth device name and mac name

```
usage: ghome bscan [-h] [--ip IP] [--name NAME]

optional arguments:
  -h, --help   show this help message and exit

Optional named arguments:
  --ip IP      Google Home IP Address
  --name NAME  Google Home Device Name

```

Simple usage
``` ghome bscan --ip 192.168.1.10 ```

or
``` ghome bscan --name "Kitchen Speaker" ```


### bluetooth_paired
Check if device is paried via bluetooth to any current device as well as history of all deviced connected, last connected and whether or not they are currently connected.

```
usage: ghome bpaired [-h] [--ip IP] [--name NAME]

optional arguments:
  -h, --help   show this help message and exit

Optional named arguments:
  --ip IP      Google Home IP Address
  --name NAME  Google Home Device Name
```

Simple usage
``` ghome bpaired --ip 192.168.1.10 ```

or
``` ghome bpaired --name "Kitchen Speaker" ```

### bluetooth_discovery
This is to enable or disable bluetooth discovery to allow for pairing as needed. The action can be to enable or disable coupled with the ip or device name.

```
usage: ghome bdisc [-h] [--action ACTION] [--ip IP] [--name NAME]

optional arguments:
  -h, --help       show this help message and exit

Required named arguments.:
  --action ACTION  enable or disable Bluetooth discoverability

Optional named arguments:
  --ip IP          Google Home IP Address
  --name NAME      Google Home Device Name
```

Simple usage
``` ghome bpaired --action enable --ip 192.168.1.10 ```

or
``` ghome bpaired --action enable --name "Kitchen Speaker" ```

* [saved_network](#saved_network)


### wifi scan
Prints the wifi scan results of all available wifi connections and their ssid based on the proximity of the device to other connections. You might want to run this twice, since it may not build the device cache directly.

```
usage: ghome wscan [-h] [--ip IP] [--name NAME]

optional arguments:
  -h, --help   show this help message and exit

Optional named arguments:
  --ip IP      Google Home IP Address
  --name NAME  Google Home Device Name
```

Simple usage
``` ghome wscan --action enable --ip 192.168.1.10 ```

or
``` ghome wscan --action enable --name "Kitchen Speaker" ```

### saved_network
This tool allows you to print any saved network on the device and nothing else it may provide only information on current network being used if there is only a single network it was connected to .

```
usage: ghome saved_network [-h] [--ip IP] [--name NAME]

optional arguments:
  -h, --help   show this help message and exit

Optional named arguments:
  --ip IP      Google Home IP Address
  --name NAME  Google Home Device Name
```

Simple usage
``` ghome saved_network --action enable --ip 192.168.1.10 ```

or
``` ghome saved_network --action enable --name "Kitchen Speaker" ```


## Changelog

### v0.0.2
- Added major revisions to the code to use autheticated device tokens
- Makes use of master token and autogenerates new one every 24 hours
- Device ports are adjusted for authenicated endpoints based on endpoints
- Additional tools were added and overall improvements were made
- Tool supports Python 3 only.
