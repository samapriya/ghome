# ghome: Simple CLI for Google Home & Mini
This is an application of the google home API Blueprint reported [here](https://github.com/rithvikvibhu/GHLocalApi). While a lot of the end points maybe of interest to quite a few people, I used the ones I use most and I thought would be most useful and created a command line tool for you to search for a Google home mini device and then use this tool to interact with it and perform actions as needed.

## Table of contents
* [Installation](#installation)
* [Getting started](#getting-started)
* [ghome Simple CLI for Earth Engine Uploads](#ghome-simple-cli-for-earth-engine-uploads)
    * [list](#list)
    * [reboot](#reboot)
    * [alarm](#alarm)
    * [do not disturb](#do-not-disturb)
    * [bluetooth status](#bluetooth-status)
    * [bluetooth scan](#bluetooth-scan)
    * [bluetooth paired](#bluetooth-paired)
    * [bluetooth discovery](#bluetooth-discovery)
    * [wifi scan](#wifi-scan)

## Installation
This assumes that you have native python & pip installed in your system, you can test this by going to the terminal (or windows command prompt) and trying

```python``` and then ```pip list```

If you get no errors and you have python 2.7.14 or higher you should be good to go. Please note that I have tested this only on python 2.7.15, but it should run on Python 3.

To install **ghome: Simple CLI for Google Home & Mini** you can install using two methods.

```pip install ghome```

or you can also try

```
git clone https://github.com/samapriya/ghome.git
cd ghome
python setup.py install
```
For Linux use sudo or try ```pip install ghome --user```.

Installation is an optional step; the application can also be run directly by executing ghome.py script. The advantage of having it installed is that ghome can be executed as any command line tool. I recommend installation within a virtual environment. If you don't want to install, browse into the ghome folder and try ```python ghome.py``` to get to the same result.


## Getting started

As usual, to print help:

```
usage: ghome [-h] {list,reboot,alarm,dnd,bstat,bscan,bpair,bdisc,wscan} ...

Simple Google Home Mini Client

positional arguments:
  {list,reboot,alarm,dnd,bstat,bscan,bpair,bdisc,wscan}
    list                Lists all google home mini devices & IP address
    reboot              Reboot a google home mini using IP address
    alarm               Print out the current alarms setup on your google home
                        mini
    dnd                 Enable or disable <Do not Disturb mode> for a google
                        home mini using IP address
    bstat               Print current bluetooth status for a google home mini
                        using IP address
    bscan               Scan for Bluetooth devices near a google home mini
                        using IP address
    bpair               Print current paired bluetooth devices for a google
                        home mini using IP address
    bdisc               Enable or disable bluetooth discovery for a google
                        home mini using IP address
    wscan               Scan for Wifi networks near a google home mini using
                        IP address

optional arguments:
  -h, --help            show this help message and exit
```

To obtain help for specific functionality, simply call it with _help_ switch, e.g.: `ghome wscan -h`. If you didn't install ghome, then you can run it just by going to *ghome* directory and running `python ghome.py [arguments go here]`

## ghome Simple CLI for Earth Engine Uploads
The tool is based on curret unofficial API blueprint published for the device and is subject to change in the future.

### list
**This is a key step since it lists all google home mini devices in your wifi, it used nmap to identify said devices. You can avoid this tool by using a third party tool like [Fing] to identify your google home devices.Usage is simply

``` ghome list```

### reboot
Just a simple tool to reboot your google home device quickly.

```
usage: ghome reboot [-h] [--ip IP]

optional arguments:
  -h, --help  show this help message and exit

Required named arguments.:
  --ip IP     Use "ip" for Google Home Mini device
```

### alarm
This tool will simply list all alarms currently on your device including date , time and time zone.

```
usage: ghome alarm [-h] [--ip IP]

optional arguments:
  -h, --help  show this help message and exit

Required named arguments.:
  --ip IP     Use "ip" for Google Home Mini device
```

### do not disturb
Enable or disable do not disturb mode on the Google home mini.

```
usage: ghome dnd [-h] [--ip IP] [--action ACTION]

optional arguments:
  -h, --help       show this help message and exit

Required named arguments.:
  --ip IP          Use "ip" for Google Home Mini device
  --action ACTION  enable|disable do not disturb mode

```

### bluetooth status
The bluetooth status prints whether the device discovery is enabled,whether scanning is enabled and whether it is connected to a device.

```
usage: ghome bstat [-h] [--ip IP]

optional arguments:
  -h, --help  show this help message and exit

Required named arguments.:
  --ip IP     Use "ip" for Google Home Mini device
```

### bluetooth scan
This prints bluetooth status, including is possible bluetooth device name and mac name

```
usage: ghome bstat [-h] [--ip IP]

optional arguments:
  -h, --help  show this help message and exit

Required named arguments.:
  --ip IP     Use "ip" for Google Home Mini device

```

### bluetooth paired
Check if device is paried via bluetooth to any current device as well as history of all deviced connected, last connected and whether or not they are currently connected.

```
usage: ghome bpair [-h] [--ip IP]

optional arguments:
  -h, --help  show this help message and exit

Required named arguments.:
  --ip IP     Use "ip" for Google Home Mini device

```

### bluetooth discovery
This is to enable or disable bluetooth discovery to allow for pairing as needed. The action can be enable or disable coupled with the ip.

```
usage: ghome bdisc [-h] [--ip IP] [--action ACTION]

optional arguments:
  -h, --help       show this help message and exit

Required named arguments.:
  --ip IP          Use "ip" for Google Home Mini device
  --action ACTION  enable|disable bluetooth discovery
```

### wifi scan
Prints the wifi scan results of all available wifi connections and their ssid based on the proximity of the device to other connections. You might want to run this twice, since it may not build the device cache directly.

```
usage: ghome wscan [-h] [--ip IP]

optional arguments:
  -h, --help  show this help message and exit

Required named arguments.:
  --ip IP     Use "ip" for Google Home Mini device

```


