# wifi-scanner
WifiScanner is a tool to help detect nearby Wi-Fi devices. It scans every frequency between
2401 - 2495 MHz and detects beacon frames from AP's and probe request from clients.
Every minute the results are pushed into a [mosquitto](https://github.com/eclipse/mosquitto) 
queue using the MQTT protocol.   

# ToC
* [Introduction](#Introduction)
* [Setup](#Setup)
* [Usage](#Usage)

# Introduction
This scanner aims to be used with a GUI to display the devices. It can also be used without 
 one but then you should deactivate the message pushing into the queue. The GUI developed 
 as a PoC can be found [here](https://github.com/offsec1/wifi-device-monitor).

# Setup
First you need to set your wifi card into monitor mode. This can be done 
using [Airmon-ng](https://www.aircrack-ng.org/doku.php?id=airmon-ng).

```
$ sudo airmon-ng start wlan0
```

# Usage
In order to run the application, you´ll need python with pip installed.
Since this is some low level stuff you'd probably need to run all this as root.

```
$ git clone https://github.com/offsec1/wifi-scanner.git
$ cd wifi-scanner
# install requirements
$ pip3 install -r requirements.txt
# running wifi scanner
$ python3 app.py wlan0mon
```