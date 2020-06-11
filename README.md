# wifi-scanner

# ToC
* [Introduction](#Introduction)
* [Setup](#Setup)
* [Usage](#Usage)
* [References](#References)

# Introduction
This is a small wifi scanner

# Setup
The project contains 1 python service for now

# Usage
First you need to set your wifi card into monitor mode. Link Tutorial on how to do so.
For running on a resperry pi you need this:
```
sudo apt-get install libatlas-base-dev
```
In order to run the application, you´ll need python with pip installed.
Since this is some low level stuff you'd probably need to run all this as root.

```
git clone https://github.com/offsec1/wifi-scanner.git
cd wifi-scanner
# install requirements
pip3 install -r requirements.txt
# running wifi scanner
python3 app.py wlan0mon
```

# References
