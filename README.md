# FalconGate

A smart gateway to stop hackers, Malware and more...

## Motivation

Cyber attacks are on the raise. Hacker and cyber criminals are continuously improving their methods and building new tools and Malware with the purpose of hacking your network, spying on you and stealing valuable data. Recently a new business model has become popular among hackers: the use of Ransomware to encrypt your data and ask for a ransom to unlock it. These attacks have extended also to the Internet of Things (IoT) devices since many of them are vulnerable by design and hackers can leverage them to compromise other devices in your network or launch DDoS attacks towards other targets. Traditionally securing a network against such attacks has been an expensive item which could be afforded just by medium to large companies. With FalconGate we're aiming to change this and bring "out of the box" security for free to people, small businesses and anyone else in need.

## Features

FalconGate it's an open source smart gateway which can protect your home devices against hackers, Malware like Ransomeware and other threats. It detects and alerts on hacker intrusions on your home network as well as other devices misbehaving and attacking targets within your network or in the Internet.

Currently FalconGate it's able to:

- Block several types of Malware based on open source blacklists (see detailed list in file [intel-sources.md](intel-sources.md))
- Block Malware using the Tor network
- Detect and report potential Malware DNS requests based on VirusTotal reports
- Detect and report the presence of Malware executables and other components based on VirusTotal reports
- Detect and report Domain Generation Algorithm (DGA) Malware patterns
- Detect and report on Malware spamming activity
- Detect and report on internal and outbound port scans
- Report details of all new devices connected to your network
- Block ads based on open source lists
- Monitor a custom list of personal or family accounts used in online services for reports of hacking and alerts if any hit was found  

## Getting Started

FalconGate was built on top of other open source software so it has multiple dependencies which must be configured correctly for it to work. The fastest way to get FalconGate up and running it's to use the supplied installation script "install.py" to deploy and configure the framework in your own Raspberry Pi or Banana Pi. This script tries to "guess" your network configuration, installs all the dependencies and configures them. The installation usually takes a while because the installation script compiles Bro IDS from it's source to ensure all the latest features are available.

### Supported Platforms

Currently FalconGate has been successfully tested and implemented on Raspberry Pi (RPi 2 model B) and Banana Pi (BPI-M2+) using Raspian Jessie Lite as base image.

[Jessie Lite for RPi](https://downloads.raspberrypi.org/raspbian_lite_latest)

[Jessie Lite for BPi](https://drive.google.com/file/d/0B_YnvHgh2rwjdWp0bXRheHNJM1E/view?usp=sharing)

It should be compatible with other Debian ARM images as well but this has not been tested yet.

### Prerequisites

FalconGate has a number of software dependencies:

- Bro IDS
- Python 2.7
- Nginx
- Dnsmasq
- Exim
- PHP

It depends also on several Python modules (see [requirements.txt](requirements.txt) file for details)

### Installing FalconGate

Follow the steps below to configure your device and install FalconGate from this repository.

- Download and install the OS image to your Raspberry Pi or Banana Pi device

This is well documented in multiple sources out there.

- Connect to your device via SSH
```
$ ssh pi@<IP assigned to your RPi>
```
- Install Git if you don't have it yet
```
$ sudo apt-get update
$ sudo apt-get install git
```
- Clone FalconGate's repository to a local folder
```
$ cd /opt
$ sudo git clone https://github.com/A3sal0n/FalconGate.git
```
- Run the installation script inside FalconGate's folder
```
$ cd FalconGate/
$ sudo python install.py
```
Now you can go for a walk and prepare a coffee or any other beverage of your choice because the installation takes some time. The script will print the progress to the console.

The script should finish without issues if you're using the supported platforms. If you're attempting to install FalconGate experimentally to a new hardware platform/OS and you get some errors during the installation you could try to correct the issues manually and continue to execute the steps listed in the installation script.

- Login to your router and disable it's DHCP server function

FalconGate was designed to work connected to a router over ethernet. It does not replaces the functions of your router. Instead it becomes a layer of security between your devices and your router. Disabling your router's DHCP allows FalconGate to become the new gateway for all the devices connected to the same router in your VLAN.

- Reboot your device to apply all the configuration changes

- Login to FalconGate's web app and configure the email address(es) to be used as recipients for alerts and your VirusTotal API key
```
https://[FalconGate IP address]
Username: admin
Password: falcongate
```
*Change the default password after the first logon to the application*

- Navigate to the "Configuration" page and fill in the correct fields

This configuration it's not mandatory but highly desired if you want to unleash FalconGate's full power.
In order to obtain a free VirusTotal API key you must register at (https://www.virustotal.com/).

### Deployment

Some important considerations to keep in mind when deploying FalconGate to a real environment: home or production network.

- Change the default SSH password in your Raspberry Pi or Banana Pi devices
- Regenerate the openssh-server certificates for SSH encryption

### Limitations

Currently the RPi 2 model B and the Banana Pi M2+ have both a single ethernet interface so the traffic forwarding in the gateway it's done using this single interface. This has an impact in networks with fast Internet connection (e.g. > 50Mb/s). However it's still good enough for the home networks of many people's  and even some small businesses. 

### Collaborators
[easy4MEr](https://github.com/easy4MEr)

### Follow us

You can subscribe to our [newsletter](http://eepurl.com/cvwEYj) to receive news on major developments, new features released, etc.

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details

