# FalconGate

A smart gateway to stop hackers, Malware and more...

## Motivation

Cyber attacks are on the raise. Hacker and cyber criminals are continuously improving their methods and building new tools and Malware with the purpose of hacking your network, spying on you and stealing valuable data. Recently a new business model has become popular among hackers: the use of Ransomware to encrypt your data and ask for a ransom to unlock it. These attacks have extended also to the Internet of Things (IoT) devices since many of them are vulnerable by design and hackers can leverage them to compromise other devices in your network or launch DDoS attacks towards other targets. Traditionally securing a network against such attacks has been an expensive item which could be afforded just by medium to large companies. With FalconGate we're aiming to change this and bring "out of the box" security for free to people, small businesses and anyone else in need.

FalconGate it's an open source smart gateway which can protect your home devices against hackers, Malware like Ransomeware and other threats. It detects and alerts on hacker intrusions on your home network as well as other devices misbehaving and attacking targets within your network or in the Internet.

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

It depends also on several Python modules (see requirements.txt file for details)

### Installing

Follow the steps below to configure your device and install FalconGate from its repository.

- Download and install the OS image to your Raspberry Pi or Banana Pi device

This is well documented in multiple sources out there.

- Connect to your device via SSH

- Install Git if you don't have it yet
<code>
$ sudo apt-get update
$ sudo apt-get install git
</code>
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
Now you can go for a walk, a coffee or any other beverage of your like because the installation takes some time. The script will print the progress to the console.

The script should finish without issues if you're using the supported platforms. If you're attempting to install FalconGate experimentally to a new hardware platform/OS and you get some errors during the installation you could try to correct the issues manually following the steps listed in the installation script.  

- Login to you router and disable it's DHCP server function

FalconGate was designed to work connected to a router over ethernet. It does not replaces the functions of your router. Instead it becomes a layer of security between your devices and your router. Disabling your router's DHCP allows FalconGate to become the new gateway for all the devices connected to the same router in your VLAN.

- Reboot your device to apply all the configuration changes

### Deployment

Add additional notes about how to deploy this on a live system

### Limitations

## Authors

* **Leonardo Mokarzel Falcon** - *Initial work*

See also the full list of [contributors](https://github.com/A3sal0n/FalconGate/graphs/contributors)

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details

## Acknowledgments


