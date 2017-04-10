# FalconGate

A smart gateway to stop hackers, Malware and more...

## Motivation

Cyber attacks are on the raise. Hacker and cyber criminals are continuously improving their methods and building new tools and Malware with the purpose of hacking your network, spying on you and stealing valuable data. Recently a new business model has become popular among hackers: the use of Ransomware to encrypt your data and ask for a ransom to unlock it. These attacks have extended also to the Internet of Things (IoT) devices since many of them are vulnerable by design and hackers can leverage them to compromise other devices in your network or launch DDoS attacks towards other targets. Traditionally securing a network against such attacks has been an expensive item which could be afforded just by medium to large companies. With FalconGate we're aiming to change this and bring "out of the box" security for free to people, small businesses and anyone else in need.

## Features

FalconGate is an open source smart gateway which can protect your home devices against hackers, Malware like Ransomeware and other threats. It detects and alerts on hacker intrusions on your home network as well as other devices misbehaving and attacking targets within your network or in the Internet.

Currently FalconGate is able to:

- Block several types of Malware based on open source blacklists (see detailed list in file [intel-sources.md](intel-sources.md))
- Block Malware using the Tor network
- Detect and report potential Malware DNS requests based on VirusTotal reports
- Detect and report the presence of Malware executables and other components based on VirusTotal reports
- Detect and report Domain Generation Algorithm (DGA) Malware patterns
- Detect and report on Malware spamming activity
- Detect and report on internal and outbound port scans
- Report details of all new devices connected to your network
- Block ads based on open source lists
- Monitor a custom list of personal or family accounts used in online services for public reports of hacking  

## Getting Started

FalconGate was built on top of other open source software so it has multiple dependencies which must be configured correctly for it to work. The fastest way to get FalconGate up and running is to deploy one of the supported system images from our [downloads page](https://github.com/A3sal0n/FalconGate/wiki/Downloads).

### Supported Platforms

Currently FalconGate has been successfully tested and implemented on Raspberry Pi (RPi 2 and 3) and Banana Pi (BPI-M2+) using Raspian Jessie Lite as base OS. You can download the base image for RPi [here](https://downloads.raspberrypi.org/raspbian_lite_latest).

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

### Other dependencies

The devices's malware detection can be enhanced with the utilization of [VirusTotal's personal free API](https://www.virustotal.com/en/documentation/public-api/)

Currently FalconGate uses [have i been pwned](https://haveibeenpwned.com/API/v2) public API to detect whether credentials and/or other data from personal accounts have been stolen by hackers from third party sites.

### Deploying FalconGate

- [From a supported image](https://github.com/A3sal0n/FalconGate/wiki/Deploy_from_image)

- [Install from scratch](https://github.com/A3sal0n/FalconGate/wiki/Install_from_source)

### Public API

FalconGate uses its own cloud based API engine to support the capabilities of the platform. Currently our API provides access to centrally collected lists of malicious IP addresses and domains used by Malware and cyber criminals. All the sources used to collect this information are open source and publicly available.

You can register to get access to our public API [here](http://eepurl.com/cHtpQj). Once you receive your access key you can configure it in FalconGate's webgui to start receiving the updates.

### Limitations

Currently the Raspberry Pi version 2 and 3 have both only one slow ethernet interface (10/100 Mbit). The traffic forwarding in the gateway it's done using only this interface. This has an impact in networks with fast internet connections (e.g. > 50Mb/s). However it's still good enough for the home networks of many people's  and even some small businesses. 

### Collaborators
[easy4MEr](https://github.com/easy4MEr)

### Follow us

You can subscribe to our [newsletter](http://eepurl.com/cvwEYj) to receive news on major developments, new features released, etc.

### Donate

So far we have been running this project with money from our own pockets. We have plans to continue expanding the capabilities of FalconGate but unfortunately many of the things we have in mind will require some additional level of investment. If you like our project or you have found it useful please consider donating some money to support us.

**Paypal:** https://www.paypal.me/FalconGate

**Bitcoin wallet:** 14TdcLb2DYHZmcwqCUWP64v4g1UaTs8yK8

![alt tag](https://github.com/A3sal0n/FalconGate/blob/master/html/images/bitcoin_wallet.png)

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details

