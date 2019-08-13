# Falcongate

An advanced cybersecurity platform to stop Malware, Ransomware, detect cyber attacks and more...

## Motivation

Cyber attacks are on the raise and the cyber criminals are continuously improving their tactics and developing new tools and Malware to achieve their goals of breaching their targets, spying, stealing valuable data and cause destructive damage to assets. In recent years a new business model has become popular among cyber criminals: the use of Ransomware to encrypt personal or company data and ask for a ransom to unlock it. These attacks are currently also targeting the Internet of Things (IoT) devices since many of them are vulnerable by design and criminals can leverage them to compromise other devices in their target network or launch DDoS attacks towards other targets. Traditionally securing a network against such attacks has been an expensive activity which could be afforded just by medium to large companies. With Falcongate we're aiming to change this and bring "out of the box" security for free to common people, small businesses and anyone else in need.

## Features

Falcongate is an open source platform which can protect your home devices against hackers, Malware like Ransomeware and other threats. It detects and alerts on hacker intrusions on your home network as well as other devices misbehaving and attacking targets within your network or in the Internet.

Currently Falcongate is able to:

- Block several types of Malware based on our free Threat Intelligence feeds
- Block Malware using the Tor network
- Detect and report potential Malware DNS requests based on VirusTotal reports
- Detect and report the presence of Malware executables and other components based on VirusTotal reports
- Detect and report Domain Generation Algorithm (DGA) Malware patterns
- Detect and report on Malware spamming activity
- Detect and report suspicious port scan and tracerouting activity on the network
- Report details of all new devices connected to the network
- Block ads based on open source lists
- Monitor a custom list of personal or family accounts used in online services for public reports of hacking
- Encrypt the DNS traffic to protect all devices against DNS spoofing and stop your ISP or attackers from spying on DNS requests (see https://dnscrypt.org/)
- Discover and report open ports on your home devices
- Detect and alert on active default vendor accounts in all devices in your home network
  - Protocols currently supported:
    - SSH
    - FTP
    - Telnet
    - RDP
    - SMB
    - VNC
    

## Getting Started

Falcongate was built on top of other open source software so it has multiple dependencies which must be configured correctly for it to work.

### Supported Operating Systems

Currently Falcongate fully supports only Ubuntu 18.04


### Prerequisites

Falcongate has a number of software dependencies:

- Zeek
- Python 3.6.8
- Nginx
- Dnsmasq
- Exim
- PHP
- dnscrypt-proxy
- Nmap

### Other dependencies

The devices's malware detection can be enhanced with the utilization of [VirusTotal's personal free API](https://www.virustotal.com/en/documentation/public-api/)

Currently Falcongate uses [have i been pwned](https://haveibeenpwned.com/API/v2) public API to detect whether credentials and/or other data from personal accounts have been stolen by hackers from third party sites.

### Installing Falcongate

- [Install from source on Ubuntu 18.04](https://github.com/A3sal0n/FalconGate/wiki/Install-from-source)


### Collaborators
[easy4MEr](https://github.com/easy4MEr)

### Follow us

You can subscribe to our [newsletter](http://eepurl.com/cvwEYj) to receive news on major developments, new features released, etc.

### Donate

If you like our project or you have found it useful please consider donating some money to support us.

**Paypal:** https://www.paypal.me/FalconGate

**Bitcoin wallet:** 14TdcLb2DYHZmcwqCUWP64v4g1UaTs8yK8

![alt tag](https://github.com/A3sal0n/FalconGate/blob/master/html/images/bitcoin_wallet.png)

## License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details

