##! Local site policy for FalconGate (Zeek 8 compatible).
##!
##! The installer copies this file to /opt/zeek/share/zeek/site/local.zeek.
##! Script paths follow Zeek 8: no ".bro" suffixes, and scripts removed in
##! Zeek 8 (e.g. tuning/defaults, misc/scan) are not loaded. It is based on the
##! stock Zeek local.zeek plus the three FalconGate-specific settings at the end.

# Log which scripts were loaded during each run.
@load misc/loaded-scripts

# Report capture loss and periodic stats.
@load misc/capture-loss
@load misc/stats

# Detect traceroute being run on the network.
@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
@load frameworks/software/vulnerable
# Detect software changing (e.g. an attacker installing a hacked SSHD).
@load frameworks/software/version-changes

# Signatures to detect cleartext forward and reverse Windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

# Detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software

# Protocol analyzers
@load base/protocols/ssl            # TLS/SSL certificate extraction
@load base/protocols/http           # HTTP logs
@load base/protocols/dns            # DNS query logs
@load base/protocols/smb            # SMB session and file logs
@load base/protocols/ssh            # SSH session logs
@load base/protocols/ftp            # FTP logs
@load base/protocols/smtp           # Email header logs

# Detect DNS results pointing into your local address space that are hosted
# externally (requires Site::local_zones to be defined).
@load protocols/dns/detect-external-names

# Detect various activity in FTP sessions.
@load protocols/ftp/detect

# Asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load policy/protocols/conn/mac-logging

# SSL/TLS certificate validation and reduced certificate logging.
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load policy/protocols/ssl/expiring-certs

# Threat intelligence framework
@load base/frameworks/intel/files

# SSH geo-data, brute-force detection and interesting-hostname logins.
@load protocols/ssh/geo-data
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks (renamed from detect-sqli in Zeek 8).
@load protocols/http/detect-sql-injection

# Enable MD5/SHA1/SHA256 hashing for all files.
@load frameworks/files/hash-all-files

# Check file hashes against Team Cymru's Malware Hash Registry.
@load frameworks/files/detect-MHR

#### FalconGate customizations ####

# Extract interesting files from traffic for inspection.
@load FalconGate/extract-important-files

# Detect port and address scans (replaces misc/scan, removed in Zeek 8).
# Raises Scan::Port_Scan / Scan::Address_Scan notices read by lib/logparser.py.
@load FalconGate/port-scan

# Emit every log as JSON - the FalconGate log parsers (lib/logparser.py) read
# the Zeek logs as JSON, so this is required, not optional.
@load policy/tuning/json-logs

# VMs and many NICs offload checksums, which makes Zeek see "bad" checksums and
# skip analysis. Ignore checksums so detection works on virtual/offloaded NICs.
redef ignore_checksums = T;