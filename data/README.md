# Bundled data

## default_creds.csv

A seed list of default `login:password` combinations used by the Hydra
default-credentials assessment (`lib/offensive.py`). At runtime Falcongate
refreshes this list about once a week from the upstream SecLists lists
configured under `[api_urls] fg_intel_creds` in `config.ini`, writing the
merged result to `/tmp/default_creds.csv`. This bundled copy is the fallback
used on first run and whenever the remote lists cannot be downloaded.

### Source and format

Built by concatenating and de-duplicating these SecLists lists:

- `Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt`
- `Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt`
- `Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt`
- `Passwords/Default-Credentials/vnc-betterdefaultpasslist.txt`
- `Passwords/Default-Credentials/windows-betterdefaultpasslist.txt`

Each line is `login:password` (split on the first colon). Password-only
entries, such as the VNC list, are stored with an empty login (`:password`)
so they remain valid for Hydra's `-C` option.

To rebuild the seed, download the files above and merge them with the same
normalisation used at runtime (`DownloadIntel.retrieve_default_creds` in
`lib/intel.py`): trim whitespace, drop blank and `#` comment lines, prefix a
colon to any colon-less line, and drop duplicates.

## detect_domains.csv.gz

A gzipped, deduplicated map of domains to a threat category, one `domain,category`
per line. Used for **detection/alerting only** — these domains are **never**
blackholed (unlike the `[blacklists_domain]` feeds). At runtime `lib/intel.py`
(`DownloadIntel.refresh_detect_domains`) refreshes the map about once a week from
the upstream blocklistproject plain-domain lists and holds it in memory
(`settings.detect_domains`); a DNS lookup of a listed domain flags that lookup and
raises a "bad domain" alert tagged with its category. This bundled gzip is the
offline fallback used when the upstream lists cannot be downloaded.

### Source and format

Built from the `alt-version/<category>-nl.txt` lists of the blocklistproject
repository, for these categories (processed worst-first, so a domain appearing in
several lists keeps its most severe category):

`malware, ransomware, phishing, fraud, scam, abuse, crypto, drugs, gambling, vaping`

To rebuild: download each `<category>-nl.txt`, drop blank/`#` lines, emit
`domain,category`, dedupe by domain keeping the first (worst-first) occurrence,
and gzip.

## Attribution

The detection domain lists are from the **blocklistproject** project
(https://github.com/blocklistproject/Lists), released into the public domain under
the **Unlicense**:

```
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or distribute this
software, either in source code form or as a compiled binary, for any purpose,
commercial or non-commercial, and by any means.

For more information, please refer to <https://unlicense.org/>
```

The credential lists are from the SecLists project
(https://github.com/danielmiessler/SecLists), redistributed here under its
MIT License:

```
MIT License

Copyright (c) 2018 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
