# Bundled data

## default_creds.csv

A seed list of default `login:password` combinations used by the Hydra
default-credentials assessment (`lib/offensive.py`). At runtime FalconGate
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

## Attribution

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
