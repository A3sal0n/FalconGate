This folder contains a collection of scripts that can be used to test some of Falcongate's detection capabilities.

Run these scripts from a device connected to the Falcongate network.

The application compatibility tests can be run with:

```bash
python3.15 -m unittest discover -s tests -p 'test_*.py' -v
```