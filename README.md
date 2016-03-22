# PcapParser
A simple tool which can parse pcap files. It is created for offline ctf.
# Usage
pcapparse.py [-h] [-v] [-s string] [-p PORT] [-i IP] pcapfile

positional arguments:
  pcapfile              Specify the pcap file to parse

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -s string, --search string
                        only display stream containing the string
  -p PORT, --port PORT  specify the port bound to the web service(default 80)
  -i IP, --ip IP        spcify the ip address which you think is evil and may
                        steal your flag
