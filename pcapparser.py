#!/usr/bin/python
import argparse
import dpkt
import urllib

DEBUG = False

def dictappend(d, k, v):
    if k in d:
        d[k] += v
    else:
        d[k] = v

def ipparse(ipstr):
    ip = map(ord, ipstr)
    assert len(ip) == 4
    return '{}.{}.{}.{}'.format(ip[0], ip[1], ip[2], ip[3])

def show(enermy, httplist):
    httpdirt = {}
    for seq, http in httplist:
        httpdirt[seq] = http
    for seq in sorted(httpdirt.keys()):
        http = httpdirt[seq]
        print '*******************************************************************'
        if type(http) == dpkt.http.Request:
            print '{} ==> YOU\n'.format(enermy)
            print '{} {}'.format(http.method, urllib.unquote_plus(http.uri))

        if type(http) == dpkt.http.Response:
            print 'YOU ==> {}\n'.format(enermy)
            print '{} {}'.format(http.status, http.reason)

        if args.verbose:
            header = http.headers
            for i in header:
                print '{}: {}'.format(i, header[i])
        print '\n'
        print repr(urllib.unquote_plus(http.body))
        print '\n\n*******************************************************************'


parser = argparse.ArgumentParser(description='Pcap parser for ctf')
parser.add_argument('pcapfile', type=file,
                    help='Specify the pcap file to parse')
parser.add_argument('-v', '--verbose', action='store_true',
                    help='increase output verbosity')
parser.add_argument('-s', '--search', metavar='string',
                    help='only display stream containing the string')
parser.add_argument('-p', '--port', type=int, default=80,
                    help='specify the port bound to the web service(default 80)')
parser.add_argument('-i', '--ip', help='spcify the ip address which you think is evil and may steal your flag')
args = parser.parse_args()

reqtmp = ''
restmp = ''
httppool = {}
pcap = dpkt.pcap.Reader(args.pcapfile)
for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue

        tcp = ip.data
        if tcp.dport == args.port and len(tcp.data) > 0:
            source = (ip.src, tcp.sport)
            reqtmp += tcp.data
            try:
                req = dpkt.http.Request(reqtmp)
                if DEBUG:
                    print repr(req)
                if ((args.search in restmp) if args.search else True):
                    dictappend(httppool, source, [(tcp.seq, req)])
                reqtmp = ''
            except dpkt.UnpackError as e:
                if DEBUG:
                    print '{}:{}'.format(ipparse(source[0]), source[1]), 'length of segment: {}'.format(len(reqtmp))
                    print e
                if reqtmp[:3] != 'GET' and reqtmp[:4] != 'POST':
                    reqtmp = ''   # The data in this TCP stream is not http!

        if tcp.sport == args.port and len(tcp.data) > 0:
            destination = (ip.dst, tcp.dport)
            restmp += tcp.data
            try:
                res = dpkt.http.Response(restmp)
                if DEBUG:
                    print repr(res)
                if ((args.search in restmp) if args.search else True):
                    dictappend(httppool, destination, [(tcp.seq, res)])
                restmp = ''
            except dpkt.UnpackError as e:
                if DEBUG:
                    print '{}:{}'.format(ipparse(destination[0]), destination[1]), 'length of segment: {}'.format(len(restmp))
                    print e
                if restmp[:4] != 'HTTP':
                    restmp = ''   # The data in this TCP stream is not http!

for ip, port in httppool:
    if args.ip and ip != args.ip:
        continue
    show('{}:{}'.format(ipparse(ip), port), httppool[(ip, port)])
