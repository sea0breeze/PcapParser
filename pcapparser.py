#!/usr/bin/python
import argparse
import dpkt
import urllib
import gzip
import StringIO

DEBUG = False

def gzdecode(data) :
    compressedstream = StringIO.StringIO(data)
    gziper = gzip.GzipFile(fileobj=compressedstream)
    data2 = gziper.read()
    return data2

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
    #return
    httpdirt = {}
    for seq, http in httplist:
        httpdirt[seq] = http
    for seq in sorted(httpdirt.keys()):
        print seq
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
        if http.body != None:        # Avoid error when body is empty.
            if http.headers.get('content-encoding') == 'gzip':
                try:
                    http.body = gzdecode(http.body)
                except Exception as e:
                    print e;
            if DEBUG :
                print len(http.body)
            else:
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

reqtmp = {}
restmp = {}
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
            if tcp.seq in [i[0] for i in httppool.get(source, [])]:
                continue
            dictappend(reqtmp, source, tcp.data)
            #if tcp.sport == 52833:
            #    print repr(ip)+'\n\n'
            try:
                req = dpkt.http.Request(reqtmp[source])
                if DEBUG:
                    print req.headers
                if ((args.search in reqtmp[source]) if args.search else True):
                    dictappend(httppool, source, [(tcp.seq, req)])
                reqtmp[source] = ''
            except dpkt.UnpackError as e:
                if DEBUG:
                    print '{}:{}'.format(ipparse(source[0]), source[1]),
                    print 'length of request segment: {}'.format(len(reqtmp[source]))
                    print ts, e
                if reqtmp[source][:3] != 'GET' and reqtmp[source][:4] != 'POST':
                    reqtmp[source] = ''   # The data in this TCP stream is not http!

        if tcp.sport == args.port and len(tcp.data) > 0:
            destination = (ip.dst, tcp.dport)
            if tcp.seq in [i[0] for i in httppool.get(destination, [])]:
                continue
            dictappend(restmp, destination, tcp.data)
            #if tcp.dport == 52833:
            #    print repr(ip)+'\n\n'
            try:
                res = dpkt.http.Response(restmp[destination])
                if DEBUG:
                    print res.headers
                if ((args.search in restmp[destination]) if args.search else True):
                    dictappend(httppool, destination, [(tcp.seq, res)])
                restmp[destination] = ''
            except dpkt.UnpackError as e:
                #if 'invalid' in str(e):
                #    print repr(tcp), '{}:{}'.format(ipparse(destination[0]), destination[1])
                if DEBUG:
                    print '{}:{}'.format(ipparse(destination[0]), destination[1]),
                    print 'length of response segment: {}'.format(len(restmp[destination]))
                    print ts, e
                if restmp[destination][:4] != 'HTTP':
                    restmp[destination] = ''   # The data in this TCP stream is not http!

for ip, port in httppool:
    readableIP = ipparse(ip)
    if args.ip and readableIP != args.ip:
        continue
    show('{}:{}'.format(readableIP, port), httppool[(ip, port)])
