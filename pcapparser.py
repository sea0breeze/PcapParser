#!/usr/bin/python
import argparse
import dpkt
import urllib
import gzip
import StringIO
import string

DEBUG = False

def gzdecode(data) :
    '''This function deal with gzip compressed data 
    in http.
    
    '''
    
    compressedstream = StringIO.StringIO(data)
    gziper = gzip.GzipFile(fileobj=compressedstream)
    data2 = gziper.read()
    return data2

def dictappend(d, k, v):
    '''Just a utile function. Perhaps there is
    a better way to impletement it.
    
    '''
    
    if k in d:
        d[k] += v
    else:
        d[k] = v

def ipparse(ipstr):
    '''Convert the 4-byte string representing ip address
    to a readable string for human.
    
    '''
    
    ip = map(ord, ipstr)
    assert len(ip) == 4
    return '{}.{}.{}.{}'.format(ip[0], ip[1], ip[2], ip[3])

def show(enermy, httplist):
    '''Print the message in a ordered list of dkpt.http.Requset/Response
    objects tidily.
    
    '''
    
    if DEBUG:
        return
    for http in httplist:
        if args.search and args.search not in repr(http):
            continue
        print '*******************************************************************'
        if type(http) == dpkt.http.Request:
            print '{} ==> YOU\n'.format(enermy)
            print '{} {}'.format(http.method, urllib.unquote_plus(http.uri))

        if type(http) == dpkt.http.Response:
            print 'YOU ==> {}\n'.format(enermy)
            print 'HTTP/{} {} {}'.format(http.version, http.status, http.reason)

        header = http.headers
        for i in header:
            print '{}: {}'.format(i, header[i])
        print '\n'
        if http.body != None and args.verbose:        # Avoid error when body is empty.
            if http.headers.get('content-encoding') == 'gzip':
                try:
                    http.body = gzdecode(http.body)
                except Exception as e:
                    print e;
            if DEBUG :
                print len(http.body)
            elif header.has_key('content-type') and 'image' in header['content-type']:
                '<Here is a cute image file. But printing its contents may not be a good idea:)>'
            elif set(http.body).issubset(set(string.printable)):
                print urllib.unquote_plus(http.body)
            else:
                print "<Oh my god, what's this? Anyway i can not print it>"

        print '\n\n*******************************************************************'

def makestream(reql, resl):
    '''Make a list of dkpt.http.Requset objects and a list 
    of dpkt.http.Response from the same tcp stream ordered.
    
    '''
    
    reqdict = {}
    resdict = {}
    reqseq = min([tcp.seq for tcp in reql])
    resseq = min([tcp.seq for tcp in resl])
    for reqseg in reqlist:
        reqdict[reqseg.seq] = (reqseg, len(reqseg.data))
    for resseg in reslist:
        resdict[resseg.seq] = (resseg, len(resseg.data))

    tcpstream = []
    reqbuffer = ''
    resbuffer = ''
    time = len(reql)
    for i in range(time):
        req, reqlength = reqdict[reqseq]
        if DEBUG:
            print 'Request seq: {} ack: {} len: {}'.format(req.seq, req.ack, reqlength)
        reqseq += reqlength
        reqbuffer += req.data
        if req.flags & 0b1000: # PUSH is set
            if reqbuffer[:3] == 'GET' or reqbuffer[:4] == 'POST':
                tcpstream.append(dpkt.http.Request(reqbuffer))
            else:              # This stream is not http!
                if DEBUG:
                    print repr(reqbuffer)
                return []
            reqbuffer = ''
            while True:
                res, reslength = resdict[resseq]
                assert res.ack == reqseq
                if DEBUG:
                    print 'Response seq: {} ack: {} len: {}'.format(res.seq, res.ack, reslength)
                resseq += reslength
                resbuffer += res.data
                if res.flags & 0b1000:  # PUSH is set
                    if resbuffer[:4] != 'HTTP':
                        raise Exception # This stream is not http!
                    try:
                        tcpstream.append(dpkt.http.Response(resbuffer))
                        if DEBUG:
                                print repr(tcpstream[-1].headers)
                        resbuffer = ''
                        break
                    except dpkt.dpkt.UnpackError as e:
                        continue
    if DEBUG:
        'One stream ends!'
    return tcpstream

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
        if tcp.dport == args.port and ((ip.src == args.ip) if args.ip else 1) and len(tcp.data) > 0:
            source = (ip.src, tcp.sport)
            dictappend(reqtmp, source, [tcp])

        if tcp.sport == args.port and ((ip.dst == args.ip) if args.ip else 1) and len(tcp.data) > 0:
            destination = (ip.dst, tcp.dport)
            dictappend(restmp, destination, [tcp])

for ip, port in reqtmp:
    try:
        reslist = restmp[(ip, port)]
    except KeyError:
        continue    # Requests with no responses won't be displayed.
    reqlist = reqtmp[(ip, port)]
    httppool[(ip, port)] = makestream(reqlist, reslist)

for ip, port in httppool:
    readableIP = ipparse(ip)
    if args.ip and readableIP != args.ip:
        continue
    show('{}:{}'.format(readableIP, port), httppool[(ip, port)])
