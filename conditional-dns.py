#!/usr/bin/env python
# coding=utf-8

import argparse
import datetime
import sys
import time
import threading
import traceback
import struct
import configparser
import logging

try:
    import socketserver
except ImportError:
    print("This program must be run using Python3.")
    sys.exit(2)

try:
    from dns import reversename
    from dns.resolver import Resolver
    from netaddr import IPNetwork, IPAddress
    from dnslib import *
    import netifaces
except ImportError:
    print("Please verify dependencies are installed: dnslib, dnspython, netaddr, netifaces")
    print("sudo pip install dnslib dnspython netaddr netifaces")
    sys.exit(2)

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


# Configure request logging
logger = logging.getLogger('conditional-dns')
logger.setLevel(logging.INFO)
fh = logging.FileHandler('/var/log/conditional-dns.log')
fh.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)

# Create the DNS resolvers globally so it's not created for each query
opendnsRes = Resolver()
opendnsRes.nameservers = ['208.67.222.123', '208.67.220.123']
unlocatorRes = Resolver()
unlocatorRes.nameservers = ['185.37.39.39', '185.37.37.37']

# Generate a list of this server's possible reverse DNS address
myreversedns = []
for iface in netifaces.interfaces():
    if netifaces.AF_INET in netifaces.ifaddresses(iface):
        for link in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
            myreversedns.append(str(reversename.from_address(link['addr'])))

# Read config file
conffile = '/etc/conditional-dns.conf'
c = configparser.ConfigParser()
c.read(conffile)

# Generate list of domains to send to sniproxy
sniproxyServer = c.get('sniproxy', 'server')
confSniproxyDomains = c.get('sniproxy', 'items')
sniproxyDomains = list(filter(None, [x.strip() for x in confSniproxyDomains.splitlines()]))

# Generate list of domains not to let OpenDNS block
confAlwaysOpendns = c.get('alwaysOpendns', 'items')
alwaysOpendns = list(filter(None, [x.strip() for x in confAlwaysOpendns.splitlines()]))

# Generate list of domains not to let Unlocate redirect
confAlwaysUnlocator = c.get('alwaysUnlocator', 'items')
alwaysUnlocator = list(filter(None, [x.strip() for x in confAlwaysUnlocator.splitlines()]))

def dns_response(data):
    # Parse the request
    request = DNSRecord.parse(data)

    # Create reply skeleton
    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    # Parse out the query target
    qname = request.q.qname
    qn = str(qname)

    # If query is our reversedns, return PTR record so Windows doesn't waste 2 seconds looking us up
    if qn in myreversedns:
        reply.add_answer(RR(qn,QTYPE.PTR,rdata=PTR('localdns'),ttl=5*60))

    # If query is opendns.com, return OpenDNS lookup
    elif 'opendns.com' in qn:
        odnsResp = opendnsRes.query(qn)
        odnsAns = odnsResp[0].address
        reply.add_answer(RR(qn,QTYPE.A,rdata=A(odnsAns),ttl=5*60))
        logger.info('MGMT ' + qn + ' (' + odnsAns + ')')

    # If query is for sniproxy, return sniproxy server IP
    elif any([ x in qn for x in sniproxyDomains ]):
        reply.add_answer(RR(qn,QTYPE.A,rdata=A(sniproxyServer),ttl=5*60))
        logger.info('SNIPROXY ' + qn + ' (' + sniproxyServer + ')')

    # If query is in always Unlocator list, return Unlocator lookup
    elif any([ x in qn for x in alwaysUnlocator ]):
        unlocResp = unlocatorRes.query(qn)
        unlocAns = unlocResp[0].address
        reply.add_answer(RR(qn,QTYPE.A,rdata=A(unlocAns),ttl=5*60))
        logger.info('ALWAYS_UNLOCATOR ' + qn + ' (' + unlocAns + ')')

    # If query is in always Opendns list, return Opendns lookup
    elif any([ x in qn for x in alwaysOpendns ]):
        odnsResp = opendnsRes.query(qn)
        odnsAns = odnsResp[0].address
        reply.add_answer(RR(qn,QTYPE.A,rdata=A(odnsAns),ttl=5*60))
        logger.info('ALWAYS_OPENDNS ' + qn + ' (' + odnsAns + ')')

    # Else do both OpenDNS and Unlocator lookups
    else:
        # Query OpenDNS
        odnsResp = opendnsRes.query(qn, raise_on_no_answer=False)
        odnsAns = odnsResp[0].address
        
        # Query Unlocator
        unlocResp = unlocatorRes.query(qn, raise_on_no_answer=False)
        unlocAns = unlocResp[0].address
        
        # If OpenDNS would block or request is for opendns.com, return OpenDNS response IP
        if IPAddress(odnsAns) in IPNetwork("146.112.61.104/29"):
            reply.add_answer(RR(qn,QTYPE.A,rdata=A(odnsAns),ttl=5*60))
            logger.info('BLOCKED ' + qn + ' (' + odnsAns + ')')

        # Else tell client to use Unlocator
        else:
            reply.add_answer(RR(qn,QTYPE.A,rdata=A(unlocAns),ttl=5*60))
            logger.info('UNLOCATOR ' + qn + ' (' + unlocAns + ')')

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        try:
            data = self.get_data()
            self.send_data(dns_response(data))
        except Exception as e:
            logger.error("%s request %s (%s %s): %s" % (self.__class__.__name__[:3], now, self.client_address[0], self.client_address[1], data))
            logger.exception("Error parsing DNS request")


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192)
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')
    
    # Parse arguments
    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()

