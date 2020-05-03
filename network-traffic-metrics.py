#!/usr/bin/python3
import subprocess
import time
import re
import socket
import argparse
import os
import asyncio
import sys
from influxdb import InfluxDBClient
# import json

# Notes:
# Unsupported: ARP, nmap, and multicast
# Not sure about IPv6 tracking.

metric_labels = ['src', 'dst', 'service', 'proto']
# Loaded from /etc/services, service_map[port][proto] = service_name
service_map = {}
services = set()  # Names of all services

# In-memory tracker of what we've collected in an interval, flushed after an interval
packet_counter = {}
throughput_counter = {}

# Given an IP or FQDN, extract the domain name to be used as server/client.


def extract_domain(string):
    if opts.fqdn:
        return string
    parts = string.split('.')
    l = len(parts)
    if l == 4 and all(p.isnumeric() for p in parts):
        return string  # IP Address
    return '.'.join(parts[l-2:]) if l > 2 else string

# Use the data loaded from /etc/services to determine the service name for a port+proto


def lookup_service(port, proto):
    if not port in service_map:
        return None
    if not proto in service_map[port]:
        return None
    return service_map[port][proto]

# Helper for building regex.


def re_param(name, pattern):
    return f'(?P<{name}>{pattern})'


# Pre-compile regex for matching tcpdump output:
pattern = '.*' + '.*'.join([
    'proto ' + re_param('proto', '\w+') + ' ',
    'length ' + re_param('length', '\d+'),
    '\n\s*' + re_param('src', '[\w\d\.-]+') + '\.' + re_param('srcp', '[\w\d-]+') +
    ' > ' +
    re_param('dst', '[\w\d\.-]+') + '\.' + re_param('dstp', '[\w\d-]+'),
]) + '.*'
dump_matcher = re.compile(pattern)


# Write a point out to influxdb based on the global metrics. Also reset them to zero
async def write_points(opts):

    # Connect to influx
    client = InfluxDBClient(
        host=opts.host, port=opts.port, database="netmetrics")

    while True:
        await asyncio.sleep(int(opts.interval))
        print("writing a point!")
        # Go through this big hash
        # packet_counter[src][dst][proto][service]
        global packet_counter
        # print(json.dumps(packet_counter, indent=4))
        for src in packet_counter:
            for dst in packet_counter[src]:
                for proto in packet_counter[src][dst]:
                    for service in packet_counter[src][dst][proto]:
                        # We have all the keys now at any given point to build a metric
                        packet = {
                            "measurement": "packets",
                            "tags": {
                                "src":  src,
                                "dst":  dst,
                                "proto": proto,
                                "service": service
                            },
                            "fields": {
                                "packets": packet_counter[src][dst][proto][service]
                            }
                        }
                        client.write_points([packet, ])
        global throughput_counter
        for src in throughput_counter:
            for dst in throughput_counter[src]:
                for proto in throughput_counter[src][dst]:
                    for service in throughput_counter[src][dst][proto]:
                        # We have all the keys now at any given point to build a metric
                        throughput = {
                            "measurement": "throughput",
                            "tags": {
                                "src":  src,
                                "dst":  dst,
                                "proto": proto,
                                "service": service
                            },
                            "fields": {
                                "throughput": throughput_counter[src][dst][proto][service]
                            }
                        }
                        client.write_points([throughput, ])

        # Clear the cache
        packet_counter = {}
        throughput_counter = {}

# Parse output from tcpdump and update the Prometheus counters.


def parse_packet(line):
    m = dump_matcher.match(line)
    if not m:
        print('[SKIP] ' + line.replace("\n", "\t"))
        return

    labels = {
        'src': extract_domain(m.group('src')),
        'dst': extract_domain(m.group('dst')),
        'proto': m.group('proto').lower(),
        'service': None
    }
    # If the last part of the src/dst is a service, just use the literal service name:
    if m.group('dstp') in services:
        labels['service'] = m.group('dstp')
    elif m.group('srcp') in services:
        labels['service'] = m.group('srcp')
    # Otherwise, do a lookup of port/proto to the service:
    if not labels['service'] and m.group('dstp').isnumeric():
        labels['service'] = lookup_service(
            int(m.group('dstp')), labels['proto'])
    if not labels['service'] and m.group('srcp').isnumeric():
        labels['service'] = lookup_service(
            int(m.group('srcp')), labels['proto'])
    if not labels['service']:
        labels['service'] = "unknown"

    # packet_counter[src][dst][proto][service]
    # clean the names
    src = labels['src']
    dst = labels['dst']
    proto = labels['proto']
    service = labels['service']
    # make the keys if they don't exist - this is possibly the worst thing I've ever written
    global packet_counter
    global throughput_counter
    if src not in packet_counter:
        packet_counter[src] = {}
    if src not in throughput_counter:
        throughput_counter[src] = {}
    if dst not in packet_counter[src]:
        packet_counter[src][dst] = {}
    if dst not in throughput_counter[src]:
        throughput_counter[src][dst] = {}
    if proto not in packet_counter[src][dst]:
        packet_counter[src][dst][proto] = {}
    if proto not in throughput_counter[src][dst]:
        throughput_counter[src][dst][proto] = {}
    if service not in packet_counter[src][dst][proto]:
        packet_counter[src][dst][proto][service] = 0
    if service not in throughput_counter[src][dst][proto]:
        throughput_counter[src][dst][proto][service] = 0

    packet_counter[labels['src']][labels['dst']
                                  ][labels['proto']][labels['service']] += 1
    throughput_counter[labels['src']][labels['dst']
                                      ][labels['proto']][labels['service']] += int(m.group('length'))
    # print("hiii")
# Run tcpdump and stream the packets out


async def stream_packets():
    p = await asyncio.create_subprocess_exec(
        'tcpdump', '-i', opts.interface, '-v', '-l', opts.filters,
        stdout=asyncio.subprocess.PIPE)
    while True:
        # When tcpdump is run with -v, it outputs two lines per packet;
        # readuntil ensures that each "line" is actually a parse-able string of output.
        line = await p.stdout.readuntil(b' IP ')
        if len(line) <= 0:
            print(f'No output from tcpdump... waiting.')
            await asyncio.sleep(1)
            continue
        try:
            parse_packet(line.decode('utf-8'))
        except BaseException as e:
            print(f'Failed to parse line "{line}" because: {e}')

if __name__ == '__main__':
    # Load a map of ports to services from /etc/services:
    matcher = re.compile('(?P<service>\w+)\s*(?P<port>\d+)/(?P<proto>\w+)')
    with open('/etc/services') as f:
        for line in f.readlines():
            match = matcher.match(line)
            if not match:
                continue
            port = int(match.group('port'))
            if not port in services:
                service_map[port] = {}
            service_map[port][match.group('proto')] = match.group('service')
            services.add(match.group('service'))

    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default=os.getenv('NTM_INTERFACE', 'eth0'),
                        help='The network interface to monitor.')
    parser.add_argument('--host', '-l', default=os.getenv('NTM_HOST', "127.0.0.1"),
                        help='The influxdb hostname.')
    parser.add_argument('--port', '-p', default=int(os.getenv('NTM_PORT', 8086)),
                        help='The influxdb port.')
    parser.add_argument('--interval', '-n', default=int(os.getenv('NTM_INTERVAL', 15)),
                        help='The grouping interval in seconds.')
    parser.add_argument('--fqdn', '-f', action='store_true',
                        help='Include the FQDN (will increase cardinality of metrics significantly)')
    parser.add_argument('filters', nargs='?', default=os.getenv('NTM_FILTERS', ''),
                        help='The TCPdump filters, e.g., "src net 192.168.1.1/24"')
    opts = parser.parse_args()

    async def main():
        await asyncio.gather(
            stream_packets(),
            write_points(opts)
        )

    asyncio.run(main())
