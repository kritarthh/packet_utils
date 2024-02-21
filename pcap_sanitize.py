#!/usr/bin/env python

from scapy.all import *
import re
import random
from scapy.utils import PcapWriter
import sys
import json

if len(sys.argv) < 2:
    print(f"Provide pcap file.")
    print(f"Example usage: python {sys.argv[0]} <pcap-file> <audio,headers,ips,domains,names,endpoints,numbers>")
    sys.exit(1)
in_file = sys.argv[1]
if in_file.split('.')[-1] != 'pcap':
    print(f"invalid pcap file {in_file}")
    sys.exit(1)
if len(sys.argv) < 3:
    print(f"provide things you want to hide. comma separated 'audio,headers,ips,domains,names,endpoints,numbers'")
    sys.exit(1)

#you can manually add mappings here in case you do not want to randomize them
ips = {}
domains = {}
endpoints = {}
numbers = {}
names = {}

sanitize_headers = [
    r'(X-[^:]*): ([^\r\n]*)'
]

def hide_header(m):
    return 'X' * len(m.group(1)) + ': ' + 'X' * len(m.group(2))

def randomize_ip(ip):
    random_ip = ''
    while len(random_ip) != len(ip):
        random_ip = '.'.join('%s'%random.randint(0, 255) for i in range(4))
    return random_ip

def randomize_number(number):
    random_number = ''
    for ch in number:
        if ch.isnumeric():
            random_number += str(random.randint(0, 9))
        else:
            random_number += ch
    return random_number

def randomize_string(endpoint):
    random_string = ''
    for ch in endpoint:
        if ch.isnumeric():
            random_string += str(random.randint(0, 9))
        elif ch.isalpha():
            random_string += random.choice(string.ascii_letters).lower()
        else:
            random_string += ch
    return random_string

hide_types = sys.argv[2]
print(f'Hiding {hide_types}')
packets = rdpcap(in_file)

out_file = '.'.join(in_file.split('.')[:-1]) + '_sharable.pcap'
mappings_out_file = '.'.join(in_file.split('.')[:-1]) + '_MAPPINGS_NOT_SHARABLE.json'
new_pcap = PcapWriter(out_file)


def replace_data(pkt):
    content = pkt[Raw].load.decode('utf-8')

    if 'headers' in hide_types:
        for sh in sanitize_headers:
            content = re.sub(sh, hide_header, content)
    if 'ips' in hide_types:
        for k, v in ips.items():
            pkt[IP].src = pkt[IP].src.replace(k,v)
            pkt[IP].dst = pkt[IP].dst.replace(k,v)
            content = content.replace(k, v)
    if 'domains' in hide_types:
        for k, v in domains.items():
            content = content.replace(k, v)
    if 'endpoints' in hide_types:
        for k, v in endpoints.items():
            content = content.replace(k, v)
    if 'numbers' in hide_types:
        for k, v in numbers.items():
            content = content.replace(k, v)
    if 'names' in hide_types:
        for k, v in names.items():
            content = content.replace(k, v)

    pkt[Raw].load = content.encode('utf-8')
    return pkt

for pkt in packets:
    content = pkt.getlayer(Raw).load
    try:
        sip_content = content.decode('utf-8')

        ips.update({pkt[IP].src: ips.get(pkt[IP].src, randomize_ip(pkt[IP].src))})
        ips.update({pkt[IP].dst: ips.get(pkt[IP].dst, randomize_ip(pkt[IP].dst))})
        ips.update(dict([(el, ips.get(el, randomize_ip(el))) for el in re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', sip_content)]))

        domains.update(dict([(el[1:], domains.get(el[1:], randomize_string(el[1:]))) for el in re.findall(r'@[a-zA-Z][^ ;:\r\n>]+', sip_content)]))
        domains.update(dict([(el[4:], domains.get(el[4:], randomize_string(el[4:]))) for el in re.findall(r'sip:[a-zA-Z][^@>;: ]+', sip_content)]))
        for d in list(domains.keys()):
            if '.' not in d:
                domains.pop(d, None)

        endpoints.update(dict([(el[4:], endpoints.get(el[4:], randomize_string(el[4:]))) for el in re.findall(r'sip:[^@>:;+ ]+', sip_content)]))
        endpoints = {k:v for k,v in endpoints.items() if k not in domains}
        endpoints = {k:v for k,v in endpoints.items() if k not in ips}
        endpoints = {k:v for k,v in endpoints.items() if k not in numbers}

        numbers.update(dict([(el[4:].strip('+'), numbers.get(el[4:].strip('+'), randomize_number(el[4:].strip('+')))) for el in re.findall(r'sip:\+\d+', sip_content)]))

        names.update(dict([(el[6:].strip('" '), names.get(el[6:].strip('" '), randomize_string(el[6:].strip('" ')))) for el in re.findall(r'From: [^\<]+', sip_content)]))
        names.update(dict([(el[4:].strip('" '), names.get(el[4:].strip('" '), randomize_string(el[4:].strip('" ')))) for el in re.findall(r'To: [^\<]+', sip_content)]))
        names = {k:v for k,v in names.items() if k not in numbers}

        pkt = replace_data(pkt)
        new_pcap.write(pkt)
    except Exception as e:
        try:
            RTP(pkt[Raw].load)

            if 'audio' in hide_types:
                pkt[Raw].load = pkt[Raw].load[:12] + b'\xff' * len(pkt[Raw].load[12:])

            if 'ips' in hide_types:
                for k, v in ips.items():
                    pkt[IP].src = pkt[IP].src.replace(k,v)
                    pkt[IP].dst = pkt[IP].dst.replace(k,v)

            new_pcap.write(pkt)
        except Exception as ee:
            print(e)
            print(ee)
        pass

mappings = {
    'ips': ips,
    'domains': domains,
    'endpoints': endpoints,
    'numbers': numbers,
    'names': names
}
for k in list(mappings.keys()):
    if k not in hide_types:
        mappings.pop(k, None)
j = json.dumps(mappings, indent=4)
print(j)
with open(mappings_out_file, 'w') as f:
    f.write(j)

print(f"Modified pcap file written to {out_file}")
print(f"Mappings file for internal reference written to {mappings_out_file}")
