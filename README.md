# packet_utils

## pcap_sanitize.py

Hide sensitive things in pcap files.

IPs, domains, names, endpoints, custom headers, audio can be hidden.

Example usage:

```
python pcap_sanitize.py <pcap-file> audio,headers,ips,domains,endpoints,names,numbers
```

