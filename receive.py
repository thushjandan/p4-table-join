#!/usr/bin/env python3
import sys

from scapy.all import (
    IntField,
    IP,
    UDP,
    bind_layers,
    Packet,
    BitField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class DBEntry(Packet):
    fields_desc = [ 
        BitField("bos", 0, 1),
        BitField("entryId", 0, 31),
        IntField("secondAttr", 0),
        IntField("thirdAttr", 0),
    ]

class DBRelation(Packet):
    name = "MYP4DB_Relation"
    fields_desc = [ 
        BitField("relationId", 0, 7),
        BitField("flush", 0, 1)
    ]

bind_layers(IP, DBRelation, proto=0xFA)
bind_layers(DBRelation, DBEntry)
bind_layers(DBEntry, DBEntry, bos=0)
bind_layers(DBEntry, UDP, bos=1)

def handle_pkt(pkt):
    print("got a packet")
    pkt.show2()
    sys.stdout.flush()


def main():
    iface = 'eth0'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="proto 250", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()