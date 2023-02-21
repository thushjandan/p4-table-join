
#!/usr/bin/env python3

import socket
import sys
import random
from time import sleep

from scapy.all import (
    IP,
    UDP,
    Ether,
    IntField,
    BitField,
    Packet,
    get_if_hwaddr,
    get_if_list,
    bind_layers,
    sendp
)
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
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

def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, proto=0xFA) / DBRelation(relationId=0x1, flush=0x1)
    i = 0
    for p in range(0,10):
        entityId = random.randint(0, 1000)
        secondAttr = random.randint(0, 1000)
        thirdAttr = random.randint(0, 1000)
        try:
            pkt = pkt / DBEntry(bos=0, entryId=int(entityId), secondAttr=int(secondAttr), thirdAttr=int(thirdAttr))
            i = i+1
        except ValueError:
            pass
    
    if pkt.haslayer(DBEntry):
        pkt.getlayer(DBEntry, i).bos = 1
        
    pkt = pkt / UDP(dport=4321, sport=1234) / sys.argv[2]

    pkt.show2()
    try:
        sendp(pkt, iface=iface)
        sleep(1)        
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()