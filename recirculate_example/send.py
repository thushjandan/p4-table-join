
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

# Number of tuples to generate
NUMBER_ENTRIES = 10
# Generate randomly the entityIds from a range of 0 to 1000
RANDOM_ENTITYIDS = random.sample(range(0, 1000), NUMBER_ENTRIES)

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
        BitField("replyJoinedrelationId", 0, 7),
        BitField("isReply", 0, 1),
        BitField("reserved", 0, 1),
    ]

# IP proto 250 indicates MYP4DB_Relation
bind_layers(IP, DBRelation, proto=0xFA)
bind_layers(DBRelation, DBEntry)
# Recursively bind to the same type as long bottom of stack has not reached
bind_layers(DBEntry, DBEntry, bos=0)
# If bottom of stack has reached, then UDP header will follow
bind_layers(DBEntry, UDP, bos=1)

# Generate MYP4DB packet and append it to an existing ipv4 packet
def generate_db_pkt(relationId, pick_random_entityId=False, isFlush=0):
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr, proto=0xFA) / DBRelation(relationId=relationId, isReply=0)
    i = 0
    # Create a header stack of DBEntries
    for p in range(0,NUMBER_ENTRIES):
        entityId = RANDOM_ENTITYIDS[i]
        # Pick a new random entity if random generator returns false
        if pick_random_entityId and not bool(random.getrandbits(1)):
            entityId = random.randint(0, 1000)
        secondAttr = random.randint(0, 1000)
        thirdAttr = random.randint(0, 1000)
        # Append to the header stack
        try:
            pkt = pkt / DBEntry(bos=0, entryId=int(entityId), secondAttr=int(secondAttr), thirdAttr=int(thirdAttr))
            i = i+1
        except ValueError:
            pass
    
    # Set the bottom of stack flag for the last entry.
    if pkt.haslayer(DBEntry):
        pkt.getlayer(DBEntry, i).bos = 1
        
    pkt = pkt / UDP(dport=4321, sport=1234) / sys.argv[2]
    return pkt

def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    # Generate the first relation, which will be stored on the switch
    r_relation = generate_db_pkt(relationId=1)

    r_relation.show2()
    iface = get_if()
    # Send packet
    try:
        sendp(r_relation, iface=iface)
        sleep(1)        
    except KeyboardInterrupt:
        raise
    
    # Generate the second relation, but reuse randomly entityId
    s_relation = generate_db_pkt(relationId=2, pick_random_entityId=True)

    s_relation.show2()
    # Send packet
    try:
        sendp(s_relation, iface=iface)
        sleep(1)        
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()