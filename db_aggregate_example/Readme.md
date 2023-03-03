# P4 application for table aggregation (sum function)
This P4 application is a toy example, which implements a table aggragation from a relation grouped by entityId within the dataplane. BMv2 & Mininet are used to run this P4 app.

## Overview
Let's assume we have a single table/relation, called `R`, and it has three (unsigned) integer attributes.

First we pump the table `R` with random numbers to the switch. The switch will store these tuples in a hash table using `extern register`.

Then we set the `aggregate` flag in the packet header to retrieve the aggregation from a certain entityId.

### Example
**Relation R**
| entityId | secondAttr | thirdAttr |
|----------|------------|-----------|
| 153      | 2          | 5         |
| 153      | 3          | 5         |
| 153      | 1          | 6         |
| 789      | 685        | 145       |

**Result**
| entityId | secondAttr | thirdAttr |
|----------|------------|-----------|
| 153      | 6          | 16        |
| 789      | 685        | 145       |

## How to build
Build a vagrant box with all the necessary tools installed for P4 development using the scripts from the [p4lang/tutorials](https://github.com/p4lang/tutorials/tree/master/vm-ubuntu-20.04) repo.

Afterwards, start the P4 application as follows:
```bash
$ make
```
It will build the P4 app and start mininet with 1 bmv2 switch and 2 end host.

### How to stop
First, `exit` from the mininet console and stop the app:
```
make stop
# Cleanup
make clean
```

## Design
After the IPv4 header, the [MYP4DB_Relation](#relational-header-myp4db_relation) header will be appended, which contains the metadata for a relation. IPv4 protocol number 0xFA (250) is used to indicate that header.
An additional header of type [DBEntry](#request-tuple-dbentry) will follow, which contains a single tuple.

The switch will process the tuple from the header. If the flag `aggregate` is set, the switch will return the aggregation. Otherwise the switch will drop the packet after processing.

### Relational Header (MYP4DB_Relation)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  relationId |a|
+-+-+-+-+-+-+-+-+

```
Total 2 bytes (16-bits)
* relationId (7-bit): the name of the relation represented as an unsigned integer. 
* aggregate (1-bit): flag if the switch should return the aggregation results. The default is empty (0). If 0, the switch drops the packet after processing. otherwise the switch will return the results.

### Request Tuple (DBEntry)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           entryId                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           secondAttr                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           thirdAttr                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
Total 12 bytes (96 bits)
* entryId (32-bit): primary key represented as an unsigned integer.
* secondAttr (32-bit): Second attribute of the tuple represented as an unsigned integer.
* thirdAttr (32-bit): Third attribute of the tuple represented as an unsigned integer.

## Example
* Start the mininet simulator with bmv2 switch running our P4 code.
```
make
mininet> xterm h1 h2
```
* In the terminal of h2, execute `receive.py` script
```
h2> ./receive.py
```
* In the terminal of h1, send request with `send.py` script
```
h1> ./send.py 10.0.2.2 "P4 is cool"
```

### Example output
10 packets will be sent from h1. EntityIds will be randomly reused. Afterwards, for each used entityId another packet using the aggregate flag will be sent to retrieve the aggregation, which will be grouped by entitiyId.

#### 2 samples sent by h1, which will be stored on the switch
```###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 08:00:00:00:01:11
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = 250
     chksum    = 0x62ce
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        aggregate = 0
###[ DBEntry ]### 
           entryId   = 799
           secondAttr= 1
           thirdAttr = 3
###[ UDP ]### 
              sport     = 1234
              dport     = 4321
              len       = 18
              chksum    = 0x0
###[ Raw ]### 
                 load      = 'P4 is cool'

###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 08:00:00:00:01:11
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = 250
     chksum    = 0x62ce
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        aggregate = 0
###[ DBEntry ]### 
           entryId   = 383
           secondAttr= 2
           thirdAttr = 4
###[ UDP ]### 
              sport     = 1234
              dport     = 4321
              len       = 18
              chksum    = 0x0
###[ Raw ]### 
                 load      = 'P4 is cool'
```
#### 2 samples sent by h1, which will trigger a JOIN on the switch
As the switch holds currently tuples from the relation R with id `1`, we send tuples from relation S with id `2` now
```Sent 1 packets.
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 08:00:00:00:01:11
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = 250
     chksum    = 0x62ce
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        aggregate = 1
###[ DBEntry ]### 
           entryId   = 186
           secondAttr= 0
           thirdAttr = 3
###[ UDP ]### 
              sport     = 1234
              dport     = 4321
              len       = 18
              chksum    = 0x0
###[ Raw ]### 
                 load      = 'P4 is cool'

###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 08:00:00:00:01:11
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = 250
     chksum    = 0x62ce
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        aggregate = 1
###[ DBEntry ]### 
           entryId   = 799
           secondAttr= 1
           thirdAttr = 0
###[ UDP ]### 
              sport     = 1234
              dport     = 4321
              len       = 18
              chksum    = 0x0
###[ Raw ]### 
                 load      = 'P4 is cool'
```
#### Retrieved packets on h2
```sniffing on eth0
got a packet
###[ Ethernet ]### 
  dst       = 08:00:00:00:02:22
  src       = ff:ff:ff:ff:ff:ff
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 63
     proto     = 250
     chksum    = 0x63ce
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        aggregate = 1
###[ DBEntry ]### 
           entryId   = 383
           secondAttr= 11
           thirdAttr = 12
###[ UDP ]### 
              sport     = 1234
              dport     = 4321
              len       = 18
              chksum    = 0x0
###[ Raw ]### 
                 load      = 'P4 is cool'

got a packet
###[ Ethernet ]### 
  dst       = 08:00:00:00:02:22
  src       = ff:ff:ff:ff:ff:ff
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 63
     proto     = 250
     chksum    = 0x63ce
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        aggregate = 1
###[ DBEntry ]### 
           entryId   = 773
           secondAttr= 9
           thirdAttr = 4
###[ UDP ]### 
              sport     = 1234
              dport     = 4321
              len       = 18
              chksum    = 0x0
###[ Raw ]### 
                 load      = 'P4 is cool'

got a packet
###[ Ethernet ]### 
  dst       = 08:00:00:00:02:22
  src       = ff:ff:ff:ff:ff:ff
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 63
     proto     = 250
     chksum    = 0x63ce
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        aggregate = 1
###[ DBEntry ]### 
           entryId   = 186
           secondAttr= 3
           thirdAttr = 8
###[ UDP ]### 
              sport     = 1234
              dport     = 4321
              len       = 18
              chksum    = 0x0
###[ Raw ]### 
                 load      = 'P4 is cool'

got a packet
###[ Ethernet ]### 
  dst       = 08:00:00:00:02:22
  src       = ff:ff:ff:ff:ff:ff
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 63
     proto     = 250
     chksum    = 0x63ce
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        aggregate = 1
###[ DBEntry ]### 
           entryId   = 799
           secondAttr= 2
           thirdAttr = 3
###[ UDP ]### 
              sport     = 1234
              dport     = 4321
              len       = 18
              chksum    = 0x0
###[ Raw ]### 
                 load      = 'P4 is cool'
```
