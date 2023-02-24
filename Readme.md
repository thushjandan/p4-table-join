# P4 application for table join between two relations
This P4 application is a toy example, which implements a table join between two relations within the dataplane. BMv2 & Mininet are used to run this P4 app.

## Overview
Let's assume we have two tables/relations called R and S and they have each three (unsigned) integer attributes.

First we pump the table R with random numbers to the switch. The switch will store these tuples in a hash table using `extern register`.

First we pump the table S with random numbers to the switch. The switch will recognized the table S and will do an INNER JOIN with table R.

### Example
**Relation R**
| entityId | secondAttr | thirdAttr |
|----------|------------|-----------|
| 123      | 32         | 214       |
| 45       | 234        | 56        |
| 6        | 456        | 852       |
| 789      | 685        | 145       |

**Relation S**
| entityId | secondAttr | thirdAttr |
|----------|------------|-----------|
| 209      | 642        | 595       |
| 45       | 53         | 842       |
| 321      | 67         | 1         |
| 789      | 74         | 315       |

**Result**
| entityId | secondAttr | thirdAttr | forthAttr | fifthAttr |
|----------|------------|-----------|-----------|-----------|
| 45       | 234        | 56        | 53        | 842       |
| 789      | 685        | 145       | 74        | 315       |

## How to build
Start the P4 application
```bash
$ make
```
First, `exit` from the mininet console and stop the app:
```
make stop
# Cleanup
make clean
```

## Design
After the IPv4 header, the [MYP4DB_Relation](#relational-header-myp4db_relation) will be appended, which contains the metadata for a relation and control flags. 
A header stack of type `DBEntry` will follow for every tuple.

The switch will process each tuple from the header stack. If the switch decides to store the relation in case of an empty hash table, it will remove the whole header stack as well as MYP4DB_Relation header at the end. So, the receiver will only receive the UDP packet consisting of Ethernet & IPv4 headers.

In case the requested relation is a different from the stored relation, a INNER JOIN operation is assumed on the switch and a header stack of type `DBReplyEntry`, containing the joined tuples, is generated.

### Relational Header (MYP4DB_Relation)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  relationId |replyJoinedR.|i|r|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
* relationId (7-bit): the name of the relation represented as an unsigned integer. 
* replyJoinedRelation (7-bit): the name of the joined relation represented as an unsigned integer. The default is empty (0) and will only be used within a reply packet.
* isReply (1-bit): indicates if it is a request or reply packet. 0 for request and 1 for reply.
* reserved (1-bit): reserved for future uses.
### Request Tuple (DBEntry)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|b|                           entryId                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           secondAttr                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           thirdAttr                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
* bos (1-bit): indicates if bottom of stack has reached. 1 if bos has reached, otherwise 0
* entryId (31-bit): primary key represented as an unsigned integer.
* secondAttr (32-bit): Second attribute of the tuple represented as an unsigned integer.
* thirdAttr (32-bit): Third attribute of the tuple represented as an unsigned integer.
### Reply Tuple (Joined tuple)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|b|                           entryId                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           secondAttr                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           thirdAttr                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           forthAttr                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           fifthAttr                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
* bos (1-bit): indicates if bottom of stack has reached. 1 if bos has reached, otherwise 0
* entryId (31-bit): primary key represented as an unsigned integer.
* secondAttr (32-bit): Second attribute of the tuple represented as an unsigned integer.
* thirdAttr (32-bit): Third attribute of the tuple represented as an unsigned integer.
* forthAttr (32-bit): Forth attribute of the tuple represented as an unsigned integer.
* fifthAttr (32-bit): Fifth attribute of the tuple represented as an unsigned integer.
### Processing logic

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
Following 2 packets will be sent from h1. All the entries in the first packet will be stored in the hash table of the switch. The second request will trigger a INNER JOIN on the switch and h2 will get all the joined records.

A long story short, all the joined tuples (INNER JOIN) can be found in the DBReplyEntry header stack [see here](#retrieved-packets-on-h2).
#### Sent packets on h1
```
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 08:00:00:00:01:11
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 160
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = 250
     chksum    = 0x6261
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 1
        replyJoinedrelationId= 0
        isReply   = 0
        reserved  = 0
###[ DBEntry ]### 
           bos       = 0
           entryId   = 225
           secondAttr= 788
           thirdAttr = 843
###[ DBEntry ]### 
              bos       = 0
              entryId   = 521
              secondAttr= 654
              thirdAttr = 857
###[ DBEntry ]### 
                 bos       = 0
                 entryId   = 456
                 secondAttr= 223
                 thirdAttr = 550
###[ DBEntry ]### 
                    bos       = 0
                    entryId   = 840
                    secondAttr= 496
                    thirdAttr = 985
###[ DBEntry ]### 
                       bos       = 0
                       entryId   = 939
                       secondAttr= 470
                       thirdAttr = 470
###[ DBEntry ]### 
                          bos       = 0
                          entryId   = 994
                          secondAttr= 870
                          thirdAttr = 115
###[ DBEntry ]### 
                             bos       = 0
                             entryId   = 670
                             secondAttr= 309
                             thirdAttr = 423
###[ DBEntry ]### 
                                bos       = 0
                                entryId   = 972
                                secondAttr= 67
                                thirdAttr = 35
###[ DBEntry ]### 
                                   bos       = 0
                                   entryId   = 813
                                   secondAttr= 307
                                   thirdAttr = 967
###[ DBEntry ]### 
                                      bos       = 1
                                      entryId   = 559
                                      secondAttr= 739
                                      thirdAttr = 288
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
     len       = 160
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = 250
     chksum    = 0x6261
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 2
        replyJoinedrelationId= 0
        isReply   = 0
        reserved  = 0
###[ DBEntry ]### 
           bos       = 0
           entryId   = 225
           secondAttr= 318
           thirdAttr = 621
###[ DBEntry ]### 
              bos       = 0
              entryId   = 521
              secondAttr= 106
              thirdAttr = 313
###[ DBEntry ]### 
                 bos       = 0
                 entryId   = 238
                 secondAttr= 748
                 thirdAttr = 286
###[ DBEntry ]### 
                    bos       = 0
                    entryId   = 840
                    secondAttr= 418
                    thirdAttr = 157
###[ DBEntry ]### 
                       bos       = 0
                       entryId   = 837
                       secondAttr= 358
                       thirdAttr = 910
###[ DBEntry ]### 
                          bos       = 0
                          entryId   = 212
                          secondAttr= 741
                          thirdAttr = 403
###[ DBEntry ]### 
                             bos       = 0
                             entryId   = 670
                             secondAttr= 650
                             thirdAttr = 381
###[ DBEntry ]### 
                                bos       = 0
                                entryId   = 36
                                secondAttr= 516
                                thirdAttr = 133
###[ DBEntry ]### 
                                   bos       = 0
                                   entryId   = 813
                                   secondAttr= 981
                                   thirdAttr = 202
###[ DBEntry ]### 
                                      bos       = 1
                                      entryId   = 559
                                      secondAttr= 762
                                      thirdAttr = 308
###[ UDP ]### 
                                         sport     = 1234
                                         dport     = 4321
                                         len       = 18
                                         chksum    = 0x0
###[ Raw ]### 
                                            load      = 'P4 is cool'


Sent 1 packets.
```
#### Retrieved packets on h2
```
###[ Ethernet ]### 
  dst       = 08:00:00:00:02:22
  src       = 08:00:00:00:02:22
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 39
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 54
     proto     = udp
     chksum    = 0x6dc3
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ UDP ]### 
        sport     = 1234
        dport     = 4321
        len       = 18
        chksum    = 0x0
###[ Raw ]### 
           load      = 'P4 is cool'


###[ Ethernet ]### 
  dst       = 08:00:00:00:02:22
  src       = 08:00:00:00:02:22
  type      = IPv4
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 160
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 54
     proto     = 250
     chksum    = 0x6c61
     src       = 10.0.1.1
     dst       = 10.0.2.2
     \options   \
###[ MYP4DB_Relation ]### 
        relationId= 2
        replyJoinedrelationId= 1
        isReply   = 1
        reserved  = 0
###[ DBReplyEntry ]### 
           bos       = 0
           entryId   = 559
           secondAttr= 762
           thirdAttr = 308
           forthAttr = 739
           fifthAttr = 288
###[ DBReplyEntry ]### 
              bos       = 0
              entryId   = 813
              secondAttr= 981
              thirdAttr = 202
              forthAttr = 307
              fifthAttr = 967
###[ DBReplyEntry ]### 
                 bos       = 0
                 entryId   = 670
                 secondAttr= 650
                 thirdAttr = 381
                 forthAttr = 309
                 fifthAttr = 423
###[ DBReplyEntry ]### 
                    bos       = 0
                    entryId   = 840
                    secondAttr= 418
                    thirdAttr = 157
                    forthAttr = 496
                    fifthAttr = 985
###[ DBReplyEntry ]### 
                       bos       = 0
                       entryId   = 521
                       secondAttr= 106
                       thirdAttr = 313
                       forthAttr = 654
                       fifthAttr = 857
###[ DBReplyEntry ]### 
                          bos       = 1
                          entryId   = 225
                          secondAttr= 318
                          thirdAttr = 621
                          forthAttr = 788
                          fifthAttr = 843
###[ UDP ]### 
                             sport     = 1234
                             dport     = 4321
                             len       = 18
                             chksum    = 0x0
###[ Raw ]### 
                                load      = 'P4 is cool'
```

## References
This repository is using parts of the [p4lang/tutorials](https://github.com/p4lang/tutorials) repository to bootstrap the application.