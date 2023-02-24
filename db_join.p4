/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_RESUBMIT 6

/* Max tuples within a packet */
#define MAX_DB_ENTRY 16
/* Max hash table cells */
#define NB_CELLS 65536

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_MYP4DB = 0xFA;
const bit<8> TYPE_UDP = 0x11;

enum bit<8> FieldLists {
    resubmit_FL = 0
}

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header db_relation_t {
    bit<6>  relationId;
    bit<1>  flush;
    bit<1>  isReply;
}

header db_entry_t {
    bit<1>    bos;
    bit<31>   entryId;
    bit<32>   secondAttr;
    bit<32>   thirdAttr;
}

header db_reply_entry_t {
    bit<1>    bos;
    bit<31>   entryId;
    bit<32>   secondAttr;
    bit<32>   thirdAttr;
    bit<32>   forthAttr;
    bit<32>   fifthAttr;
}

struct db_entry_metadata_t {
    @field_list(FieldLists.resubmit_FL)
    bit<16>  nextIndex;
    @field_list(FieldLists.resubmit_FL)
    bool                    containsReply;
}

struct metadata {
    db_entry_metadata_t     dbEntry_meta;
}

struct headers {
    ethernet_t                      ethernet;
    ipv4_t                          ipv4;
    db_relation_t                   db_relation;
    db_entry_t[MAX_DB_ENTRY]        db_entries;
    db_reply_entry_t[MAX_DB_ENTRY]  db_reply_entries;

}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_MYP4DB     : parse_relation;
            default         : accept;
        }
    }

    /* Parse the relation id */ 
    state parse_relation {
        packet.extract(hdr.db_relation);
        transition select(hdr.db_relation.isReply) {
            0       : parse_entries;
            default : parse_reply_entries;
        }
    }

    /* Parse all the headers in the entries header stack until bottom of the stack has reached */
    state parse_entries {
        packet.extract(hdr.db_entries.next);
        transition select(hdr.db_entries.last.bos) {
            1       : parse_temp_reply_entries;
            default : parse_entries;
        }
    }

    state parse_temp_reply_entries {
        transition select(meta.dbEntry_meta.containsReply) {
            true    : parse_reply_entries;
            false   : accept;
        }
    }

    state parse_reply_entries {
        packet.extract(hdr.db_reply_entries.next);
        transition select(hdr.db_reply_entries.last.bos) {
            1       : accept;
            default : parse_reply_entries;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
        
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    // Initialize hash table
    register<bit<64>>(NB_CELLS) database;
    register<bit<1>>(1) databaseControl;
    register<bit<6>>(1) relationIdRegister;

    action db_update() {
        bit<16> hashedKey = 0;
        bit<64> tmpTuple = 0;
        bit<16> currentIndex = 0;

        currentIndex = 0;

        tmpTuple[63:32] = hdr.db_entries[currentIndex].secondAttr;
        tmpTuple[31:0] = hdr.db_entries[currentIndex].thirdAttr;

        hash(hashedKey, HashAlgorithm.crc16, (bit<32>)0, { hdr.db_entries[currentIndex].entryId }, (bit<32>)NB_CELLS);
        log_msg("Hashing an entry {} from {}", {hashedKey, hdr.db_entries[currentIndex].entryId});
        // Add entry in hash table
        database.write((bit<32>)hashedKey, tmpTuple);
        hdr.db_entries.pop_front(1);
        meta.dbEntry_meta.nextIndex = meta.dbEntry_meta.nextIndex + 1;
    }

    action lock_database() {
        databaseControl.write((bit<32>)0, 1);
        relationIdRegister.write((bit<32>)0, hdr.db_relation.relationId);
    }

    apply {
        bit<16> currentIndex = meta.dbEntry_meta.nextIndex;

        if (hdr.db_entries[0].isValid()) {
            log_msg("Validating header of {}", {hdr.db_entries[0].entryId});
            bit<1> databaseLocked;
            bit<6> db_relationId;
            bit<1> bosReached = hdr.db_entries[0].bos;
            databaseControl.read(databaseLocked, (bit<32>)0);

            if (databaseLocked == 0) {
                lock_database();
            }
            relationIdRegister.read(db_relationId, (bit<32>)0);
            if (db_relationId == hdr.db_relation.relationId || hdr.db_relation.flush == 1) {
                meta.dbEntry_meta.containsReply = false;
                db_update();
                hdr.ipv4.totalLen = hdr.ipv4.totalLen - 12;
            } else {

                bit<16> hashedKey = 0;
                bit<64> tmpTuple = 0;
                bit<32> secondAttr = 0;
                bit<32> thirdAttr = 0;

                hash(hashedKey, HashAlgorithm.crc16, (bit<32>)0, { hdr.db_entries[0].entryId }, (bit<32>)NB_CELLS);
                // Read entry from hash table
                database.read(tmpTuple, (bit<32>)hashedKey);
                secondAttr = tmpTuple[63:32];
                thirdAttr = tmpTuple[31:0];
                meta.dbEntry_meta.containsReply = true;
                // Add new entry in metadata
                hdr.db_reply_entries.push_front(1);
                hdr.db_reply_entries[0].setValid();
                hdr.db_reply_entries[0].bos = 0;
                // Set bos only on the first entry as it will be moved to the end.
                if (hdr.db_reply_entries[1].isValid() == false) {
                    hdr.db_reply_entries[0].bos = 1;
                }
                hdr.db_reply_entries[0].entryId = hdr.db_entries[0].entryId;
                hdr.db_reply_entries[0].secondAttr = hdr.db_entries[0].secondAttr;
                hdr.db_reply_entries[0].thirdAttr = hdr.db_entries[0].thirdAttr;
                hdr.db_reply_entries[0].forthAttr = secondAttr;
                hdr.db_reply_entries[0].fifthAttr = thirdAttr;
                log_msg("Retrieved entry {}, secondAttr {}, thirdAttr {}", {hdr.db_entries[0].entryId, secondAttr, thirdAttr});
                hdr.db_entries.pop_front(1);
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
            }

            if (hdr.db_entries[0].isValid() && bosReached != 1) {
                recirculate_preserving_field_list((bit<8>)FieldLists.resubmit_FL);
            }
            if (bosReached == 1) {
                if (meta.dbEntry_meta.containsReply != true) {
                    hdr.ipv4.protocol = TYPE_UDP;
                    hdr.db_relation.setInvalid();
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen - 1;
                } else {
                    hdr.db_relation.isReply = 1;
                }
            }

        }

    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.db_relation);
        packet.emit(hdr.db_entries);
        packet.emit(hdr.db_reply_entries);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
