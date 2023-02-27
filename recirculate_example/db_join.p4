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

/* Enum for tags to preserve fields within the recirculate pipeline */
enum bit<8> FieldLists {
    resubmit_FL = 0
}

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> db_attribute_t;

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
    bit<7>  relationId;
    bit<7>  replyJoinedRelationId;
    bit<1>  isReply;
    bit<1>  reserved;
}

header db_entry_t {
    bit<1>          bos;
    bit<31>         entryId;
    db_attribute_t  secondAttr;
    db_attribute_t  thirdAttr;
}

header db_reply_entry_t {
    bit<1>          bos;
    bit<31>         entryId;
    db_attribute_t  secondAttr;
    db_attribute_t  thirdAttr;
    db_attribute_t  forthAttr;
    db_attribute_t  fifthAttr;
}

struct db_entry_metadata_t {
    /* Preserve containsReply flag within recirculate pipeline 
    * to distinguish if there is an additional reply header stack
    */
    @field_list(FieldLists.resubmit_FL)
    bool    containsReply;
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

    /* Parse the relation header */ 
    state parse_relation {
        packet.extract(hdr.db_relation);
        transition select(hdr.db_relation.isReply) {
            0       : parse_entries;
            default : parse_reply_entries;
        }
    }

    /*  Parse all the headers in the db_entries header stack until bottom of stack has reached.
    *   In case, there are temporary reply entries added after bottom of stack, go
    *   to parse_temp_reply_entries state to distinguish if further parsing is required.
    */
    state parse_entries {
        packet.extract(hdr.db_entries.next);
        transition select(hdr.db_entries.last.bos) {
            1       : parse_temp_reply_entries;
            default : parse_entries;
        }
    }

    /**
    * Check from the preserved metadata field if a reply header stack exists.
    * If yes, then parse that as well for manipulation purposes, otherwise stop here.
    */
    state parse_temp_reply_entries {
        transition select(meta.dbEntry_meta.containsReply) {
            true    : parse_reply_entries;
            false   : accept;
        }
    }

    /**
    * Parse reply header stack until bottom of stack has reached.
    */
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
    // Database control registers. Used to store the name of the relation
    register<bit<7>>(1) relationIdRegister;

    /*
    * Insert a single entry to the hash table.
    */
    action db_update() {
        bit<16> hashedKey = 0;
        bit<64> tmpTuple = 0;

        // Encode all the attributes into a single field.
        tmpTuple[63:32] = hdr.db_entries[0].secondAttr;
        tmpTuple[31:0] = hdr.db_entries[0].thirdAttr;

        // Hash the primary key (entryId)
        hash(hashedKey, HashAlgorithm.crc16, (bit<32>)0, { hdr.db_entries[0].entryId }, (bit<32>)NB_CELLS);
        log_msg("Hashing an entry {} from {}", {hashedKey, hdr.db_entries[0].entryId});
        // Add entry to the hash table
        database.write((bit<32>)hashedKey, tmpTuple);
        // Remove the entry from the header stack to be able to push it to the circulate pipeline
        hdr.db_entries.pop_front(1);
    }

    /**
    * Lock the database by writing the relation Id.
    */
    action lock_database() {
        relationIdRegister.write((bit<32>)0, hdr.db_relation.relationId);
    }

    /**
    *   Decrement the IPv4 length by 12 bytes for removing an entry from the db_entry header stack.
    */
    action dec_length_of_dbentry() {
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 12;
    }

    apply {

        if (hdr.db_entries[0].isValid()) {
            bit<7> db_relationId;
            // Read out bottom of stack flag to figure out if we have reached the last entry.
            bit<1> bosReached = hdr.db_entries[0].bos;

            relationIdRegister.read(db_relationId, (bit<32>)0);

            // If relationId register is empty (=0), then hash table is probably empty.
            // That's why let's lock the database by writing the relationId
            if (db_relationId == 0) {
                lock_database();
            }

            // If the relationId in the packet is the same from the register, then add entries
            // otherwise it is an INNER JOIN operation
            if (db_relationId == hdr.db_relation.relationId) {
                // Operation to insert entries
                meta.dbEntry_meta.containsReply = false;
                db_update();
                dec_length_of_dbentry();
            } else {
                // INNER JOIN Operation
                bit<16> hashedKey = 0;
                bit<64> tmpTuple = 0;
                bit<32> secondAttr = 0;
                bit<32> thirdAttr = 0;

                // Hash primary key (entryId)
                hash(hashedKey, HashAlgorithm.crc16, (bit<32>)0, { hdr.db_entries[0].entryId }, (bit<32>)NB_CELLS);
                // Read entry from hash table
                database.read(tmpTuple, (bit<32>)hashedKey);
                // Decode the value from the register
                secondAttr = tmpTuple[63:32];
                thirdAttr = tmpTuple[31:0];
                // Check if primary key has been found
                // If the value from the register is 0, then we assume that there weren't any entries for that key.
                if (secondAttr != 0 && thirdAttr != 0) {
                    // Primary key exists in hash table. Do the JOIN
                    meta.dbEntry_meta.containsReply = true;
                    // Add a new entry in reply header stack
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
                    // Increase by 8 bytes for adding two addition fields => Diff db_entry and db_reply_entry
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen + 8;
                } else {
                    // Primary key has not been found in the hash table
                    // Decrement the IPv4 length as we are removing the entry from the header stack.
                    dec_length_of_dbentry();
                }
                hdr.db_entries.pop_front(1);
            }

            // If we haven't reached the bottom of stack of the db_entries header stack,
            // then we recirculate this modified packet again to loop over the whole header stack.
            if (hdr.db_entries[0].isValid() && bosReached != 1) {
                recirculate_preserving_field_list((bit<8>)FieldLists.resubmit_FL);
            }

            if (bosReached == 1) {
                // If we have reached the bottom of stack, check if we have added any reply headers
                if (meta.dbEntry_meta.containsReply != true) {
                    // If there are not any reply headers, then remove the relation header and set the next protocol to UDP
                    hdr.ipv4.protocol = TYPE_UDP;
                    hdr.db_relation.setInvalid();
                    // Decrement IPv4 length as we have removed the db_relation header.
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen - 1;
                } else {
                    // If our header stack contains a reply, then set the flag in the relation header.
                    hdr.db_relation.isReply = 1;
                    hdr.db_relation.replyJoinedRelationId = db_relationId;
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
