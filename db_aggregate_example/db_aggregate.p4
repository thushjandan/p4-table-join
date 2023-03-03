/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* Max hash table cells */
#define NB_CELLS 65536

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_MYP4DB = 0xFA;

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
    bit<1>  aggregate;
}

header db_tuple_t {
    db_attribute_t  entryId;
    db_attribute_t  secondAttr;
    db_attribute_t  thirdAttr;
}

struct metadata {
    
}

struct headers {
    ethernet_t          ethernet;
    ipv4_t              ipv4;
    db_relation_t       db_relation;
    db_tuple_t          db_tuple;
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
        transition parse_entries;
    }

    /*  Parse the db_tuple header */
    state parse_entries {
        packet.extract(hdr.db_tuple);
        transition accept;
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
    
    // Initialize hash table
    register<bit<64>>(NB_CELLS) database;

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

    table relation_reply_table {
        key = {
            hdr.db_relation.aggregate: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        const entries = {
            (0) : drop();
            (1) : NoAction();
        }
        default_action = NoAction();
    }

    apply {
        // Run IPv4 routing logic.
        ipv4_lpm.apply();

        if (hdr.db_relation.isValid()) {
            // Insert tuple in the hash table
            bit<16> hashedKey = 0;
            bit<64> tmpTuple = 0;

            // Hash the primary key (entryId)
            hash(hashedKey, HashAlgorithm.crc16, (bit<32>)0, { hdr.db_tuple.entryId }, (bit<32>)NB_CELLS);
            log_msg("Hashing an entry {} from {}", {hashedKey, hdr.db_tuple.entryId});

            // Read entry from hash table
            database.read(tmpTuple, (bit<32>)hashedKey);

            // SUM the values
            tmpTuple[63:32] = tmpTuple[63:32] + hdr.db_tuple.secondAttr;
            tmpTuple[31:0] = tmpTuple[31:0] + hdr.db_tuple.thirdAttr;

            // Add entry to the hash table
            database.write((bit<32>)hashedKey, tmpTuple);

            // Prepare response
            hdr.db_tuple.secondAttr = tmpTuple[63:32];
            hdr.db_tuple.thirdAttr = tmpTuple[31:0];
            // Drop packet after processing in case no reply is requested
            relation_reply_table.apply();
        }    
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    
    apply {

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
        packet.emit(hdr.db_tuple);
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
