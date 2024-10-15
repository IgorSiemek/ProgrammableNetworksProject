/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_ICMP = 1;
const bit<8>  TYPE_UDP = 17;

const bit<32> DOS_THRESHOLD = 10;  // Maximum allowed packets from a single IP can be fixed!

#define BLOOM_FILTER_ENTRIES 4096
#define BLOOM_FILTER_BIT_WIDTH 1

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
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
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: tcp;
            TYPE_ICMP: accept;  // ICMP packets don't need further parsing
            TYPE_UDP: udp;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

    state udp {
        packet.extract(hdr.udp);
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

    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_1;
    register<bit<BLOOM_FILTER_BIT_WIDTH>>(BLOOM_FILTER_ENTRIES) bloom_filter_2;

    // Register to track the number of packets per source IP
    register<bit<32>>(BLOOM_FILTER_ENTRIES) packet_count_register;

    //register counters for drop and forward
    register<bit<32>>(1) drop_count_register;
    register<bit<32>>(1) forward_count_register;

    //last reset time register
    register<bit<48>>(1) last_reset_time;

    bit<32> reg_pos_one; bit<32> reg_pos_two;
    bit<1> reg_val_one; bit<1> reg_val_two;
    bit<1> direction;
    

    action drop() {
        bit<32> drop_count;
        drop_count_register.read(drop_count, 0);
        drop_count = drop_count + 1;
        drop_count_register.write(0, drop_count);
        mark_to_drop(standard_metadata);
    }

    action compute_hashes(ip4Addr_t ipAddr1, ip4Addr_t ipAddr2, bit<16> port1, bit<16> port2){
       //Get register position
       hash(reg_pos_one, HashAlgorithm.crc16, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);

       hash(reg_pos_two, HashAlgorithm.crc32, (bit<32>)0, {ipAddr1,
                                                           ipAddr2,
                                                           port1,
                                                           port2,
                                                           hdr.ipv4.protocol},
                                                           (bit<32>)BLOOM_FILTER_ENTRIES);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        bit<32> forward_count;
        forward_count_register.read(forward_count, 0);
        forward_count = forward_count + 1;
        forward_count_register.write(0, forward_count);

        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action set_packet_count_register(ip4Addr_t srcAddr, ip4Addr_t dstAddr, bit<32> packet_count) 
    {
        bit<32> pos_1;
        bit<32> pos_2;

        hash(pos_1, HashAlgorithm.crc16, (bit<32>)0, {srcAddr}, (bit<32>)BLOOM_FILTER_ENTRIES);
        hash(pos_2, HashAlgorithm.crc16, (bit<32>)0, {dstAddr}, (bit<32>)BLOOM_FILTER_ENTRIES);

        packet_count_register.write(pos_1, packet_count);
        packet_count_register.write(pos_2, packet_count);
    }

    //Dos check action
    action check_dos(out bit<1> exceed_threshold, ip4Addr_t srcAddr, ip4Addr_t dstAddr) {
        bit<32> packet_count;
        bit<48> current_time;
        bit<48> last_reset;
        
        // Compute hash position in the register for the source IP
        bit<32> reg_pos;
        hash(reg_pos, HashAlgorithm.crc16, (bit<32>)0, {srcAddr}, (bit<32>)BLOOM_FILTER_ENTRIES);
        
        // Read the packet count from the register
        packet_count_register.read(packet_count, reg_pos);        

        // Increment the packet count
        packet_count = packet_count + 1;

        // Write the updated packet count back to the register
        //packet_count_register.write(reg_pos, packet_count);

        // Get the current timestamp in useconds/nanoseconds
        current_time = standard_metadata.ingress_global_timestamp;
        last_reset_time.read(last_reset, 0);
        
        if (current_time - last_reset >= 10000000) {
            packet_count = 0;
            last_reset = current_time;
        }
        last_reset_time.write(0, last_reset);
        set_packet_count_register(srcAddr, dstAddr, packet_count);

        // Drop packet if the threshold is exceeded
        if (packet_count > DOS_THRESHOLD) {
            exceed_threshold = 1;
        } else {
            exceed_threshold = 0;
        }
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

    action set_direction(bit<1> dir) {
        direction = dir;
    }

    table check_ports {
        key = {
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_direction;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // Define a table for firewall (access control list)
    table ipv4_acl {
        key = {
            hdr.ipv4.srcAddr: lpm;
            hdr.ipv4.dstAddr: lpm;
            hdr.ipv4.protocol: exact;
            hdr.tcp.srcPort: exact;
            hdr.tcp.dstPort: exact;
        }
        actions = {
            drop;  // Drop the packet
            NoAction;  // Allow the packet (default action)
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        bit<1> exceed_threshold;

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            
            if (hdr.ipv4.protocol == TYPE_ICMP) {

                check_dos(exceed_threshold, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr);
                //If DoS threshold is exceeded, drop the packet
                if (exceed_threshold == 1) {
                    drop();
                }
            }
            // Check if the protocol is UDP and comes from host 10.0.4.4 in hex 32w0x0A000404
            else if (hdr.udp.isValid() && hdr.ipv4.srcAddr == 32w0x0A000404) {
                log_msg("Drop UDP packet from specific source");
                drop();
            }
            else {
                if (hdr.tcp.isValid()) {
                    direction = 0; // default
                    if (check_ports.apply().hit) {
                        if (direction == 0) {
                            compute_hashes(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort);
                        } else {
                            compute_hashes(hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort);
                        }

                        // Packet comes from external network
                        if (direction == 1) {
                            bloom_filter_1.read(reg_val_one, reg_pos_one);
                            bloom_filter_2.read(reg_val_two, reg_pos_two);

                            // If the entries are not set in the bloom filter, drop the packet
                            if (reg_val_one != 1 || reg_val_two != 1) {
                                drop();  // Move the drop call here directly
                            }
                        }
                    }
                }
            }
        }
    }


}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
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
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
