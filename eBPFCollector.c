#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#define TELEMETRY_REPORT_VERSION 2
#define INT_VERSION 2
#define INT_MX 3
#define INT_MD 1

#define INT_DST_PORT _INT_DST_PORT
#define MAX_INT_HOP _MAX_INT_HOP

#define CURSOR_ADVANCE(_target, _cursor, _len, _data_end) \
    ({  _target = _cursor; _cursor += _len; \
        if(unlikely(_cursor > _data_end)) return XDP_DROP; })

#define CURSOR_ADVANCE_NO_PARSE(_cursor, _len, _data_end) \
    ({  _cursor += _len; \
        if(unlikely(_cursor > _data_end)) return XDP_DROP; })

#define CURSOR_COPY(_target, _cursor, _len, _data_end) \
    ({  _target = *(typeof(_target)*)_cursor; _cursor += _len; \
        if(unlikely(_cursor > _data_end)) return XDP_DROP; })


#if defined(__BIG_ENDIAN_BITFIELD)
#define ntohll(x) (x)
#elif defined(__LITTLE_ENDIAN_BITFIELD)
#define ntohll(x) ((((__u64)ntohl(x)) << 32) + ntohl(x >> 32))
#else
#error  "Please fix <asm/byteorder.h>"
#endif

/********************************************************************
************************ P R O T O C O L S **************************
********************************************************************/

struct shim_header_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8  int_type:4,
          npt:2,
          rsvd1:2;
    __u8  len;
    __u8  rsvd2;
    __u8  original_dscp:6,
          rsvd3:2;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8  rsvd3:2,
          original_dscp:6;
    __u8  rsvd2;
    __u8  len;
    __u8  rsvd1:2,
          npt:2,
          int_type:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

struct int_header1_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u32 ver:4,
          d:1,
          e:1,
          m:1,
          rsvd:12,
          hop_ml:5,
          hop_count:8;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u32 hop_count:8,
          hop_ml:5,    
          rsvd:12,
          m:1,
          e:1,
          d:1,
          ver:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

struct int_header2_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u16 instruction_mask;
    __u16 domain_specific_id;
    __u16 ds_instruction;
    __u16 ds_flags;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u16 ds_flags;
    __u16 ds_instruction;
    __u16 domain_specific_id;
    __u16 instruction_mask;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

struct report_group_header_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u32 ver:4,
          hw_id:6,
          seq_no:22;
    __u32 node_id;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u32 node_id;
    __u32 seq_no:22,
          hw_id:6,
          ver:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

struct individual_report_header_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u8  rep_type:4,
          in_type:4;
    __u8  len;
    __u8  rep_md_len;
    __u8  d:1,
          q:1,
          f:1,
          i:1,
          rsvd:4;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u8  rsvd:4,
          i:1,
          f:1,
          q:1,
          d:1;
    __u8  rep_md_len;
    __u8  len;
    __u8  in_type:4,
          rep_type:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));

struct main_contents_header_t {
#if defined(__BIG_ENDIAN_BITFIELD)
    __u16 rep_md_bits;
    __u16 domain_specific_id;
    __u16 domain_specific_md_bits;
    __u16 domain_specific_md_status;
#elif defined(__LITTLE_ENDIAN_BITFIELD)
    __u16 domain_specific_md_status;
    __u16 domain_specific_md_bits;
    __u16 domain_specific_id;
    __u16 rep_md_bits;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
} __attribute__((packed));



struct db_entry {
    __u8  int_mode;
    __u8  length;
    __u8  hop_ml;
    __u8  quantity;
    __u16 packet_id;

    __u8 is_node_id;
    __u8 is_level1[2];
    __u8 is_hop_latency[2];
    __u8 is_queue[2];
    __u8 is_ingress_time[2];
    __u8 is_egress_time[2];
    __u8 is_level2[2];
    __u8 is_tx_utilization[2];
    __u8 is_buffer[2];
    __u8 is_drop_reason;

    __u32 node_id[MAX_INT_HOP];
    __u16 lvl1_ingr_id[MAX_INT_HOP];
    __u16 lvl1_egr_id[MAX_INT_HOP];
    __u32 hop_latency[MAX_INT_HOP];
    __u8  queue_id[MAX_INT_HOP];
    __u32 queue_occupancy[MAX_INT_HOP];
    __u64 ingr_timestamp[MAX_INT_HOP];
    __u64 egr_timestamp[MAX_INT_HOP];
    __u32 lvl2_ingr_id[MAX_INT_HOP];
    __u32 lvl2_egr_id[MAX_INT_HOP];
    __u32 tx_utilization[MAX_INT_HOP];
    __u8  buffer_id[MAX_INT_HOP];
    __u32 buffer_occupancy[MAX_INT_HOP];
    __u8  queue_id2;
    __u8  drop_reason;
    __u16  padding;
};

BPF_RINGBUF_OUTPUT(events, 64);
BPF_PROG_ARRAY(functions, 1);
BPF_ARRAY(data, struct db_entry, 1);

/*********************************************************************
**************************** P A R S E R *****************************
*********************************************************************/

int collector(struct xdp_md *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;

    // Parse outer: Ether -> IP -> UDP -> TelemetryReport

    struct ethhdr *eth;
    CURSOR_ADVANCE(eth, cursor, sizeof(*eth), data_end);

    if (unlikely(ntohs(eth->h_proto) != ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip;
    CURSOR_ADVANCE(ip, cursor, sizeof(*ip), data_end);

    if (unlikely(ip->protocol != IPPROTO_UDP)) return XDP_PASS;
    struct udphdr *udp;
    CURSOR_ADVANCE(udp, cursor, sizeof(*udp), data_end);

    if (unlikely(ntohs(udp->dest) != INT_DST_PORT)) return XDP_PASS;
    struct report_group_header_t *grouphdr;
    __u64 *temp;
    CURSOR_ADVANCE(temp, cursor, sizeof(*grouphdr), data_end);
    *temp = ntohll(*temp);
    grouphdr = temp;

    if (unlikely(grouphdr->ver != TELEMETRY_REPORT_VERSION)) return XDP_DROP;
    struct individual_report_header_t *individualhdr;
    __u32 *temp1;
    CURSOR_ADVANCE(temp1, cursor, sizeof(*individualhdr), data_end);
    *temp1 = ntohl(*temp1);
    individualhdr = temp1;

    if (unlikely(individualhdr->rep_type != 1)) return XDP_DROP;
    struct main_contents_header_t *mainhdr;
    __u64 *temp2;
    CURSOR_ADVANCE(temp2, cursor, sizeof(*mainhdr), data_end);
    *temp2 = ntohll(*temp2);
    mainhdr = temp2;

    if (unlikely(individualhdr->in_type != 4)) return XDP_DROP;
    
    __u8  report_length = individualhdr->len;
    __u8  rep_md_len = individualhdr->rep_md_len;
    __u16 INT_ins = mainhdr->rep_md_bits;

    struct db_entry entry;
    entry.node_id[0] = grouphdr->node_id;

    entry.is_level1[0]         = (INT_ins >> 14) & 0x1;
    entry.is_hop_latency[0]    = (INT_ins >> 13) & 0x1;
    entry.is_queue[0]          = (INT_ins >> 12) & 0x1;
    entry.is_ingress_time[0]   = (INT_ins >> 11) & 0x1;
    entry.is_egress_time[0]    = (INT_ins >> 10) & 0x1;
    entry.is_level2[0]         = (INT_ins >> 9) & 0x1;
    entry.is_tx_utilization[0] = (INT_ins >> 8) & 0x1;
    entry.is_buffer[0]    	   = (INT_ins >> 7) & 0x1;
    entry.is_drop_reason       = (INT_ins) & 0x1;


    if (entry.is_level1[0]) {
        __u32 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
        temp3 = ntohl(temp3);
        __u16 *temp4 = (__u16*)&temp3;
        #if defined(__BIG_ENDIAN_BITFIELD)
        entry.lvl1_ingr_id[0] = *temp4;
        entry.lvl1_egr_id[0] = *(temp4 + 1);
        #elif defined(__LITTLE_ENDIAN_BITFIELD)
        entry.lvl1_ingr_id[0] = *(temp4 + 1);
        entry.lvl1_egr_id[0] = *temp4;
        #else
        #error  "Please fix <asm/byteorder.h>"
        #endif
    }

    if (entry.is_hop_latency[0]) {
        __u32 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(entry.hop_latency[0]), data_end);
        entry.hop_latency[0] = ntohl(temp3);
    }

    if (entry.is_queue[0]) {
        __u32 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
        temp3 = ntohl(temp3);
        __u8 *temp4 = (__u8*)&temp3;
        #if defined(__BIG_ENDIAN_BITFIELD)
        entry.queue_id[0] = *temp4;
        entry.queue_occupancy[0] = temp3 & 0xFFFFFF;
        #elif defined(__LITTLE_ENDIAN_BITFIELD)
        entry.queue_id[0] = *(temp4 + 3);
        entry.queue_occupancy[0] = temp3 & 0xFFFFFF;
        #else
        #error  "Please fix <asm/byteorder.h>"
        #endif
    }

    if (entry.is_ingress_time[0]) {
        __u64 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(entry.ingr_timestamp[0]), data_end);
        entry.ingr_timestamp[0] = ntohll(temp3);
    }

    if (entry.is_egress_time[0]) {
        __u64 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(entry.egr_timestamp[0]), data_end);
        entry.egr_timestamp[0] = ntohll(temp3);
    }

    if (entry.is_level2[0]) {
        __u64 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
        temp3 = ntohll(temp3);
        __u32 *temp4 = (__u32*)&temp3;
        #if defined(__BIG_ENDIAN_BITFIELD)
        entry.lvl2_ingr_id[0] = *temp4;
        entry.lvl2_egr_id[0] = *(temp4 + 1);
        #elif defined(__LITTLE_ENDIAN_BITFIELD)
        entry.lvl2_ingr_id[0] = *(temp4 + 1);
        entry.lvl2_egr_id[0] = *temp4;
        #else
        #error  "Please fix <asm/byteorder.h>"
        #endif
    }

    if (entry.is_tx_utilization[0]) {
        __u32 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(entry.tx_utilization[0]), data_end);
        entry.tx_utilization[0] = ntohl(temp3);
    }

    if (entry.is_buffer[0]) {
        __u32 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
        temp3 = ntohl(temp3);
        __u8 *temp4 = (__u8*)&temp3;
        #if defined(__BIG_ENDIAN_BITFIELD)
        entry.buffer_id[0] = *temp4;
        entry.buffer_occupancy[0] = temp3 & 0xFFFFFF;
        #elif defined(__LITTLE_ENDIAN_BITFIELD)
        entry.buffer_id[0] = *(temp4 + 3);
        entry.buffer_occupancy[0] = temp3 >> 8;
        #else
        #error  "Please fix <asm/byteorder.h>"
        #endif
    }

    if (entry.is_drop_reason) {
        __u32 temp3;
        CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
        temp3 = ntohl(temp3);
        __u8 *temp4 = (__u8*)&temp3;
        #if defined(__BIG_ENDIAN_BITFIELD)
        entry.queue_id2 = *temp4;
        entry.drop_reason = *(temp4 + 1);
        entry.padding = temp3 & 0xFFFF;
        #elif defined(__LITTLE_ENDIAN_BITFIELD)
        entry.queue_id2 = *(temp4 + 3);
        entry.drop_reason = *(temp4 + 2);
        entry.padding = temp3 & 0xFFFF;
        #else
        #error  "Please fix <asm/byteorder.h>"
        #endif
    }

    // Parse Inner: IP->UDP/TCP->INT

    struct iphdr *inner_ip;
    CURSOR_ADVANCE(inner_ip, cursor, sizeof(*inner_ip), data_end);

    struct udphdr *inner_udp;
    struct tcphdr *inner_tcp;

    if (inner_ip->protocol == IPPROTO_UDP){
        CURSOR_ADVANCE(inner_udp, cursor, sizeof(*inner_udp), data_end);
        entry.packet_id = ntohs(inner_udp->check);
    } else if (inner_ip->protocol == IPPROTO_TCP){
        CURSOR_ADVANCE(inner_tcp, cursor, sizeof(*inner_tcp), data_end);
        entry.packet_id = ntohs(inner_tcp->check);
    } else {
        return XDP_DROP;
    }

    struct shim_header_t *shimhdr;
    __u32 *temp3;
    CURSOR_ADVANCE(temp3, cursor, sizeof(*shimhdr), data_end);
    *temp3 = ntohl(*temp3);
    shimhdr = temp3;
    entry.int_mode = shimhdr->int_type;

    struct int_header1_t *inthdr1;
    __u32 *temp4;
    CURSOR_ADVANCE(temp4, cursor, sizeof(*inthdr1), data_end);
    *temp4 = ntohl(*temp4);
    inthdr1 = temp4;

    struct int_header2_t *inthdr2;
    __u64 *temp5;
    CURSOR_ADVANCE(temp5, cursor, sizeof(*inthdr2), data_end);
    *temp5 = ntohll(*temp5);
    inthdr2 = temp5;

    if (unlikely(inthdr1->ver != INT_VERSION)) return XDP_DROP;

    if (entry.int_mode == INT_MD){
        entry.length = shimhdr->len;
        entry.hop_ml = inthdr1->hop_ml;
        __u16 bitmap = inthdr2->instruction_mask;

        entry.is_node_id           = (bitmap >> 15) & 0x1;
        entry.is_level1[1]         = (bitmap >> 14) & 0x1;
        entry.is_hop_latency[1]    = (bitmap >> 13) & 0x1;
        entry.is_queue[1]          = (bitmap >> 12) & 0x1;
        entry.is_ingress_time[1]   = (bitmap >> 11) & 0x1;
        entry.is_egress_time[1]    = (bitmap >> 10) & 0x1;
        entry.is_level2[1]         = (bitmap >> 9) & 0x1;
        entry.is_tx_utilization[1] = (bitmap >> 8) & 0x1;
        entry.is_buffer[1]    	   = (bitmap >> 7) & 0x1;
        
        __u32 key = 0;
        data.update(&key, &entry);
        __u32 index = 0;
        functions.call(ctx, index);

    } else if (entry.int_mode == INT_MX){
        events.ringbuf_output(&entry, sizeof(entry), 0);
    }

    return XDP_DROP;
}

int extension(struct xdp_md *ctx){
    __u32 key = 0;
    struct db_entry* _entry = data.lookup(&key);
    if (unlikely(!_entry)) return XDP_DROP;
    struct db_entry entry = *_entry;

    void* data_end = (void*)(long)ctx->data_end;
    void* cursor = (void*)(long)ctx->data;

    struct individual_report_header_t *individualhdr;
    struct iphdr *inner_ip;
    CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct ethhdr), data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct iphdr), data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct udphdr), data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct report_group_header_t), data_end);
    CURSOR_ADVANCE(individualhdr, cursor, sizeof(*individualhdr), data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct main_contents_header_t), data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, 4 * individualhdr->rep_md_len, data_end);
    CURSOR_ADVANCE(inner_ip, cursor, sizeof(*inner_ip), data_end);
    if (inner_ip->protocol == IPPROTO_UDP){
        CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct udphdr), data_end);
    } else if (inner_ip->protocol == IPPROTO_TCP){
        CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct tcphdr), data_end);
    } else {
        return XDP_DROP;
    }
    CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct shim_header_t), data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct int_header1_t), data_end);
    CURSOR_ADVANCE_NO_PARSE(cursor, sizeof(struct int_header2_t), data_end);

    if (likely(entry.hop_ml != 0)) entry.quantity = (__u8)(entry.length - 3) / entry.hop_ml;

    #pragma unroll
    for (__u8 index = 1; index < MAX_INT_HOP; index += 1){
        
        if(index <= entry.quantity){

            if (entry.is_node_id) {
                __u32 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(entry.node_id[index]), data_end);
                entry.node_id[index] = ntohl(temp3);
            }

            if (entry.is_level1[1]) {
                __u32 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
                temp3 = ntohl(temp3);
                __u16 *temp4 = (__u16*)&temp3;
                #if defined(__BIG_ENDIAN_BITFIELD)
                entry.lvl1_ingr_id[index] = *temp4;
                entry.lvl1_egr_id[index] = *(temp4 + 1);
                #elif defined(__LITTLE_ENDIAN_BITFIELD)
                entry.lvl1_ingr_id[index] = *(temp4 + 1);
                entry.lvl1_egr_id[index] = *temp4;
                #else
                #error  "Please fix <asm/byteorder.h>"
                #endif
            }

            if (entry.is_hop_latency[1]) {
                __u32 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(entry.hop_latency[index]), data_end);
                entry.hop_latency[index] = ntohl(temp3);
            }

            if (entry.is_queue[1]) {
                __u32 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
                temp3 = ntohl(temp3);
                __u8 *temp4 = (__u8*)&temp3;
                #if defined(__BIG_ENDIAN_BITFIELD)
                entry.queue_id[index] = *temp4;
                entry.queue_occupancy[index] = temp3 & 0xFFFFFF;
                #elif defined(__LITTLE_ENDIAN_BITFIELD)
                entry.queue_id[index] = *(temp4 + 3);
                entry.queue_occupancy[index] = temp3 & 0xFFFFFF;
                #else
                #error  "Please fix <asm/byteorder.h>"
                #endif
            }

            if (entry.is_ingress_time[1]) {
                __u64 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(entry.ingr_timestamp[index]), data_end);
                entry.ingr_timestamp[index] = ntohll(temp3);
            }

            if (entry.is_egress_time[1]) {
                __u64 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(entry.egr_timestamp[index]), data_end);
                entry.egr_timestamp[index] = ntohll(temp3);
            }

            if (entry.is_level2[1]) {
                __u64 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
                temp3 = ntohll(temp3);
                __u32 *temp4 = (__u32*)&temp3;
                #if defined(__BIG_ENDIAN_BITFIELD)
                entry.lvl2_ingr_id[index] = *temp4;
                entry.lvl2_egr_id[index] = *(temp4 + 1);
                #elif defined(__LITTLE_ENDIAN_BITFIELD)
                entry.lvl2_ingr_id[index] = *(temp4 + 1);
                entry.lvl2_egr_id[index] = *temp4;
                #else
                #error  "Please fix <asm/byteorder.h>"
                #endif
            }

            if (entry.is_tx_utilization[1]) {
                __u32 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(entry.tx_utilization[index]), data_end);
                entry.tx_utilization[index] = ntohl(temp3);
            }

            if (entry.is_buffer[1]) {
                __u32 temp3;
                CURSOR_COPY(temp3, cursor, sizeof(temp3), data_end);
                temp3 = ntohl(temp3);
                __u8 *temp4 = (__u8*)&temp3;
                #if defined(__BIG_ENDIAN_BITFIELD)
                entry.buffer_id[index] = *temp4;
                entry.buffer_occupancy[index] = temp3 & 0xFFFFFF;
                #elif defined(__LITTLE_ENDIAN_BITFIELD)
                entry.buffer_id[index] = *(temp4 + 3);
                entry.buffer_occupancy[index] = temp3 >> 8;
                #else
                #error  "Please fix <asm/byteorder.h>"
                #endif
            }
        }
    }
    
    events.ringbuf_output(&entry, sizeof(entry), 0);

    return XDP_DROP;
}
