import threading
from bcc import BPF
import psycopg
import ctypes as ct
from libc.stdint cimport uintptr_t
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t


cdef enum: MAX_HOP = 4
cdef struct db_entry:
    uint8_t  int_mode
    uint8_t  length
    uint8_t  hop_ml
    uint8_t  quantity
    uint16_t packet_id

    uint8_t is_node_id
    uint8_t is_level1[2]
    uint8_t is_hop_latency[2]
    uint8_t is_queue[2]
    uint8_t is_ingress_time[2]
    uint8_t is_egress_time[2]
    uint8_t is_level2[2]
    uint8_t is_tx_utilization[2]
    uint8_t is_buffer[2]
    uint8_t is_drop_reason

    uint32_t node_id[MAX_HOP]
    uint16_t lvl1_ingr_id[MAX_HOP]
    uint16_t lvl1_egr_id[MAX_HOP]
    uint32_t hop_latency[MAX_HOP]
    uint8_t  queue_id[MAX_HOP]
    uint32_t queue_occupancy[MAX_HOP]
    uint64_t ingr_timestamp[MAX_HOP]
    uint64_t egr_timestamp[MAX_HOP]
    uint32_t lvl2_ingr_id[MAX_HOP]
    uint32_t lvl2_egr_id[MAX_HOP]
    uint32_t tx_utilization[MAX_HOP]
    uint8_t  buffer_id[MAX_HOP]
    uint32_t buffer_occupancy[MAX_HOP]
    uint8_t  queue_id2
    uint8_t  drop_reason
    uint16_t padding


class DBCollector(object):

    def __init__(self, int_dst_port=1234):

        self.MAX_INT_HOP = MAX_HOP
        self.INT_DST_PORT = int_dst_port
        self.ifaces = set()

        self.bpf_collector = BPF(src_file="eBPFCollector.c", debug=0,
            cflags=["-w",
                    "-D_MAX_INT_HOP=%s" % self.MAX_INT_HOP,
                    "-D_INT_DST_PORT=%s" % self.INT_DST_PORT])
        self.fn_collector = self.bpf_collector.load_func("collector", BPF.XDP)

        self.mx_lock = threading.Lock()
        self.mx_data = []

        self.md_lock = threading.Lock()
        self.md_data = []

        self.client = psycopg.connect("dbname=postgres user=postgres")


    def attach_iface(self, iface):
        if iface in self.ifaces:
            return
        self.bpf_collector.attach_xdp(iface, self.fn_collector, 0)
        extension = self.bpf_collector.load_func("extension", BPF.XDP)
        prog_array = self.bpf_collector.get_table("functions")
        prog_array[ct.c_int(0)] = ct.c_int(extension.fd)
        self.ifaces.add(iface)

    def detach_all_iface(self):
        for iface in self.ifaces:
            self.bpf_collector.remove_xdp(iface, 0)
        self.ifaces = set()

    def open_events(self):
        def _process_event(ctx, data, size):

            cdef uintptr_t _entry =  <uintptr_t> data
            cdef db_entry *entry = <db_entry*> _entry

            i = entry.quantity + 1


            data = [None] * 15
            
            if entry.int_mode == 3:
                data[0] = entry.node_id[0]
                data[1] = entry.packet_id
                if entry.is_level1[0]:
                    data[2] = entry.lvl1_ingr_id[0]
                    data[3] = entry.lvl1_egr_id[0]
                if entry.is_hop_latency[0]:
                    data[4] = entry.hop_latency[0]
                if entry.is_queue[0]:
                    data[5] = entry.queue_id[0]
                    data[6] = entry.queue_occupancy[0]
                if entry.is_ingress_time[0]:
                    data[7] = entry.ingr_timestamp[0]
                if entry.is_egress_time[0]:
                    data[8] = entry.egr_timestamp[0]
                if entry.is_level2[0]:
                    data[9] = entry.lvl2_ingr_id[0]
                    data[10] = entry.lvl2_egr_id[0]
                if entry.is_tx_utilization[0]:
                    data[11] = entry.tx_utilization[0]
                if entry.is_buffer[0]:
                    data[12] = entry.buffer_id[0]
                    data[13] = entry.buffer_occupancy[0]
                if entry.is_drop_reason:
                    data[14] = entry.drop_reason
                self.mx_lock.acquire()
                self.mx_data.append(data)
                self.mx_lock.release()
            elif entry.int_mode == 1:
                if entry.is_node_id:
                    data[0] = [entry.node_id[j] for j in range(i)]
                data[1] = entry.packet_id
                if entry.is_level1[1]:
                    data[2] = [entry.lvl1_ingr_id[j] for j in range(i)]
                    data[3] = [entry.lvl1_egr_id[j] for j in range(i)]
                if entry.is_hop_latency[1]:
                    data[4] = [entry.hop_latency[j] for j in range(i)]
                if entry.is_queue[1]:
                    data[5] = [entry.queue_id[j] for j in range(i)]
                    data[6] = [entry.queue_occupancy[j] for j in range(i)]
                if entry.is_ingress_time[1]:
                    data[7] = [entry.ingr_timestamp[j] for j in range(i)]
                if entry.is_egress_time[1]:
                    data[8] = [entry.egr_timestamp[j] for j in range(i)]
                if entry.is_level2[1]:
                    data[9] = [entry.lvl2_ingr_id[j] for j in range(i)]
                    data[10] = [entry.lvl2_egr_id[j] for j in range(i)]
                if entry.is_tx_utilization[1]:
                    data[11] = [entry.tx_utilization[j] for j in range(i)]
                if entry.is_buffer[1]:
                    data[12] = [entry.buffer_id[j] for j in range(i)]
                    data[13] = [entry.buffer_occupancy[j] for j in range(i)]
                if entry.is_drop_reason:
                    data[14] = entry.drop_reason
                self.md_lock.acquire()
                self.md_data.append(data)
                self.md_lock.release()     

        self.bpf_collector["events"].open_ring_buffer(_process_event)
