import argparse
import threading
import time
import sys
import psycopg

import pyximport; pyximport.install()
import DBCollector

def parse_params():
    parser = argparse.ArgumentParser(description='InfluxDB INTCollector client')

    parser.add_argument("ifaces", nargs='+',
        help="List of ifaces to receive INT reports")

    parser.add_argument("-i", "--int_port", default=1234, type=int,
        help="Destination port of INT Telemetry reports")

    parser.add_argument("-u", "--url", default="http://localhost:8086",
        help="InfluxDB server address")

    parser.add_argument("-P", "--event_period", default=1.0, type=float,
        help="Time period to push event data")

    return parser.parse_args()


if __name__ == "__main__":

    args = parse_params()

    try: 
        collector = DBCollector.DBCollector(int_dst_port=args.int_port)
        collector.client.autocommit = True
        cursor = collector.client.cursor()
        cursor.execute("DROP DATABASE IF EXISTS \"intcollector\";")
        cursor.execute("CREATE DATABASE \"intcollector\";")
        cursor.close()
        collector.client.close()
        collector.client =  psycopg.connect("dbname=intcollector user=postgres")
        cursor = collector.client.cursor()
        cursor.execute("CREATE EXTENSION IF NOT EXISTS timescaledb;")
        cursor.execute("""CREATE TABLE \"int-mx\" (
                       time TIMESTAMPTZ NOT NULL,
                       \"node id\" INTEGER NOT NULL,
                       \"packet id\" INTEGER NOT NULL,
                       \"lvl1 ingr id\" INTEGER,
                       \"lvl1 egr id\" INTEGER,
                       \"hop latency\" INTEGER,
                       \"queue id\" INTEGER,
                       \"queue occupancy\" INTEGER,
                       \"ingress time\" INTEGER,
                       \"egress time\" INTEGER,
                       \"lvl2 ingress id\" INTEGER,
                       \"lvl2 egress id\" INTEGER,
                       \"tx utilization\" INTEGER,
                       \"buffer id\" INTEGER,
                       \"buffer occupancy\" INTEGER,
                       \"drop reason\" INTEGER);""")
        cursor.execute("SELECT create_hypertable('\"int-mx\"', by_range('time'));")
        cursor.execute("""CREATE TABLE \"int-md\" (
                          time TIMESTAMPTZ NOT NULL,
                          \"node id\" INTEGER[],
                          \"packet id\" INTEGER NOT NULL,
                          \"lvl1 ingr id\" INTEGER[],
                          \"lvl1 egr id\" INTEGER[],
                          \"hop latency\" INTEGER[],
                          \"queue id\" INTEGER[],
                          \"queue occupancy\" INTEGER[],
                          \"ingress time\" INTEGER[],
                          \"egress time\" INTEGER[],
                          \"lvl2 ingress id\" INTEGER[],
                          \"lvl2 egress id\" INTEGER[],
                          \"tx utilization\" INTEGER[],
                          \"buffer id\" INTEGER[],
                          \"buffer occupancy\" INTEGER[],
                          \"drop reason\" INTEGER[]);""")
        cursor.execute("SELECT create_hypertable('\"int-md\"', by_range('time'));")
        collector.client.commit()
        collector.client.autocommit = True
    except Exception as e:
        print("Error connecting to TimescaleDB", e)
        sys.exit(1)
        
    for iface in args.ifaces:
            collector.attach_iface(iface)

    push_stop_flag = threading.Event()

    def list_to_pg_array(pylist):
        return '{' + ','.join(map(str, pylist)) + '}'

    mx_query = """ INSERT INTO \"int-mx\" (
                time, \"node id\", \"packet id\", \"lvl1 ingr id\", \"lvl1 egr id\",
                \"hop latency\", \"queue id\", \"queue occupancy\", \"ingress time\",
                \"egress time\", \"lvl2 ingress id\", \"lvl2 egress id\", \"tx utilization\",
                \"buffer id\", \"buffer occupancy\", \"drop reason\")
                VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
    
    md_query = """INSERT INTO "int-md" (
            time, "node id", "packet id", "lvl1 ingr id", "lvl1 egr id",
            "hop latency", "queue id", "queue occupancy", "ingress time",
            "egress time", "lvl2 ingress id", "lvl2 egress id", "tx utilization",
            "buffer id", "buffer occupancy", "drop reason")
            VALUES (NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""

    def _event_push():

        while not push_stop_flag.is_set():
            time.sleep(args.event_period)

            collector.mx_lock.acquire()
            data_mx = collector.mx_data
            collector.mx_data = []
            collector.mx_lock.release()

            collector.md_lock.acquire()
            data_md = collector.md_data
            collector.md_data = []
            collector.md_lock.release()
            
            data_mx = [tuple(data) for data in data_mx]
            data_md = [tuple(data) for data in data_md]

            if data_mx:
                cursor.executemany(mx_query, data_mx)
            
            if data_md:
                data_md = [(list_to_pg_array(data[0]),) + data[1:4] + tuple(list_to_pg_array(d) if isinstance(d, list) else d for d in data[4:]) for data in data_md]
                cursor.executemany(md_query, data_md)
                
    event_push = threading.Thread(target=_event_push)
    event_push.start()

    collector.open_events()
    print("eBPF program loaded")
    sys.stdout.flush()

    try:
        while True:
            collector.bpf_collector.ring_buffer_poll()

    except KeyboardInterrupt:
        pass

    finally:
        push_stop_flag.set()
        print("\nExiting...")
        collector.detach_all_iface()
        event_push.join()
        cursor.close()
        collector.client.close()