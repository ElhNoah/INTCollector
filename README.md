# INTCollector
This project is a further development based on [INTCollector by ana13zs](https://github.com/ana13zs/intcollector), which is a high-performance collector to process INT Telemetry reports, and send data to database server. This new version is specifically designed to work with INT Telemetry reports v2.0 and uses PostgreSQL with TimeScaleDB extension as the database backend.
## Requirements
- [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc)
- [PostgreSQL](https://www.postgresql.org/download/)
    - [TimeScaleDB extension](https://github.com/timescale/timescaledb)

Additionally, the following Python packages are required:
- [psycopg](https://pypi.org/project/psycopg/)
- [Cython](https://pypi.org/project/Cython/)

Install them using pip: `pip3 install psycopg Cython`

Before continuing, load the TimeScaleDB extension in PostgreSQL and activate the database server.
```sh
service postgresql start
psql -U postgres -c 'SHOW config_file'  # Check PostgreSQL config file location
echo "shared_preload_libraries = 'timescaledb'" >> $CONFIG_FILE # Add TimeScaleDB to shared_preload_libraries
service postgresql restart
```

## Usage
Clone this repository:
```sh
git clone https://github.com/ElhNoah/INTCollector.git
cd INTCollector
```

Run INTCollector listing which network interface to monitor:
```sh
sudo python3 DBClient.py eth0 eth1 & # in this example, INTCollector will run on interfaces eth0 and eth1
```

The script will create a database named `intcollector` which contains 2 tables: `int-mx` and `int-md`. The 2 tables will be automatically updated as INT Telemetry reports are received by one of the monitored interfaces.

## Troubleshooting
If you encounter any authentication issues when connecting to PostgreSQL, set the postgres database without authentication:
```sh
psql -U postgres -c 'SHOW hba_file'  # Check pg_hba.conf file location
echo "local all postgres trust" >> $HBA_FILE