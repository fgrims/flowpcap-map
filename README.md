# network_datasets

Tools to link the **flows** of the CIC intrusion-detection datasets (CIC-IDS2017, CSE-CIC-IDS2018) to the **raw packets** they were computed from.

The CIC datasets ship two separate things:

- **PCAP captures** with the raw traffic of each day;
- **flow CSVs** produced by CICFlowMeter, one row per flow with ~80 statistical features and a **label** (`BENIGN`, `DDoS`, `Portscan`, ...).

Nothing in the datasets tells you which packets belong to which flow. This project rebuilds that mapping once and stores it in a small SQLite index per day. You can then:

- get all the raw packets of a flow (or of every flow with a given label);
- go the other way: given a packet in a PCAP, get the flow it belongs to and its label.

Packets are **never copied or extracted**. The index stores only *where* each packet is in the original PCAP (file + byte offset), and packets are read on demand with a single `seek()`.

---

## Table of contents

1. [How it works](#how-it-works)
2. [Repository layout](#repository-layout)
3. [Requirements](#requirements)
4. [Getting the data](#getting-the-data)
5. [Building the index](#building-the-index)
6. [Index database schema](#index-database-schema)
7. [Querying the index](#querying-the-index)
8. [Limitations and caveats](#limitations-and-caveats)

---

## How it works

```
 flows CSV (CICFlowMeter)              PCAP(s) of the same day
          │                                      │
          ▼                                      │
 1. build an in-memory flow index                │
    5-tuple → [(flow_id, start, end), ...]       │
          │                                      ▼
          └──────────────► 2. single pass over every packet:
                              - parse IP / TCP / UDP headers
                              - look up its 5-tuple (both directions)
                              - keep the flows whose time window
                                [start, start + duration] contains
                                the packet timestamp
                                         │
                                         ▼
                           3. SQLite index (<day>_index.db)
                              flow_id ↔ (pcap_file, byte offset)
                              flow_id → label
                                         │
                                         ▼
                           4. query_flows.py reads packets on demand
```

In more detail, `flow_indexer.py`:

1. **Reads the CSV** and gives every flow a unique id, `<row>_<label>_<dataset>` (e.g. `003741_DDoS_cic2017`), where `<row>` is the 1-based row number in the CSV. Each flow gets a time window: `[Timestamp, Timestamp + Flow Duration]`, optionally widened by a tolerance.
2. **Scans each PCAP once**, packet by packet. For each IPv4 packet it extracts `(src_ip, dst_ip, src_port, dst_port, protocol)` and looks it up in both directions, because CIC flows are bidirectional. Every flow whose time window contains the packet timestamp gets that packet. Packets whose IPs never appear in the CSV are skipped early.
3. **Writes the matches** to SQLite: one row per (flow, packet) with the PCAP path, the byte offset of the packet record and its captured length.
4. If the same packet matches more than one flow (same 5-tuple, overlapping time windows), it is stored once **per flow** and flagged `ambiguous = 1`.

With multiple PCAPs per day (e.g. CIC2018), the PCAPs are scanned in parallel, one worker process per file. The partial results are then merged into the final database.

---

## Repository layout

```
network_datasets/
├── README.md
├── datasets/
│   ├── cic2017/
│   │   ├── pcaps/                 ← put the CIC-IDS2017 PCAPs here
│   │   ├── flows/                 ← put the CIC-IDS2017 flow CSVs here
│   │   └── mapping_flow_packet/   ← index databases (generated)
│   └── cic2018/
│       ├── pcaps/                 ← put the CSE-CIC-IDS2018 PCAPs here
│       ├── flows/                 ← put the CSE-CIC-IDS2018 flow CSVs here
│       └── mapping_flow_packet/   ← index databases (generated)
└── scripts/
    ├── requirements.txt
    ├── config.example.json        ← template for the indexer config
    ├── flow_indexer.py            ← builds the index
    ├── query_flows.py             ← query functions on top of the index
    └── packet_to_label.py         ← example: packet → flow label, step by step
```

PCAPs, CSVs and `scripts/config.json` are git-ignored. Only the folder structure is versioned.

---

## Requirements

- **Python ≥ 3.10**
- **Linux**: the indexer uses `fork` to share the flow index with its worker processes.
- Enough **RAM** to hold one day of flows in memory (the CSV is loaded with pandas and indexed in a dict).
- **Disk**: the datasets are large (tens of GB for CIC2017, hundreds of GB for CIC2018). The index databases are small by comparison.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r scripts/requirements.txt
```

---

## Getting the data

The datasets are **not** downloaded by this project. Download the PCAPs and the flow CSVs yourself and place them in the folders below.

| Dataset         | PCAPs go in                 | Flow CSVs go in            |
|-----------------|-----------------------------|----------------------------|
| CIC-IDS2017     | `datasets/cic2017/pcaps/`   | `datasets/cic2017/flows/`  |
| CSE-CIC-IDS2018 | `datasets/cic2018/pcaps/`   | `datasets/cic2018/flows/`  |

Official sources:

- CIC-IDS2017: <https://www.unb.ca/cic/datasets/ids-2017.html>
- CSE-CIC-IDS2018: <https://www.unb.ca/cic/datasets/ids-2018.html>

### CIC-IDS2017

There is one PCAP per day (`Monday-WorkingHours.pcap`, ..., `Friday-WorkingHours.pcap`) and one CSV per day. Name the CSVs after the day (`monday.csv`, `tuesday.csv`, ...), because the CSV name becomes the name of the index folder (see [Output](#output)).

> **Note: use the re-extracted CIC-IDS2017 flows.**
> For CIC-IDS2017, download the flow CSVs from
> **<https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/>**
> instead of the original ones. These flows were re-extracted from the PCAPs with a fixed version of CICFlowMeter, with better flow timestamps. Since the indexer matches packets to flows by timestamp, this gives a much more accurate mapping.
>
> These CSVs differ slightly from the original ones:
> - timestamps are in UTC with microsecond precision (`2017-07-07 11:59:50.315195`), which matches the defaults in `config.example.json`;
> - some labels have an ` - Attempted` suffix (e.g. `Botnet - Attempted`), for attacks that did not succeed. There is also an extra `Attempted Category` column;
> - some label names differ from the original release (e.g. `Portscan`).

### CSE-CIC-IDS2018

There is one folder of PCAPs per day, with one capture file per host (file names often have no `.pcap` extension), and one CSV per day.

Recommended layout:

```
datasets/cic2018/pcaps/Friday-02-03-2018/<all PCAP files of that day>
datasets/cic2018/flows/Friday-02-03-2018.csv
```

Use the `Day-DD-MM-YYYY` naming for the CSVs (`Friday-02-03-2018.csv`, `Wednesday-14-02-2018.csv`, ...) so the index folders get the same names.

### PcapNG files

Only **classic PCAP** is supported. If a file is PcapNG, the indexer skips it with a warning. Convert it first:

```bash
editcap -F pcap input.pcapng output.pcap
```

---

## Building the index

### 1. Create the config

```bash
cp scripts/config.example.json scripts/config.json
```

Edit `scripts/config.json` and replace `/path/to/network_datasets` with the absolute path of your clone.

### 2. Config reference

Global keys. Every key marked *per pair* can also be set inside a single entry of `pairs` to override the global value.

| Key                     | Description | Default |
|-------------------------|-------------|---------|
| `dataset_name`          | Dataset tag used in the flow ids (`cic2017`, `cic2018`). | required |
| `index_dir`             | Output root. One sub-folder per CSV is created here. | required |
| `timestamp_format`      | `strptime` format of the CSV `Timestamp` column. If parsing fails, the same format without seconds is tried (CICFlowMeter sometimes drops them). *Per pair.* | `%Y-%m-%d %H:%M:%S.%f` |
| `timestamp_tz_offset_h` | UTC offset, in hours, of the CSV timestamps (`0` if they are UTC, `-3` for Canadian ADT, ...). PCAP timestamps are always UTC. *Per pair.* | `0` |
| `timestamp_tolerance_s` | Seconds added on each side of a flow's time window. Useful if CSV timestamps are rounded. *Per pair.* | `0` |
| `max_workers`           | Number of PCAPs scanned in parallel. | `--max-workers`, else `SLURM_CPUS_PER_TASK`, else `1` |
| `column_mapping`        | Names of the CSV columns used by the indexer: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `timestamp`, `flow_duration` (in µs), `label`. Instead of the five 5-tuple columns, you can give a `flow_id` column formatted as `src-dst-sport-dport-proto`. | required |
| `pairs`                 | List of CSV ↔ PCAP pairs, one per day (see below). | required |

Each entry of `pairs` has a `csv` path plus **one** of:

- `"pcaps": [...]`: explicit list of PCAP files;
- `"pcap": "..."`: a single PCAP file;
- `"pcap_dir": "..."`: a folder; every file in it (recursively) is treated as a PCAP. Convenient for CIC2018.

Example pair for CIC2018:

```json
{
  "csv":      "/path/to/network_datasets/datasets/cic2018/flows/Friday-02-03-2018.csv",
  "pcap_dir": "/path/to/network_datasets/datasets/cic2018/pcaps/Friday-02-03-2018",
  "timestamp_format": "%d/%m/%Y %H:%M:%S"
}
```

Use a separate config file per dataset (`dataset_name` and `index_dir` are global).

### 3. Run

```bash
cd scripts

# all pairs, one after the other
python flow_indexer.py config.json

# only one pair (0-based index in "pairs")
python flow_indexer.py config.json --pair-index 2

# override the number of parallel workers
python flow_indexer.py config.json --max-workers 8
```

On a SLURM cluster, `--pair-index $SLURM_ARRAY_TASK_ID` runs one day per array task. `max_workers` defaults to `SLURM_CPUS_PER_TASK`.

### Output

For each CSV the indexer creates:

```
<index_dir>/<csv name without extension>/<csv name without extension>_index.db
```

for example `datasets/cic2017/mapping_flow_packet/friday/friday_index.db`.

While it runs, `.parts/` (parallel mode) or `.tmp_*.db` files are created in the same folder. They are merged and deleted automatically at the end.

### Checking the result

The log reports, for each PCAP, the number of packets, how many were matched to a flow and how many were ambiguous:

```
[friday] 9,997,874 pkts | 8,431,005 matched | 1203 ambiguous | 312.4s
```

A **very low match rate** almost always means wrong timestamps: check `timestamp_tz_offset_h` and `timestamp_format`. Re-run with a different offset (or a small `timestamp_tolerance_s`) and compare.

---

## Index database schema

```sql
-- one row per (flow, packet) match
packet_offsets(
    flow_id   TEXT,     -- e.g. '003741_DDoS_cic2017'
    pcap_file TEXT,     -- PCAP path as written in the config
    offset    INTEGER,  -- byte offset of the packet record (its 16-byte header) in the PCAP
    caplen    INTEGER,  -- captured length of the packet data, in bytes
    ambiguous INTEGER   -- 1 if the same packet also matched other flows
)
-- indexes: idx_flow(flow_id), idx_pkt(pcap_file, offset)

-- one row per CSV flow (also flows with no matched packet)
flows(flow_id TEXT PRIMARY KEY, label TEXT)          -- index: idx_label(label)

-- one row per scanned PCAP: what is needed to decode its records
pcap_meta(pcap_file TEXT PRIMARY KEY, byte_order TEXT, ts_res TEXT, link_type INTEGER, snaplen INTEGER)
```

To read a packet: `seek(offset)` in `pcap_file`, read the 16-byte record header (timestamp, lengths), then read `caplen` bytes of packet data.

`pcap_file` is stored exactly as written in the config. **Do not move the PCAPs after indexing**, or packet reads will fail. Lookups by packet tolerate a different path to the same file and also fall back to matching the file name.

---

## Querying the index

All query functions are in `scripts/query_flows.py`.

### Setup

At the top of `query_flows.py`, set:

```python
PATH_TO_DBS = "/path/to/network_datasets/datasets/cic2018/mapping_flow_packet"   # folder with one sub-folder per day
DB = PATH_TO_DBS + "/Friday-02-03-2018/Friday-02-03-2018_index.db"              # default database
```

Then import it from your code (run from `scripts/`, or add `scripts/` to `PYTHONPATH`):

```python
import query_flows as q
```

Running `python query_flows.py` runs `example_packet_extraction()`, a short end-to-end demo.

### Common return values

- **packet record** (from `get_flow_packets`): `{'timestamp', 'data', 'link_type', 'pcap_file', 'offset', 'ambiguous'}`, where `data` contains the raw bytes of the packet starting from the link layer.
- **flow match** (from the packet → label functions): `{'flow_id', 'label', 'ambiguous'}`. The functions return a **list** of these:
  - empty list: the packet does not belong to any flow of the CSV;
  - one element: the normal case;
  - several elements: the packet is ambiguous and belongs to more than one flow.

### Flows and labels

| Function | Returns |
|----------|---------|
| `get_labels(db)` | All distinct labels in a database. |
| `get_flows_by_label(db, label)` | All `flow_id`s with that label, sorted. |
| `get_benign_flows(db=DB)` | `flow_id`s with label `BENIGN`, sorted by number of packets (largest first). |
| `get_malicious_flows(db=DB)` | `flow_id`s with any label other than `BENIGN` (`- Attempted` labels included), sorted by number of packets. |
| `get_all_benign_flows()` / `get_all_malicious_flows()` | Same as above, for every database in `PATH_TO_DBS`, concatenated. |
| `get_db_paths(path_to_dbs=PATH_TO_DBS)` | The `.db` file of each sub-folder of `path_to_dbs`. |

```python
for db in q.get_db_paths():
    print(db, q.get_labels(db))

ddos = q.get_flows_by_label(q.DB, "DDoS")
```

`get_all_*` only return flow ids. A flow id is unique only inside its own database (the row number restarts in each CSV), so keep track of the database if you need to read the packets later.

### Flow → packets

| Function | Returns |
|----------|---------|
| `get_flow_packets(db, flow_id)` | All packets of a flow, read from the PCAP, as packet records ordered by position in the file. |
| `get_packets_by_flows(db, flow_ids)` | Only the locations (`flow_id`, `pcap_file`, `offset`, `caplen`, `ambiguous`) of the packets of several flows, without reading the PCAP. Fast. Useful for counting packets or planning reads. |
| `get_packet_info(data, link_type)` | Decodes a raw packet: `{'src_ip', 'dst_ip', 'protocol', 'ttl', 'length', 'src_port', 'dst_port', 'tcp_flags'}`, or `None` if it is not IPv4. Supports Ethernet, Linux cooked capture (SLL) and raw IP. |

```python
packets = q.get_flow_packets(q.DB, ddos[0])
for p in packets:
    info = q.get_packet_info(p['data'], p['link_type'])
    print(p['timestamp'], info['src_ip'], info['src_port'], '→', info['dst_ip'], info['dst_port'])
```

`p['data']` can be passed to dpkt, scapy, or any feature extractor.

### Packet → flow label

A packet is identified by its **PCAP file** plus **one** of the following: its byte offset, its packet number, or its header fields.

| Function | Identify the packet by | Speed |
|----------|------------------------|-------|
| `get_packet_labels(db, pcap_file, offset)` | Byte offset of its record, e.g. the `offset` of a packet record. | Instant |
| `get_packet_labels_by_number(db, pcap_file, packet_number)` | Packet number, 1-based, as in Wireshark's **No.** column. | Reads the PCAP up to that packet |
| `get_packet_labels_by_fields(db, pcap_file, **fields)` | Header fields: IPs, ports, protocol, timestamp. | Reads the whole PCAP |
| `find_packet_labels(pcap_file, offset, path_to_dbs=PATH_TO_DBS)` | Like `get_packet_labels`, but finds by itself which database indexes that PCAP. | Instant |

```python
# by offset
q.get_packet_labels(q.DB, "/path/capture.pcap", 1834562)
# → [{'flow_id': '003741_DDoS_cic2017', 'label': 'DDoS', 'ambiguous': 0}]

# by packet number, as shown in Wireshark
q.get_packet_labels_by_number(q.DB, "/path/capture.pcap", 12345)

# by header fields: any field you leave out matches any value
results = q.get_packet_labels_by_fields(
    q.DB, "/path/capture.pcap",
    src_ip="172.31.69.25", dst_port=80, protocol="tcp",
    timestamp=1519917361.123456,
)
for r in results:
    print(r['packet_number'], r['offset'], r['timestamp'], r['labels'])
```

Fields accepted by `get_packet_labels_by_fields` (and by `find_packets`):

| Field | Meaning |
|-------|---------|
| `src_ip`, `dst_ip` | IPv4 addresses as strings. |
| `src_port`, `dst_port` | Port numbers. |
| `protocol` | Number (`6`) or name (`'tcp'`, `'udp'`, `'icmp'`). |
| `timestamp` | Epoch seconds. In Wireshark: *View → Time Display Format → Seconds Since Epoch*. |
| `tolerance` | Allowed difference on `timestamp`, in seconds (default `1e-6`). |
| `bidirectional` | `True` also matches the reverse direction (src and dst swapped). |
| `limit` | Stop after this many matching packets. |

Each result contains `packet_number`, `offset`, `timestamp`, the decoded header fields and `labels`, a list of flow matches.

Without `timestamp`, a 5-tuple usually matches many packets (often the whole flow). When `timestamp` is given, non-matching packets are discarded from their record header alone, without decoding them, so the scan is much faster.

### Walkthrough: `packet_to_label.py`

`scripts/packet_to_label.py` is a small, commented script that shows how the packet → label lookup works in practice. It takes one packet of a PCAP and finds the label of its flow with each of the four methods above, so you can compare them on the same packet.

Set the values at the top of the script:

```python
PATH_TO_DBS = ROOT / "datasets/cic2017/mapping_flow_packet"       # folder with one sub-folder per day
DB = PATH_TO_DBS / "monday/monday_index.db"                       # database of the day
PCAP = ROOT / "datasets/cic2017/pcaps/Monday-WorkingHours_2.pcap" # a PCAP indexed in DB
PACKET_NUMBER = 1                                                 # Wireshark "No." of the packet
```

Then run it from the project root:

```bash
python scripts/packet_to_label.py
```

What it does:

1. Reads the chosen packet and prints its number, byte offset, timestamp and 5-tuple. The packet must be IPv4; otherwise the script asks you to pick another `PACKET_NUMBER`.
2. Looks up the label of its flow in four ways:
   1. **by offset** with `get_packet_labels` (one query on the database);
   2. **by packet number** with `get_packet_labels_by_number` (reads the PCAP up to that packet);
   3. **by header fields** with `get_packet_labels_by_fields`, using the packet's IPs, ports, protocol and timestamp (`limit=1` stops at the first match);
   4. **by offset, without naming the database** with `find_packet_labels`, which finds which `.db` in `PATH_TO_DBS` indexes this PCAP.

For each method it prints one line per matching flow (`flow_id`, `label`, `ambiguous`), or a message if the packet does not belong to any flow of the CSV. All four methods should give the same result.

### Lower-level helpers

| Function | Purpose |
|----------|---------|
| `find_packets(pcap_file, **fields)` | Same search as `get_packet_labels_by_fields`, without the database. It only returns the matching packets. |
| `get_packet_offset(pcap_file, packet_number)` | Converts a Wireshark packet number into a byte offset. |
| `ensure_packet_index(db)` | Creates the `idx_pkt` index needed for fast packet → flow lookups. It runs automatically, so you rarely need to call it yourself. |
| `connect(db_path)` | Opens a database with rows accessible by column name, for your own SQL queries. |

### Examples in the script

- `example_packet_extraction()`: labels of every database → flows of one label → packets of one flow.
- `example_packet_label(db)`: takes a packet of a malicious flow and recovers its label from `pcap_file` + `offset`.
- `testing()`: prints the packets of a fixed flow id.

### Writing your own SQL

The schema is simple, so direct SQL is often the quickest way to answer other questions:

```python
conn = q.connect(q.DB)

# number of packets per label
conn.execute("""
    SELECT f.label, COUNT(*) AS n_packets
    FROM packet_offsets po JOIN flows f USING (flow_id)
    GROUP BY f.label ORDER BY n_packets DESC
""").fetchall()

# flows of the CSV with no matched packet
conn.execute("""
    SELECT flow_id FROM flows
    WHERE flow_id NOT IN (SELECT DISTINCT flow_id FROM packet_offsets)
""").fetchall()
```

---

## Limitations and caveats

- **Matching is heuristic.** A packet is assigned by 5-tuple + time window. If CSV timestamps are wrong, or flows of the same 5-tuple overlap in time, packets can be missed or assigned to several flows (`ambiguous = 1`). Using the re-extracted CIC2017 flows (see [above](#cic-ids2017)) reduces this a lot.
- **IPv4 only.** Non-IP and IPv6 packets are skipped. For protocols without ports (e.g. ICMP), ports are treated as `0`, as in CICFlowMeter.
- **Unmatched packets are not stored.** For a packet with no flow, the lookup functions return an empty list, not an error.
- **Classic PCAP only.** Convert PcapNG files with `editcap` first.
- **Paths are absolute.** Do not move the PCAPs after indexing, or rebuild the index after moving them.
- **First packet → label lookup on an old database.** A database built before `idx_pkt` existed gets the index on the first lookup. This can take a few minutes on a large database and needs write access. Without write access the lookups still work, but slowly.
