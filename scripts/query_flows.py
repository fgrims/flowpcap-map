import socket
import sqlite3
import struct
import sys
from pathlib import Path
import dpkt

# Struct per l'header di record PCAP (16 byte: ts_sec, ts_sub, caplen, origlen)
_REC_HDR = {
    ('little', 'us'): struct.Struct('<IIII'),
    ('big',    'us'): struct.Struct('>IIII'),
    ('little', 'ns'): struct.Struct('<IIII'),
    ('big',    'ns'): struct.Struct('>IIII'),
}


# Specifica il path della cartella contenente le sottocartelle con i database .db
PATH_TO_DBS = "/mapping_flow_packet/" 

# Specifica il path del singolo database .db da usare per le query (puoi cambiarlo a piacere)
DB = "".join([PATH_TO_DBS, "/Friday-02-03-2018/Friday-02-03-2018_index.db"])

# ---- helpers

def connect(db_path: str) -> sqlite3.Connection:
    if not Path(db_path).exists():
        sys.exit(f"[ERROR] File non trovato: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def hr(char='─', width=72):
    print(char * width)

def get_db_paths(path_to_dbs: str = PATH_TO_DBS) -> list[str]:
    """Ritorna il path del file .db in ognuna delle sottocartelle di PATH_TO_DBS."""
    root = Path(path_to_dbs)
    db_paths = []
    for subdir in sorted(root.iterdir()):
        if not subdir.is_dir():
            continue
        found = list(subdir.glob("*.db"))
        if found:
            db_paths.append(str(found[0]))
    return db_paths

# ---- 

def get_labels(db: str) -> list[str]:
    """Ritorna tutte le label presenti nel database."""
    conn = connect(db)
    rows = conn.execute("SELECT DISTINCT label FROM flows").fetchall()
    conn.close()
    return [row["label"] for row in rows]

def get_flows_by_label(db: str, label: str) -> list[str]:
    """Ritorna tutti i flow_id di una data label."""
    conn = connect(db)
    rows = conn.execute(
        "SELECT flow_id FROM flows WHERE label=? ORDER BY flow_id", (label,)
    ).fetchall()
    conn.close()
    return [row["flow_id"] for row in rows]

# ---- Flows Packets 

def get_packets_by_flows(db: str, flow_ids: list[str]) -> list[dict]:
    """Ritorna tutti i pacchetti associati a una lista di flow_id."""
    conn = connect(db)
    placeholders = ','.join('?' for _ in flow_ids)
    query = f"""
        SELECT flow_id, pcap_file, offset, caplen, ambiguous
        FROM packet_offsets
        WHERE flow_id IN ({placeholders})
        ORDER BY flow_id, pcap_file, offset
    """
    rows = conn.execute(query, flow_ids).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_flow_packets(db: str, flow_id: str) -> list[dict]:
    """Ritorna tutti i pacchetti (con i byte raw) di un dato flow_id."""
    conn = connect(db)
    rows = conn.execute("""
        SELECT po.pcap_file, po.offset, po.caplen, po.ambiguous,
               pm.byte_order, pm.ts_res, pm.link_type
        FROM packet_offsets AS po
        JOIN pcap_meta AS pm ON pm.pcap_file = po.pcap_file
        WHERE po.flow_id = ?
        ORDER BY po.pcap_file, po.offset
    """, (flow_id,)).fetchall()
    conn.close()

    packets = []
    for r in rows:
        rec_hdr = _REC_HDR[(r['byte_order'], r['ts_res'])]
        with open(r['pcap_file'], 'rb') as f:
            f.seek(r['offset']) # legge i pacchetti a partire dall'offset
            ts_sec, ts_sub, _, _ = rec_hdr.unpack(f.read(16)) # per ricostruire il timestamp
            data = f.read(r['caplen']) # legge i byte raw del pacchetto partendo dall'offset e leggendo caplen byte
        ts = ts_sec + (ts_sub / 1e9 if r['ts_res'] == 'ns' else ts_sub / 1e6)
        packets.append({
            'timestamp': ts,
            'data': data,
            'link_type': r['link_type'],
            'pcap_file': r['pcap_file'],
            'offset': r['offset'],
            'ambiguous': r['ambiguous'],
        })
    return packets

def get_packet_info(data: bytes, link_type: int = dpkt.pcap.DLT_EN10MB) -> dict | None:
    """Estrae IP sorgente/destinazione, protocollo, porte e flag TCP da un pacchetto raw."""
    try:
        if link_type == dpkt.pcap.DLT_EN10MB:
            ip = dpkt.ethernet.Ethernet(data).data
        elif link_type == dpkt.pcap.DLT_LINUX_SLL:
            ip = dpkt.ip.IP(data[16:])
        elif link_type == dpkt.pcap.DLT_RAW:
            ip = dpkt.ip.IP(data)
        else:
            return None
        if not isinstance(ip, dpkt.ip.IP):
            return None
    except Exception:
        return None

    info = {
        'src_ip':    socket.inet_ntoa(ip.src),
        'dst_ip':    socket.inet_ntoa(ip.dst),
        'protocol':  ip.p,
        'ttl':       ip.ttl,
        'length':    ip.len,
        'src_port':  None,
        'dst_port':  None,
        'tcp_flags': None,
    }

    if isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        info['src_port'] = ip.data.sport
        info['dst_port'] = ip.data.dport
        if isinstance(ip.data, dpkt.tcp.TCP):
            info['tcp_flags'] = ip.data.flags

    return info

# ----

# ---- Benign flows 

def get_benign_flows(db: str = DB) -> list[str]:
    """Ritorna tutti i flow_id di flussi benigni (label = 'BENIGN')."""
    conn = connect(db)
    query = """ 
    SELECT f.flow_id from flows as f 
    LEFT JOIN packet_offsets as po ON f.flow_id = po.flow_id 
    WHERE f.label = 'BENIGN' 
    GROUP BY f.flow_id 
    ORDER BY COUNT(po.rowid) DESC 
    """
    rows = conn.execute(query).fetchall()
    conn.close()

    return [row["flow_id"] for row in rows]

def get_all_benign_flows(): 
    """Ritorna tutti i flow_id di flussi benigni (label = 'BENIGN') da tutti i database."""
    db_list = get_db_paths(PATH_TO_DBS)
    all_benign_flows = []
    for db_path in db_list:
        benign_flows = get_benign_flows(db_path)
        all_benign_flows.extend(benign_flows)
    return all_benign_flows

# ----

# ---- Malicious flows

def get_malicious_flows(db: str = DB) -> list[str]:
    """Ritorna tutti i flow_id di flussi non benigni (label != 'BENIGN')."""
    conn = connect(db)
    query = """
    SELECT f.flow_id from flows as f
    LEFT JOIN packet_offsets as po ON f.flow_id = po.flow_id
    WHERE f.label != 'BENIGN'
    GROUP BY f.flow_id
    ORDER BY COUNT(po.rowid) DESC
    """
    rows = conn.execute(query).fetchall()
    conn.close()

    return [row["flow_id"] for row in rows]

def get_all_malicious_flows():
    """Ritorna tutti i flow_id di flussi non benigni (label != 'BENIGN') da tutti i database."""
    db_list = get_db_paths(PATH_TO_DBS)
    all_malicious_flows = []
    for db_path in db_list:
        malicious_flows = get_malicious_flows(db_path)
        all_malicious_flows.extend(malicious_flows)
    return all_malicious_flows

# ---- 

def testing(): 

    flow_ids = ["3738674_Botnet_Ares_cic2018"]
    # dato un flow_id, recupera tutti i pacchetti associati raw
    packets = get_flow_packets(DB, flow_ids[0])
    print(f"Retrieved {len(packets)} packets for flow ID {flow_ids[0]}.")
    print("First packet details:")

    # stampa informazioni sul primo pacchetto 
    if packets:
        first_packet = packets[0]
        print(f"Timestamp: {first_packet['timestamp']}")
        print(f"Data length: {len(first_packet['data'])} bytes")
        print(f"PCAP file: {first_packet['pcap_file']}")
        print(f"Offset: {first_packet['offset']}")
        print(f"Ambiguous: {first_packet['ambiguous']}")
    print("Packet data")

    # recupera informazioni dai pacchetti e stampa
    for packet in packets:
        packet_info = get_packet_info(packet['data'], packet['link_type'])
        if packet_info:
            print(f"Source IP: {packet_info['src_ip']}, Destination IP: {packet_info['dst_ip']}, "
                  f"Protocol: {packet_info['protocol']}, Source Port: {packet_info['src_port']}, "
                  f"Destination Port: {packet_info['dst_port']}, TCP Flags: {packet_info['tcp_flags']}")

def example_packet_extraction(): 
    # recuperiamo le labels per tutti i .db 
    print(f"\n\n[FASE 1]: recupera le labels per tutti i database .db in {PATH_TO_DBS}")
    dbs = get_db_paths(PATH_TO_DBS)
    labels_dict = {}
    for db in dbs:
        labels = get_labels(db)
        labels_dict[db] = labels
        print(f"Retrieved labels for {db}:\n{labels}")

    # per il primo .db, recuperiamo i flow_id per una specifica label
    print(f"\n\n[FASE 2]: recupera i flow_id per una label specifica nel primo database .db")
    selected_db = dbs[0]
    selected_label = labels_dict[selected_db][1]  # prendiamo la seconda label disponibile 
    selected_flows = get_flows_by_label(selected_db, selected_label)
    print(f"Retrieved {len(selected_flows)} flow IDs for label '{selected_label}' in database '{selected_db}'.")

    # recuperiamo i pacchetti per il primo flow_id della lista
    print(f"\n\n[FASE 3]: recupera i pacchetti per il primo flow_id della lista")
    if selected_flows:
        first_flow_id = selected_flows[0]
        packets = get_flow_packets(selected_db, first_flow_id)
        print(f"Retrieved {len(packets)} packets for flow ID '{first_flow_id}'.")

        # stampiamo informazioni sul primo pacchetto
        if packets:
            first_packet = packets[0]
            print(f"First packet details for flow ID '{first_flow_id}':")
            print(f"Timestamp: {first_packet['timestamp']}")
            print(f"Data length: {len(first_packet['data'])} bytes")
            print(f"PCAP file: {first_packet['pcap_file']}")
            print(f"Offset: {first_packet['offset']}")
            print(f"Ambiguous: {first_packet['ambiguous']}")

        # recupera informazioni dai pacchetti e stampa
        for packet in packets:
            packet_info = get_packet_info(packet['data'], packet['link_type'])
            if packet_info:
                print(f"Source IP: {packet_info['src_ip']}, Destination IP: {packet_info['dst_ip']}, "
                    f"Protocol: {packet_info['protocol']}, Source Port: {packet_info['src_port']}, "
                    f"Destination Port: {packet_info['dst_port']}, TCP Flags: {packet_info['tcp_flags']}")

def main():
    print("Starting query flows processing...")
    example_packet_extraction()

    print("\n\nEnd of query flows processing.")
    return

if __name__ == "__main__":
    main()