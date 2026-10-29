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

# ---- Packet -> Flow label

def ensure_packet_index(db: str) -> None:
    """Crea l'indice su (pcap_file, offset) se manca (DB generati prima che l'indexer lo includesse).
    La prima volta su un DB grande può richiedere qualche minuto; poi è istantaneo."""
    conn = sqlite3.connect(db)
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_pkt ON packet_offsets(pcap_file, offset)")
        conn.commit()
    except sqlite3.OperationalError as e:
        # es. DB in sola lettura: la query funziona lo stesso, ma con scansione completa (lenta)
        print(f"[WARNING] Impossibile creare idx_pkt su {db}: {e}", file=sys.stderr)
    finally:
        conn.close()

def _resolve_pcap_path(conn: sqlite3.Connection, pcap_file: str) -> str | None:
    """Trova il path del pcap così come è salvato nel DB (match esatto, poi path assoluto, poi nome file)."""
    stored = [r['pcap_file'] for r in conn.execute("SELECT pcap_file FROM pcap_meta")]
    if pcap_file in stored:
        return pcap_file
    target = Path(pcap_file).resolve()
    for p in stored:
        if Path(p).resolve() == target:
            return p
    same_name = [p for p in stored if Path(p).name == Path(pcap_file).name]
    return same_name[0] if len(same_name) == 1 else None

def _read_pcap_header(f) -> tuple[struct.Struct, bool, int]:
    """Legge il global header (24 byte) di un pcap classico aperto in 'rb'.
    Ritorna (struct dell'header di record, timestamp in ns?, link_type)."""
    hdr = f.read(24)
    if len(hdr) < 24:
        raise ValueError("File troppo corto per essere un pcap")
    for endian in ('<', '>'):
        magic = struct.unpack(endian + 'I', hdr[:4])[0]
        if magic in (0xa1b2c3d4, 0xa1b23c4d):
            link_type = struct.unpack(endian + 'I', hdr[20:24])[0]
            return struct.Struct(endian + 'IIII'), magic == 0xa1b23c4d, link_type
    raise ValueError("Non è un pcap classico (PcapNG non supportato)")

def get_packet_offset(pcap_file: str, packet_number: int) -> int:
    """Ritorna l'offset del record del pacchetto n-esimo nel pcap.
    packet_number parte da 1, come la colonna 'No.' di Wireshark. Scorre il file: O(n)."""
    if packet_number < 1:
        raise ValueError("packet_number parte da 1")
    with open(pcap_file, 'rb') as f:
        rec_hdr, _, _ = _read_pcap_header(f)
        for _ in range(packet_number - 1):
            hdr = f.read(16)
            if len(hdr) < 16:
                raise IndexError(f"{pcap_file} ha meno di {packet_number} pacchetti")
            _, _, caplen, _ = rec_hdr.unpack(hdr)
            f.seek(caplen, 1)
        offset = f.tell()
        if len(f.read(16)) < 16:
            raise IndexError(f"{pcap_file} ha meno di {packet_number} pacchetti")
    return offset

def _labels_for_offsets(db: str, pcap_file: str, offsets: list[int]) -> dict[int, list[dict]]:
    """Ritorna {offset: [{'flow_id', 'label', 'ambiguous'}]} per una lista di offset dello stesso pcap.
    Gli offset non associati a nessun flusso hanno lista vuota."""
    ensure_packet_index(db)
    conn = connect(db)
    stored_path = _resolve_pcap_path(conn, pcap_file)
    if stored_path is None:
        conn.close()
        raise ValueError(f"{pcap_file} non è indicizzato in {db}")
    result = {off: [] for off in offsets}
    unique = list(result)
    for i in range(0, len(unique), 900):  # SQLite limita il numero di parametri per query
        chunk = unique[i:i + 900]
        rows = conn.execute(f"""
            SELECT po.offset, po.flow_id, f.label, po.ambiguous
            FROM packet_offsets AS po
            JOIN flows AS f ON f.flow_id = po.flow_id
            WHERE po.pcap_file = ? AND po.offset IN ({','.join('?' * len(chunk))})
            ORDER BY po.flow_id
        """, (stored_path, *chunk)).fetchall()
        for r in rows:
            result[r['offset']].append({'flow_id': r['flow_id'], 'label': r['label'], 'ambiguous': r['ambiguous']})
    conn.close()
    return result

def get_packet_labels(db: str, pcap_file: str, offset: int) -> list[dict]:
    """Dato un pacchetto (pcap_file + offset del suo record), ritorna i flussi a cui appartiene con la label.
    Ritorna [{'flow_id', 'label', 'ambiguous'}]:
      - lista vuota  -> il pacchetto non è associato a nessun flusso del CSV
      - più elementi -> pacchetto ambiguo (rivendicato da più flussi)"""
    return _labels_for_offsets(db, pcap_file, [offset])[offset]

_PROTOCOLS = {'icmp': 1, 'tcp': 6, 'udp': 17}

def find_packets(pcap_file: str, src_ip: str | None = None, dst_ip: str | None = None,
                 src_port: int | None = None, dst_port: int | None = None,
                 protocol: int | str | None = None, timestamp: float | None = None,
                 tolerance: float = 1e-6, bidirectional: bool = False,
                 limit: int | None = None) -> list[dict]:
    """Scorre il pcap e ritorna i pacchetti che corrispondono ai campi dati (None = qualsiasi valore).
    - protocol: numero (6) o nome ('tcp', 'udp', 'icmp')
    - timestamp: epoch in secondi (in Wireshark: View > Time Display Format > Seconds Since Epoch),
      confrontato con margine +/- tolerance secondi
    - bidirectional: accetta anche il verso opposto (src e dst scambiati)
    - limit: si ferma dopo N risultati
    Ritorna [{'packet_number', 'offset', 'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', ...}]"""
    if isinstance(protocol, str):
        protocol = _PROTOCOLS[protocol.lower()]
    fwd = (src_ip, dst_ip, src_port, dst_port)
    rev = (dst_ip, src_ip, dst_port, src_port)

    def match(info: dict, want: tuple) -> bool:
        got = (info['src_ip'], info['dst_ip'], info['src_port'], info['dst_port'])
        return all(w is None or w == g for w, g in zip(want, got))

    found = []
    with open(pcap_file, 'rb') as f:
        rec_hdr, nano, link_type = _read_pcap_header(f)
        packet_number = 0
        while True:
            offset = f.tell()
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            packet_number += 1
            ts_sec, ts_sub, caplen, _ = rec_hdr.unpack(hdr)
            ts = ts_sec + (ts_sub / 1e9 if nano else ts_sub / 1e6)
            # filtro sul timestamp prima di decodificare il pacchetto (molto più veloce)
            if timestamp is not None and abs(ts - timestamp) > tolerance:
                f.seek(caplen, 1)
                continue
            info = get_packet_info(f.read(caplen), link_type)
            if info is None or (protocol is not None and info['protocol'] != protocol):
                continue
            if match(info, fwd) or (bidirectional and match(info, rev)):
                found.append({'packet_number': packet_number, 'offset': offset, 'timestamp': ts, **info})
                if limit is not None and len(found) >= limit:
                    break
    return found

def get_packet_labels_by_fields(db: str, pcap_file: str, **fields) -> list[dict]:
    """Come find_packets (stessi argomenti), ma aggiunge a ogni pacchetto trovato la chiave 'labels'
    con [{'flow_id', 'label', 'ambiguous'}] (lista vuota = pacchetto non associato a nessun flusso).
    Esempio:
        get_packet_labels_by_fields(DB, pcap, src_ip='172.31.69.25', dst_port=80,
                                    protocol='tcp', timestamp=1519917361.123456)"""
    packets = find_packets(pcap_file, **fields)
    labels = _labels_for_offsets(db, pcap_file, [p['offset'] for p in packets]) if packets else {}
    for p in packets:
        p['labels'] = labels[p['offset']]
    return packets

def get_packet_labels_by_number(db: str, pcap_file: str, packet_number: int) -> list[dict]:
    """Come get_packet_labels, ma il pacchetto è indicato col numero ('No.' di Wireshark, da 1)."""
    return get_packet_labels(db, pcap_file, get_packet_offset(pcap_file, packet_number))

def find_packet_labels(pcap_file: str, offset: int, path_to_dbs: str = PATH_TO_DBS) -> list[dict]:
    """Come get_packet_labels, ma cerca in tutti i DB di path_to_dbs quello che indicizza il pcap."""
    for db in get_db_paths(path_to_dbs):
        conn = connect(db)
        found = _resolve_pcap_path(conn, pcap_file) is not None
        conn.close()
        if found:
            return get_packet_labels(db, pcap_file, offset)
    raise ValueError(f"{pcap_file} non è indicizzato in nessun DB di {path_to_dbs}")

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

def example_packet_label(db: str = DB):
    # prende un pacchetto noto (il primo di un flusso malevolo) e ne recupera la label partendo da pcap + offset
    flow_id = get_malicious_flows(db)[0]
    pkt = get_flow_packets(db, flow_id)[0]
    print(f"Pacchetto: {pkt['pcap_file']} @ offset {pkt['offset']} (flow atteso: {flow_id})")
    for m in get_packet_labels(db, pkt['pcap_file'], pkt['offset']):
        print(f"  -> flow_id={m['flow_id']}  label={m['label']}  ambiguous={m['ambiguous']}")

    # in alternativa, col numero del pacchetto come lo mostra Wireshark:
    # get_packet_labels_by_number(db, "/path/al/file.pcap", 12345)

def main():
    print("Starting query flows processing...")
    example_packet_extraction()

    print("\n\nEnd of query flows processing.")
    return

if __name__ == "__main__":
    main()