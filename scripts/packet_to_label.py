"""
Example: given a packet from a PCAP, get the label of the flow it belongs to.

Tries the 4 ways available in query_flows.py:
  1. by the packet's byte offset in the file   -> get_packet_labels
  2. by packet number (as in Wireshark)        -> get_packet_labels_by_number
  3. by header fields (IPs, ports, ...)        -> get_packet_labels_by_fields
  4. by offset, without naming the database    -> find_packet_labels

Usage (from the project root, with the venv active):
    python scripts/packet_to_label.py
"""

from pathlib import Path

import query_flows as q

# ---- Configuration: change these values to try other packets

ROOT = Path(__file__).resolve().parent.parent
PATH_TO_DBS = ROOT / "datasets/cic2017/mapping_flow_packet"
DB = PATH_TO_DBS / "monday/monday_index.db"
PCAP = ROOT / "datasets/cic2017/pcaps/Monday-WorkingHours_2.pcap"

PACKET_NUMBER = 1  # packet number, as in Wireshark's "No." column (starts at 1)


def print_labels(matches):
    """Print the result of a lookup: one line per matching flow."""
    if not matches:
        print("   no flow: the packet does not belong to any row of the CSV")
    for m in matches:
        print(f"   flow_id = {m['flow_id']}   label = {m['label']}   ambiguous = {bool(m['ambiguous'])}")


def main():
    db = str(DB)
    pcap = str(PCAP)

    # First, get the offset and header fields of the packet we want to look up
    offset = q.get_packet_offset(pcap, PACKET_NUMBER)
    first_packets = q.find_packets(pcap, limit=PACKET_NUMBER)  # the first IPv4 packets of the file
    matching = [p for p in first_packets if p["packet_number"] == PACKET_NUMBER]
    if not matching:
        print(f"Packet no. {PACKET_NUMBER} is not IPv4: choose another PACKET_NUMBER")
        return
    packet = matching[0]

    print("EXAMPLE PACKET")
    print(f"   file      : {pcap}")
    print(f"   number    : {PACKET_NUMBER}")
    print(f"   offset    : {offset}")
    print(f"   timestamp : {packet['timestamp']}")
    print(f"   {packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']}"
          f"   protocol {packet['protocol']}")

    # 1. Offset: the fastest way, a single query on the database
    print("\n1) By offset  ->  get_packet_labels(db, pcap, offset)")
    print_labels(q.get_packet_labels(db, pcap, offset))

    # 2. Packet number: reads the PCAP up to that packet to find its offset
    print("\n2) By packet number  ->  get_packet_labels_by_number(db, pcap, number)")
    print_labels(q.get_packet_labels_by_number(db, pcap, PACKET_NUMBER))

    # 3. Header fields: searches the PCAP for packets with these values.
    #    It can find more than one, so it returns a list of packets, each with its own 'labels'.
    #    limit=1 stops at the first match (otherwise it reads the whole file).
    print("\n3) By header fields  ->  get_packet_labels_by_fields(db, pcap, src_ip=..., ...)")
    found = q.get_packet_labels_by_fields(
        db, pcap,
        src_ip=packet["src_ip"],
        dst_ip=packet["dst_ip"],
        src_port=packet["src_port"],
        dst_port=packet["dst_port"],
        protocol=packet["protocol"],
        timestamp=packet["timestamp"],
        limit=1,
    )
    for p in found:
        print(f"   found packet no. {p['packet_number']} (offset {p['offset']})")
        print_labels(p["labels"])

    # 4. Offset without a database: finds by itself which .db indexes this PCAP
    print("\n4) Without naming the database  ->  find_packet_labels(pcap, offset, path_to_dbs)")
    print_labels(q.find_packet_labels(pcap, offset, str(PATH_TO_DBS)))


if __name__ == "__main__":
    main()
