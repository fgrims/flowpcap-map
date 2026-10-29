#!/usr/bin/env python3
"""
CIC-IDS flow-to-packet offset index builder.

Scans PCAP file(s) paired with a CICFlowMeter CSV and records, for every
matched packet, the byte offset within the PCAP.  Packets can then be read
on-demand via query_flows.py (one seek() per packet) with no physical
per-flow extraction.

Only classic PCAP input files are supported. PcapNG captures must be
converted first, e.g.:  editcap -F pcap input.pcapng output.pcap

Usage:
    python flow_indexer.py config.json [--pair-index N] [--max-workers N]

Config keys (global, overridable per pair):
    index_dir               output root for index folders
    dataset_name            used to build flow_id strings
    timestamp_format        strptime format for CSV Timestamp column
    timestamp_tz_offset_h   UTC offset of CSV timestamps (default 0)
    timestamp_tolerance_s   seconds added to each side of time window (default 0)
    column_mapping          src_ip, dst_ip, src_port, dst_port, protocol,
                            timestamp, flow_duration, label

Output layout:
    <index_dir>/<csv_stem>/
        <csv_stem>_index.db          <- merged SQLite index
        .parts/                      <- per-worker partial DBs (auto-deleted)
            partial_<pcap_stem>.db

SQLite schema:
    packet_offsets(flow_id, pcap_file, offset, caplen, ambiguous)
    pcap_meta(pcap_file, byte_order, ts_res, link_type, snaplen)

    'ambiguous' is 1 when the same packet was claimed by more than one flow_id
    (overlapping time windows with the same 5-tuple).

Design note: workers use mp.get_context('fork') so the flow_index dict is
inherited via copy-on-write — no pickle overhead for large indexes.
"""

import argparse
import hashlib
import json
import multiprocessing as mp
import os
import re
import shutil
import socket
import sqlite3
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import dpkt
import pandas as pd

# ── Constants ──────────────────────────────────────────────────────────────────

_PCAP_MAGIC_LE_US = 0xa1b2c3d4
_PCAP_MAGIC_BE_US = 0xd4c3b2a1
_PCAP_MAGIC_LE_NS = 0xa1b23c4d
_PCAP_MAGIC_BE_NS = 0x4d3cb2a1
_PCAPNG_MAGIC     = b'\x0a\x0d\x0d\x0a'

_SCHEMA = """
CREATE TABLE IF NOT EXISTS packet_offsets (
    flow_id   TEXT    NOT NULL,
    pcap_file TEXT    NOT NULL,
    offset    INTEGER NOT NULL,
    caplen    INTEGER NOT NULL,
    ambiguous INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flow ON packet_offsets(flow_id);

CREATE TABLE IF NOT EXISTS flows (
    flow_id TEXT PRIMARY KEY,
    label   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_label ON flows(label);

CREATE TABLE IF NOT EXISTS pcap_meta (
    pcap_file  TEXT    PRIMARY KEY,
    byte_order TEXT    NOT NULL,
    ts_res     TEXT    NOT NULL,
    link_type  INTEGER NOT NULL,
    snaplen    INTEGER NOT NULL
);
"""

# seleziona pacchetti data la coppia id attacco



_INSERT_OFFSET = "INSERT INTO packet_offsets VALUES (?,?,?,?,?)"
_BATCH_SIZE    = 50_000

# ── Shared utilities (duplicated from extractor_improved.py) ───────────────────

def log(msg: str) -> None:
    ts = datetime.now().strftime('%H:%M:%S')
    print(f"[{ts}] {msg}", flush=True)


def sanitize(name: str) -> str:
    return re.sub(r'[^\w\-]', '_', str(name)).strip('_')


def parse_utc_ts(ts_str: str, fmt: str, tz_offset_h: float = 0.0) -> float:
    """Parse a naive timestamp string and apply a UTC offset to get a POSIX timestamp."""
    tz = timezone(timedelta(hours=tz_offset_h))
    try:
        dt = datetime.strptime(ts_str.strip(), fmt)
    except ValueError:
        # CICFlowMeter sometimes truncates seconds: fall back to format without :%S
        fallback = fmt.replace(':%S', '')
        dt = datetime.strptime(ts_str.strip(), fallback)
    return dt.replace(tzinfo=tz).timestamp()


def get_col(row, col_name: str):
    return row[col_name.strip()]


def extract_5tuple(row, col: dict) -> tuple:
    if 'flow_id' in col:
        parts = str(get_col(row, col['flow_id'])).strip().split('-')
        return parts[0], parts[1], int(parts[2]), int(parts[3]), int(parts[4])
    return (
        str(get_col(row, col['src_ip'])).strip(),
        str(get_col(row, col['dst_ip'])).strip(),
        int(get_col(row, col['src_port'])),
        int(get_col(row, col['dst_port'])),
        int(get_col(row, col['protocol'])),
    )


def flow_name(idx: int, label: str, dataset_name: str) -> str:
    return f"{idx:06d}_{sanitize(label)}_{sanitize(dataset_name)}"


# ── PCAP global-header parsing ─────────────────────────────────────────────────

def read_pcap_global_header(f) -> dict:
    """
    Read and parse the 24-byte classic-PCAP global header from an open file.
    Returns {'byte_order', 'ts_res', 'link_type', 'snaplen'}.
    Raises RuntimeError for PcapNG (not supported) or unknown magic.
    """
    magic_bytes = f.read(4)
    if len(magic_bytes) < 4:
        raise RuntimeError("File too short to be a valid PCAP")
    if magic_bytes == _PCAPNG_MAGIC:
        raise RuntimeError(
            "PcapNG is not supported by flow_indexer.py. "
            "Convert with:  editcap -F pcap input.pcapng output.pcap"
        )

    magic = struct.unpack('<I', magic_bytes)[0]
    if magic == _PCAP_MAGIC_LE_US:
        endian, ts_res = '<', 'us'
    elif magic == _PCAP_MAGIC_BE_US:
        endian, ts_res = '>', 'us'
    elif magic == _PCAP_MAGIC_LE_NS:
        endian, ts_res = '<', 'ns'
    elif magic == _PCAP_MAGIC_BE_NS:
        endian, ts_res = '>', 'ns'
    else:
        raise RuntimeError(f"Unknown PCAP magic: {magic_bytes.hex()}")

    rest = f.read(20)
    if len(rest) < 20:
        raise RuntimeError("PCAP global header truncated after magic")
    _, _, _, _, snaplen, link_type = struct.unpack(endian + 'HHiIII', rest)

    return {
        'byte_order': 'little' if endian == '<' else 'big',
        'ts_res':     ts_res,
        'link_type':  link_type,
        'snaplen':    snaplen,
    }


# ── IP-layer extraction (duplicated from extractor_improved.py) ────────────────

def _get_ip(buf: bytes, link_type: int) -> Optional[dpkt.ip.IP]:
    try:
        if link_type == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                return None
            return eth.data
        elif link_type == dpkt.pcap.DLT_LINUX_SLL:
            if len(buf) < 16:
                return None
            if struct.unpack('!H', buf[14:16])[0] != dpkt.ethernet.ETH_TYPE_IP:
                return None
            return dpkt.ip.IP(buf[16:])
        elif link_type == dpkt.pcap.DLT_RAW:
            return dpkt.ip.IP(buf)
        return None
    except Exception:
        return None


def _extract_5tuple_from_ip(ip) -> Optional[tuple]:
    """Return (src_str, dst_str, sport, dport, proto) for an IP packet, or None."""
    try:
        src_str = socket.inet_ntoa(ip.src)
        dst_str = socket.inet_ntoa(ip.dst)
    except OSError:
        return None
    data = ip.data
    if isinstance(data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        sp, dp = data.sport, data.dport
    else:
        sp = dp = 0
    return src_str, dst_str, sp, dp, ip.p


def _lookup_matches(
    src_str: str, dst_str: str, sp: int, dp: int, proto: int,
    ts: float, flow_index: dict, tolerance_s: float,
) -> set:
    """Return the set of flow_ids whose 5-tuple and time window match this packet."""
    matched_ids: set = set()
    for lookup_key in [
        (src_str, dst_str, sp, dp, proto),
        (dst_str, src_str, dp, sp, proto),
    ]:
        candidates = flow_index.get(lookup_key)
        if candidates is None:
            continue
        for flow in candidates:
            if flow['start_raw'] - tolerance_s <= ts <= flow['end_raw'] + tolerance_s:
                matched_ids.add(flow['flow_id'])
    return matched_ids


# ── Flow index building ────────────────────────────────────────────────────────

def build_flow_index(
    df,
    col: dict,
    ts_fmt: str,
    tz_offset_h: float,
    tolerance_s: float,
    dataset_name: str,
) -> tuple:
    """
    Build:
      flow_index  : dict[(src_ip, dst_ip, sp, dp, proto)] -> [flow_dict, ...]
                    sorted by start_raw (for deterministic collision resolution)
      known_ips   : set of all IPs mentioned in any flow (early-reject filter)
      flow_labels : dict[flow_id] -> original label string from the CSV

    Each flow_dict has: flow_id, start_raw, end_raw.
    """
    raw_index:   dict = defaultdict(list)
    known_ips:   set  = set()
    flow_labels: dict = {}

    for csv_idx, (_, row) in enumerate(df.iterrows(), start=1):
        src_ip, dst_ip, src_port, dst_port, proto = extract_5tuple(row, col)
        label   = str(get_col(row, col['label'])).strip()
        ts_str  = str(get_col(row, col['timestamp'])).strip()
        start_t = parse_utc_ts(ts_str, ts_fmt, tz_offset_h)
        dur_us  = float(get_col(row, col['flow_duration']))
        end_t   = start_t + max(dur_us, 0.0) / 1_000_000

        fid = flow_name(csv_idx, label, dataset_name)
        raw_index[(src_ip, dst_ip, src_port, dst_port, proto)].append({
            'flow_id':   fid,
            'start_raw': start_t,
            'end_raw':   end_t,
        })
        known_ips.add(src_ip)
        known_ips.add(dst_ip)
        flow_labels[fid] = label

    flow_index = {
        k: sorted(v, key=lambda f: f['start_raw'])
        for k, v in raw_index.items()
    }
    return flow_index, known_ips, flow_labels


# ── PCAP single-pass scan ──────────────────────────────────────────────────────

def _scan_pcap_classic(
    pcap_path: str,
    flow_index: dict,
    known_ips: set,
    tolerance_s: float,
    partial_db_path: str,
) -> tuple:
    """
    Single sequential pass through a classic-PCAP file.

    For each IP packet that matches a flow's 5-tuple and time window, records
    (flow_id, pcap_path, byte_offset, caplen, ambiguous) in a SQLite DB.

    A packet that falls within the windows of >1 flow (5-tuple collision with
    overlapping time ranges) is assigned to ALL matching flows and flagged
    ambiguous=1.  The first 20 ambiguous packets are logged; the rest are
    counted silently.

    Returns (total_pkts, matched_pkts, n_ambiguous).
    """
    total = matched = n_ambiguous = 0
    tag   = Path(pcap_path).stem
    t0    = time.monotonic()

    conn = sqlite3.connect(partial_db_path)
    conn.executescript(_SCHEMA)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')

    batch: list = []

    try:
        with open(pcap_path, 'rb') as f:
            meta    = read_pcap_global_header(f)
            endian  = '<' if meta['byte_order'] == 'little' else '>'
            nano    = meta['ts_res'] == 'ns'
            ltype   = meta['link_type']
            rec_hdr = struct.Struct(endian + 'IIII')

            conn.execute(
                "INSERT OR REPLACE INTO pcap_meta VALUES (?,?,?,?,?)",
                (pcap_path, meta['byte_order'], meta['ts_res'], ltype, meta['snaplen']),
            )
            conn.commit()  # commit now: if the file has 0 matches, no later batch flush will

            while True:
                offset    = f.tell()
                hdr_bytes = f.read(16)
                if len(hdr_bytes) < 16:
                    if hdr_bytes:
                        log(f"[WARNING][{tag}] Truncated record header at offset {offset}")
                    break

                ts_sec, ts_sub, incl_len, _ = rec_hdr.unpack(hdr_bytes)
                ts = ts_sec + (ts_sub / 1e9 if nano else ts_sub / 1e6)

                buf = f.read(incl_len)
                if len(buf) < incl_len:
                    log(f"[WARNING][{tag}] Truncated payload at offset {offset}")
                    break

                total += 1
                if total % 500_000 == 0:
                    elapsed = time.monotonic() - t0
                    rate    = total / elapsed if elapsed > 0 else 0
                    log(f"[{tag}] {total:>12,} pkts | {matched:>10,} matched | {rate:,.0f} pkt/s")

                ip = _get_ip(buf, ltype)
                if ip is None:
                    continue

                tup = _extract_5tuple_from_ip(ip)
                if tup is None:
                    continue
                src_str, dst_str, sp, dp, proto = tup

                if src_str not in known_ips and dst_str not in known_ips:
                    continue

                matched_ids = _lookup_matches(src_str, dst_str, sp, dp, proto, ts, flow_index, tolerance_s)
                if not matched_ids:
                    continue

                ambiguous = 1 if len(matched_ids) > 1 else 0
                if ambiguous:
                    n_ambiguous += 1
                    if n_ambiguous <= 20:
                        log(
                            f"[WARNING][{tag}] Ambiguous pkt offset={offset} ts={ts:.6f} "
                            f"flows={sorted(matched_ids)}"
                        )

                for fid in matched_ids:
                    batch.append((fid, pcap_path, offset, incl_len, ambiguous))
                    matched += 1

                if len(batch) >= _BATCH_SIZE:
                    conn.executemany(_INSERT_OFFSET, batch)
                    conn.commit()
                    batch.clear()

        if batch:
            conn.executemany(_INSERT_OFFSET, batch)
            conn.commit()

    finally:
        conn.close()

    elapsed = time.monotonic() - t0
    log(
        f"[{tag}] {total:>12,} pkts | {matched:>10,} matched | "
        f"{n_ambiguous} ambiguous | {elapsed:.1f}s"
    )
    return total, matched, n_ambiguous


def scan_pcap_index(
    pcap_path: str,
    flow_index: dict,
    known_ips: set,
    tolerance_s: float,
    partial_db_path: str,
) -> tuple:
    """Scan a classic-PCAP file. Raises RuntimeError (via read_pcap_global_header)
    for PcapNG input, with a hint to convert via editcap first."""
    return _scan_pcap_classic(pcap_path, flow_index, known_ips, tolerance_s, partial_db_path)


# ── Parallel worker infrastructure ─────────────────────────────────────────────
# flow_index and known_ips are built in the parent process and inherited by
# forked workers via Linux copy-on-write — no pickle overhead.

_g: dict = {}


def _worker_index(pcap_path: str) -> tuple:
    """Scan one PCAP, write partial SQLite DB to .parts/.
    Returns (total, matched, n_amb, partial_db_path) or (0,0,0,None) on skip."""
    # Hash the full path so two files with the same stem in different
    # subdirectories never collide on the same partial DB file.
    path_hash  = hashlib.md5(pcap_path.encode()).hexdigest()[:8]
    pcap_stem  = Path(pcap_path).stem
    partial_db = _g['parts_dir'] / f"partial_{pcap_stem}_{path_hash}.db"
    try:
        total, matched, n_amb = scan_pcap_index(
            pcap_path,
            _g['flow_index'],
            _g['known_ips'],
            _g['tolerance'],
            str(partial_db),
        )
        return total, matched, n_amb, str(partial_db)
    except RuntimeError as e:
        log(f"[WARNING] Skipping {pcap_path}: {e}")
        return 0, 0, 0, None


# ── Flows table ───────────────────────────────────────────────────────────────

def write_flows_table(db_path: str, flow_labels: dict) -> None:
    """Write flow_id -> label mapping into the index DB."""
    conn = sqlite3.connect(db_path)
    conn.executescript(_SCHEMA)
    conn.executemany(
        "INSERT OR IGNORE INTO flows VALUES (?,?)",
        flow_labels.items(),
    )
    # Built once all offsets are in (faster than maintaining it row by row).
    # Used by query_flows.get_packet_labels() for packet -> flow lookups.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pkt ON packet_offsets(pcap_file, offset)")
    conn.commit()
    conn.close()
    log(f"flows table: {len(flow_labels):,} entries -> {db_path}")


# ── Merge partial DBs ──────────────────────────────────────────────────────────

def merge_partials(partial_dbs: list, final_db_path: str) -> None:
    """
    Merge per-worker partial SQLite files into the final index DB.
    Reads each partial with its own connection and writes into the final DB,
    then deletes the partial file (and any WAL/SHM side files).
    """
    log(f"Merging {len(partial_dbs)} partial DB(s) -> {final_db_path} ...")

    conn = sqlite3.connect(final_db_path)
    conn.executescript(_SCHEMA)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')

    total_rows = 0
    for partial in sorted(str(p) for p in partial_dbs):
        src = sqlite3.connect(f"file:{partial}?mode=ro", uri=True)

        rows = src.execute("SELECT * FROM packet_offsets").fetchall()
        meta = src.execute("SELECT * FROM pcap_meta").fetchall()
        src.close()

        conn.executemany(_INSERT_OFFSET, rows)
        conn.executemany("INSERT OR REPLACE INTO pcap_meta VALUES (?,?,?,?,?)", meta)
        conn.commit()

        for suffix in ('', '-wal', '-shm'):
            p = Path(partial + suffix)
            if p.exists():
                p.unlink()

        total_rows += len(rows)
        log(f"  + {Path(partial).name}: {len(rows):,} rows")

    conn.close()
    log(f"Merge complete: {total_rows:,} total rows -> {final_db_path}")


# ── Per-pair pipeline ──────────────────────────────────────────────────────────

def process_pair(
    csv_path: str,
    pcap_paths: list,
    config: dict,
    pair: dict,
) -> None:
    tag = Path(csv_path).stem

    def plog(msg: str) -> None:
        print(f"[{datetime.now().strftime('%H:%M:%S')}][{tag}] {msg}", flush=True)

    col         = config['column_mapping']
    ts_fmt      = pair.get('timestamp_format',      config.get('timestamp_format',      '%Y-%m-%d %H:%M:%S.%f'))
    tz_offset_h = pair.get('timestamp_tz_offset_h', config.get('timestamp_tz_offset_h', 0.0))
    tolerance   = float(pair.get('timestamp_tolerance_s', config.get('timestamp_tolerance_s', 0.0)))
    max_workers = config.get('max_workers', 1)
    dataset     = config['dataset_name']
    index_dir   = Path(config['index_dir'])

    out_dir  = index_dir / tag
    out_dir.mkdir(parents=True, exist_ok=True)
    final_db = out_dir / f"{tag}_index.db"

    n_workers = min(max_workers, len(pcap_paths))

    plog(f"CSV      : {csv_path}")
    for p in pcap_paths:
        plog(f"PCAP     : {p}")
    plog(f"Index DB : {final_db}")
    plog(f"Workers  : {n_workers} / {len(pcap_paths)} PCAPs")
    plog(f"TZ       : {tz_offset_h:+.1f}h  |  Tolerance: +/-{tolerance}s")

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    plog(f"Flows    : {len(df):,}")

    flow_index, known_ips, flow_labels = build_flow_index(
        df, col, ts_fmt, tz_offset_h, tolerance, dataset
    )
    plog(f"Index    : {len(flow_index):,} 5-tuples | {len(known_ips):,} unique IPs")

    if n_workers > 1:
        parts_dir = out_dir / '.parts'
        if parts_dir.exists():
            plog(f"WARNING: removing stale .parts dir {parts_dir}")
            shutil.rmtree(str(parts_dir))
        parts_dir.mkdir()

        _g['flow_index'] = flow_index
        _g['known_ips']  = known_ips
        _g['parts_dir']  = parts_dir
        _g['tolerance']  = tolerance

        plog(f"Spawning {n_workers} worker processes ...")
        ctx = mp.get_context('fork')
        with ctx.Pool(processes=n_workers) as pool:
            results = pool.map(_worker_index, pcap_paths)

        total_pkts = matched_pkts = n_amb = 0
        partial_dbs = []
        for tot, mat, amb, partial_path in results:
            total_pkts   += tot
            matched_pkts += mat
            n_amb        += amb
            if partial_path is not None:
                partial_dbs.append(partial_path)

        plog(f"Workers done: {total_pkts:,} pkts | {matched_pkts:,} matched | {n_amb} ambiguous")
        if not partial_dbs:
            plog("WARNING: no valid PCAP files produced output — index DB not created")
            return
        merge_partials(partial_dbs, str(final_db))
        write_flows_table(str(final_db), flow_labels)
        try:
            parts_dir.rmdir()
        except OSError:
            shutil.rmtree(str(parts_dir), ignore_errors=True)

    else:
        total_pkts = matched_pkts = n_amb = 0
        partial_dbs = []

        for i, pcap_path in enumerate(pcap_paths, start=1):
            plog(f"Scanning ({i}/{len(pcap_paths)}): {Path(pcap_path).name}")
            tmp_db = out_dir / f".tmp_{Path(pcap_path).stem}.db"
            try:
                tot, mat, amb = scan_pcap_index(
                    pcap_path, flow_index, known_ips, tolerance, str(tmp_db)
                )
                total_pkts   += tot
                matched_pkts += mat
                n_amb        += amb
                partial_dbs.append(str(tmp_db))
            except RuntimeError as e:
                plog(f"WARNING: skipping {Path(pcap_path).name}: {e}")

        plog(f"Done: {total_pkts:,} pkts | {matched_pkts:,} matched | {n_amb} ambiguous")

        if not partial_dbs:
            plog("WARNING: no valid PCAP files produced output — index DB not created")
            return
        if len(partial_dbs) == 1:
            Path(partial_dbs[0]).rename(final_db)
        else:
            merge_partials(partial_dbs, str(final_db))
        write_flows_table(str(final_db), flow_labels)

    plog(f"Index written: {final_db}")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='CIC-IDS flow-to-packet offset index builder'
    )
    parser.add_argument('config',         help='Path to config JSON')
    parser.add_argument('--pair-index',   type=int, default=None, metavar='N',
                        help='Process only the N-th pair (0-based)')
    parser.add_argument('--max-workers',  type=int, default=None, metavar='N',
                        help='Parallel PCAP workers (overrides config; '
                             'default: SLURM_CPUS_PER_TASK or 1)')
    args = parser.parse_args()

    config = json.loads(Path(args.config).read_text())

    if args.max_workers is not None:
        config['max_workers'] = args.max_workers
    elif 'max_workers' not in config:
        slurm_cpus = int(os.environ.get('SLURM_CPUS_PER_TASK', 0))
        config['max_workers'] = slurm_cpus if slurm_cpus > 0 else 1

    log(f"Config: {args.config}  max_workers={config['max_workers']}")

    pairs = config['pairs']
    if args.pair_index is not None:
        if not (0 <= args.pair_index < len(pairs)):
            sys.exit(
                f"ERROR: --pair-index {args.pair_index} out of range "
                f"(0..{len(pairs)-1})"
            )
        log(f"Processing pair {args.pair_index}")
        pairs = [pairs[args.pair_index]]
    else:
        log(f"Processing all {len(pairs)} pairs sequentially")

    for pair in pairs:
        if 'pcap_dir' in pair:
            d = Path(pair['pcap_dir'])
            pcap_paths = sorted(str(p) for p in d.rglob('*') if p.is_file())
            if not pcap_paths:
                log(f"WARNING: no files in {d}, skipping")
                continue
        else:
            pcap_val   = pair.get('pcaps', pair.get('pcap'))
            pcap_paths = pcap_val if isinstance(pcap_val, list) else [pcap_val]

        process_pair(pair['csv'], pcap_paths, config, pair)

    log("All done.")


if __name__ == '__main__':
    main()
