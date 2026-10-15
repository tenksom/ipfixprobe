import argparse
import json
from pathlib import Path
import polars as pl
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)


def load_and_normalize(path: Path) -> pl.DataFrame:
    try:
        df = pl.read_parquet(path)
    except pl.exceptions.ComputeError:
        print(f"Could not load tshark file {path}!")
        exit(2)

    # Fehlende Spalten defensiv anlegen (falls z.B. keine QUIC-Pakete im Trace waren)
    for col, dtype in [
        ("tcp.stream", pl.Int64), ("udp.stream", pl.Int64),
        ("tcp.srcport", pl.Int64), ("tcp.dstport", pl.Int64),
        ("udp.srcport", pl.Int64), ("udp.dstport", pl.Int64),
        ("tcp.flags.syn", pl.Int64), ("tcp.flags.fin", pl.Int64), ("tcp.flags.reset", pl.Int64),
        ("ipv6.plen", pl.Int64),
    ]:
        if col not in df.columns:
            df = df.with_columns(pl.lit(None).cast(dtype).alias(col))
    # quic.retry_token muss im tshark-Export enthalten sein (-e quic.retry_token), sonst kann
    # die Token-Laenge nach einem Retry nicht wie in ipfixprobe bestimmt werden.
    if "quic.retry_token" not in df.columns:
        df = df.with_columns(pl.lit(None).cast(pl.List(pl.Binary)).alias("quic.retry_token"))

    # Normalizierung der einzelnen Spalten
    spalten = [
        ("frame.number", pl.Int64), ("ip.len", pl.Int64), ("ip.proto", pl.Int64), ("tcp.flags.syn", pl.Boolean),
        ("tcp.flags.fin", pl.Boolean), ("tcp.flags.reset", pl.Boolean), ("quic.connection.number", pl.Int64),
        ("udp.srcport", pl.Int64), ("udp.dstport", pl.Int64),
        ("tcp.srcport", pl.Int64), ("tcp.dstport", pl.Int64),
        ("ipv6.plen", pl.Int64),
        ("quic.token_length", pl.Int64)
    ]

    for col, dtype in spalten:
        df = df.with_columns(pl.col(col).list.get(0).cast(dtype).alias(col))

    df = df.with_columns(pl.col("quic.dcid").list.eval(pl.element().bin.encode("hex")).alias("quic.dcid"))
    df = df.with_columns(pl.col("quic.payload").list.eval(pl.element().bin.encode("hex")).alias("quic.payload"))
    df = df.with_columns(pl.col("quic.scid").list.eval(pl.element().bin.encode("hex")).alias("quic.scid"))
    # Laenge des Retry-Tokens in Byte (Retry-Datagramme enthalten keine weiteren Pakete)
    df = df.with_columns(
        pl.col("quic.retry_token").list.get(-1, null_on_oob=True).bin.size().cast(pl.Int64)
        .alias("quic.retry_token_length")
    )

    # IPv6-Adressen fallen bei -e ip.src/ip.dst raus (die sind nur fuer IPv4 gefuellt) -
    # deshalb auf ip.src/ipv6.src koaleszieren. Ohne das landen IPv6-TCP-Pakete mit
    # leerem flow_key in der Aggregation (siehe unten).
    for col in ("ipv6.src", "ipv6.dst"):
        if col not in df.columns:
            df = df.with_columns(pl.lit([""]).alias(col))
    df = df.with_columns([
        pl.coalesce([pl.col("ip.src").list.get(0), pl.col("ipv6.src").list.get(0)]).alias("ip.src"),
        pl.coalesce([pl.col("ip.dst").list.get(0), pl.col("ipv6.dst").list.get(0)]).alias("ip.dst"),
    ])

    df = df.with_columns(
        pl.coalesce([pl.col("ip.len"), pl.col("ipv6.plen") + 40]).alias("ip.len")
    )

    # Einheitliche Ports/Stream-ID über Protokolle hinweg, damit man EIN Gruppierungsschema hat
    df = df.with_columns([
        pl.coalesce(["tcp.srcport", "udp.srcport"]).alias("srcport"),
        pl.coalesce(["tcp.dstport", "udp.dstport"]).alias("dstport"),
        pl.coalesce(["tcp.stream", "udp.stream"]).alias("l4_stream"),
    ])

    # Transportprotokoll-Label fürs Debugging/Filtern
    df = df.with_columns(
        pl.when(pl.col("tcp.stream").is_not_null()).then(pl.lit("tcp"))
        .when(pl.col("udp.stream").is_not_null()).then(pl.lit("udp"))
        .otherwise(pl.lit("other"))
        .alias("l4_proto")
    )

    return df


def split_flow_vs_nonflow(df: pl.DataFrame) -> tuple[pl.DataFrame, pl.DataFrame]:
    """
    Trennt Pakete mit echtem L4-Flow (TCP/UDP, also tcp.stream oder udp.stream gesetzt)
    von Nicht-Flow-Verkehr (ARP, ICMPv6 Neighbor Discovery, etc.).
    Nicht-Flow-Pakete werden NICHT stillschweigend verworfen, sondern separat
    zurueckgegeben -> Kontrolle/Reporting bleibt moeglich (z.B. "5% ARP/ICMP im Trace").
    """
    # Zusätzlich auf das äußere IP-Protokoll (ip.proto ist via list.get(0) der aeussere
    # Header) TCP/UDP filtern: ICMP-Fehlermeldungen (z.B. Port Unreachable) enthalten das
    # ausloesende UDP-Paket, tshark setzt dafuer udp.stream/udp.srcport aus dem INNEREN
    # Header. Ohne diesen Filter entstehen Phantom-Flows (aeussere IP + innere Ports).
    # ip.proto ist bei IPv6 leer -> dort nicht filtern (fill_null(True)).
    has_flow = (
        pl.col("l4_stream").is_not_null()
        & pl.col("ip.proto").is_in([6, 17]).fill_null(True)
    )
    flow_df = df.filter(has_flow)
    nonflow_df = df.filter(~has_flow)
    return flow_df, nonflow_df


def canonical_key(proto, a, b):
    lo, hi = sorted([a, b])
    return f"{proto}|{lo}|{hi}"


def add_flow_key(df: pl.DataFrame) -> pl.DataFrame:
    """
    Bildet einen richtungsunabhängigen Flow-Key, damit Hin- und Rückrichtung
    im selben Flow landen: kleineres (ip, port) zuerst -> "endpoint_a", Rest -> "endpoint_b".
    Zusätzlich merken wir uns die tatsächliche Richtung jedes Pakets (a->b oder b->a).
    """
    df = df.with_columns([
        pl.concat_str(["ip.src", pl.col("srcport").cast(pl.Utf8)], separator=":").alias("ep_src"),
        pl.concat_str(["ip.dst", pl.col("dstport").cast(pl.Utf8)], separator=":").alias("ep_dst"),
    ])

    df = df.with_columns([
        pl.min_horizontal(["ep_src", "ep_dst"]).alias("endpoint_a"),
        pl.max_horizontal(["ep_src", "ep_dst"]).alias("endpoint_b"),
        (pl.col("ep_src") == pl.min_horizontal(["ep_src", "ep_dst"])).alias("is_a_to_b"),
    ])

    # Flow-Key: Protokoll + kanonische Endpunkte = richtungsunabhängiges 5-Tupel
    df = df.with_columns(
        pl.struct(["l4_proto", "endpoint_a", "endpoint_b"])
        .map_elements(lambda r: canonical_key(r["l4_proto"], r["endpoint_a"], r["endpoint_b"]))
        .alias("flow_key")
    )
    return df


def compute_quic_multiplexed(df: pl.DataFrame) -> pl.DataFrame:
    """
    Bestimmt pro 5-Tupel (flow_key), ob mehr als eine QUIC-Connection
    (quic.connection.number) beobachtet wurde.

    Bewusst OHNE Betrachtung zeitlicher Überlappung: ipfixprobe kann einen Flow
    bei einem CONNECTION_CLOSE nicht auftrennen. Kommt nach dem Close auf demselben
    5-Tupel eine neue Connection (z.B. Resumption / 0-RTT), landet sie im selben
    ipfixprobe-Flow und wird dort als multiplexed markiert. Die Referenz muss sich
    daher genauso verhalten: >1 Connection auf dem 5-Tupel => multiplexed.
    """
    return (
        df.filter(pl.col("quic.connection.number").is_not_null())
        .group_by("flow_key")
        .agg((pl.col("quic.connection.number").n_unique().max() - 1) .alias("quic_multiplexed")) #thsark starts with 1
        .select(["flow_key", "quic_multiplexed"])
    )


def aggregate_flows(df: pl.DataFrame) -> pl.DataFrame:
    df = df.sort("frame.number")
    multiplexed_df = compute_quic_multiplexed(df)

    pt_v1 = pl.col("quic.long.packet_type")
    pt_v2 = pl.col("quic.long.packet_type_v2")
    ver = pl.col("quic.version")

    valid_ver = pl.col("quic.version").list.eval(
        pl.when(
            (pl.element() == 1)  # QUIC v1
            | (pl.element() == 0x6b3343cf)  # QUIC v2
            | (pl.element().floordiv(256) == 0xff0000)  # IETF Draft (0xff0000xx)
            | ((pl.element() & 0x0f0f0f0f) == 0x0a0a0a0a)  # Grease-Version
        ).then(pl.element()).otherwise(None)
    ).list.drop_nulls()

    # Hat dieser Frame überhaupt ein Long-Header-QUIC-Paket (v1 oder v2)?
    frame_has_long = (
                             pt_v1.list.drop_nulls().list.len().fill_null(0)
                             + pt_v2.list.drop_nulls().list.len().fill_null(0)
                     ) > 0

    # Ist unter den Long-Header-Paketen dieses Frames ein 0-RTT-Paket?
    # (0-RTT ausschließen, weil es dort noch die Client-Version ist, nicht die
    # ausgehandelte Server-Version)
    frame_has_zerortt = (
            pt_v1.list.contains(1).fill_null(False)
            | pt_v2.list.contains(2).fill_null(False)
    )

    # Letzte im Frame beobachtete Version (falls mehrere Header im selben
    # Datagramm gecoalesced sind)
    frame_ver = valid_ver.list.drop_nulls().list.last()

    negotiated_version = (
        frame_ver
        .filter(frame_has_long & ~frame_has_zerortt & frame_ver.is_not_null())
        .last()  # Capture-Reihenfolge (letztes gültiges Long-Header-Frame), NICHT max()
        .alias("quic_version")
    ).replace(1798521807, 2)

    # Nur Frames mit einer erkannten QUIC-Version (v1/v2/Draft/Grease, siehe valid_ver
    # oben) als echtes Retry werten. tshark dissected auch Frames mit kaputter/unbekannter
    # Version als Long-Header-Paket inkl. Typ "Retry", wenn die ersten Bits zufällig passen
    # (z.B. Bitfehler auf dem simulierten Link). Ohne dieses Gate landet dann ein SCID aus
    # Zufallsbytes eines korrupten Pakets in quic_retry_scid.
    frame_has_valid_version = valid_ver.list.len() > 0

    frame_is_retry = (
            (pt_v1.list.contains(3).fill_null(False)
             | pt_v2.list.contains(0).fill_null(False))
            & frame_has_valid_version
    )

    # SCID des Retry-Pakets. Ein Retry-Datagramm enthält so gut wie nie weitere
    # gecoalescte Header, daher reicht hier list.get(0) analog zum Rest des Skripts.
    #
    # Es kann mehrere Retries pro Flow geben: geht das erste Retry verloren, sendet der
    # Client sein Initial erneut und der Server antwortet mit einem NEUEN Retry (neue SCID).
    # Massgeblich ist das Retry, das der Client tatsaechlich uebernommen hat: dessen SCID
    # benutzt er danach als DCID (RFC 9000 §7.2, §17.2.5.2). Dafuer pro Flow die DCIDs der
    # Client-Pakete sammeln und Retries markieren, deren SCID darin vorkommt.
    # Wurde keins uebernommen (z.B. Client antwortet nicht mehr), gilt das letzte Retry.
    df = df.with_columns(pl.col("quic.scid").list.get(0, null_on_oob=True).alias("_scid0"))
    client_dcids = (
        df.filter(pl.col("is_a_to_b") == pl.col("is_a_to_b").first().over("flow_key"))
        .select("flow_key", pl.col("quic.dcid").alias("_dcid"))
        .explode("_dcid")
        .drop_nulls()
        .unique()
        .with_columns(pl.lit(True).alias("_retry_adopted"))
    )
    df = (
        df.join(client_dcids, left_on=["flow_key", "_scid0"], right_on=["flow_key", "_dcid"], how="left")
        .with_columns(pl.col("_retry_adopted").fill_null(False))
        .sort("frame.number")  # Join garantiert keine Reihenfolge
    )
    retry_adopted = frame_is_retry & pl.col("_retry_adopted")

    retry_scid = pl.coalesce(
        pl.col("_scid0").filter(retry_adopted).drop_nulls().first(),
        pl.col("_scid0").filter(frame_is_retry).drop_nulls().last(),
    ).alias("quic_retry_scid")
    # Alle beobachteten Retry-SCIDs (Debugging / optionaler Mengen-Vergleich)
    retry_scids = (
        pl.col("_scid0").filter(frame_is_retry).drop_nulls()
        .unique(maintain_order=True).alias("quic_retry_scids")
    )

    # --- QUIC Token Length -------------------------------------------------------
    # RFC 9000 definiert die Token Length nur pro Initial-Paket, nicht pro Flow.
    #  - Server-Initials MUESSEN Token Length 0 haben (§17.2.2) -> nur Client-Richtung zaehlt.
    #  - Nach einem Retry MUSS der Client das Retry-Token in alle folgenden Initials
    #    schreiben (§8.1.2, §17.2.5.2); das erste Initial kann 0 oder ein NEW_TOKEN-Token
    #    tragen (§8.1.3).
    # -> Pro Flow sind also mehrere legitime Werte moeglich. Die Referenz liefert die MENGE
    #    aller Token-Laengen aus Client-Initials; ipfixprobe ist richtig, wenn sein Wert darin
    #    liegt (Richtigkeit, nicht Vollstaendigkeit).
    #
    # Das Token-Feld gibt es nur im Initial, und in einem gecoalescten Datagramm steht das
    # Initial immer vorne (RFC 9000 §12.2). Daher passt quic.token_length (list.get(0) in
    # load_and_normalize) zum ERSTEN Pakettyp des Frames.
    first_is_initial = (
        (pt_v1.list.get(0, null_on_oob=True) == 0)
        | (pt_v2.list.get(0, null_on_oob=True) == 1)
    ).fill_null(False) & frame_has_valid_version.fill_null(False)

    # Client = Absender des ersten Pakets im Flow (df ist nach frame.number sortiert,
    # group_by mit maintain_order -> first() ist das frueheste Paket).
    from_client = pl.col("is_a_to_b") == pl.col("is_a_to_b").first()

    client_initial = first_is_initial & from_client & pl.col("quic.token_length").is_not_null()

    # ipfixprobe (quic.cpp, PACKET_TYPE::RETRY) uebernimmt nach dem ersten Retry dessen
    # Token-Laenge und ignoriert danach die Client-Initials - unabhaengig davon, ob der Client
    # das Retry ueberhaupt erhalten hat. Die Referenz bildet das nach: gab es ein Retry, ist
    # nur dessen Token-Laenge richtig, sonst die Menge aus den Client-Initials.
    # (Auswahl zwischen beiden erfolgt nach der Aggregation, siehe unten.)
    # Gleiche Auswahl wie bei quic_retry_scid: Token des uebernommenen Retrys, sonst des letzten.
    retry_token_length = pl.coalesce(
        pl.col("quic.retry_token_length").filter(retry_adopted).drop_nulls().first(),
        pl.col("quic.retry_token_length").filter(frame_is_retry).drop_nulls().last(),
    ).alias("quic_retry_token_length")
    token_lengths = (
        pl.col("quic.token_length").filter(client_initial)
        .unique().sort()
        .alias("quic_token_lengths")
    )
    # Strengere Variante: Wert des letzten Client-Initials (= nach einem evtl. Retry).
    # Kann bei Reordering auf dem simulierten Link falsch anschlagen, daher nur optional.
    token_length_final = (
        pl.col("quic.token_length").filter(client_initial)
        .last()
        .alias("quic_token_length_final")
    )

    flows = (
        df.group_by("flow_key", maintain_order=True)
        .agg([
            pl.first("l4_proto").alias("proto"),
            pl.first("endpoint_a").alias("endpoint_a"),
            pl.first("endpoint_b").alias("endpoint_b"),

            pl.len().alias("packet_count"),
            pl.col("ip.len").sum().alias("bytes_total"),

            # Richtungsaufgeteilte Zähler
            pl.col("ip.len").filter(pl.col("is_a_to_b")).sum().alias("bytes_a_to_b"),
            pl.col("ip.len").filter(~pl.col("is_a_to_b")).sum().alias("bytes_b_to_a"),
            pl.len().filter(pl.col("is_a_to_b")).alias("packets_a_to_b"),
            pl.len().filter(~pl.col("is_a_to_b")).alias("packets_b_to_a"),

            # Zeitfenster des Flows
            pl.col("frame.time_epoch").list.get(0).first().alias("t_start"), #es gibt testfälle, in welchem der größte Zeitstempel nicht das letzte packet ist.
            pl.col("frame.time_epoch").list.get(0).last().alias("t_end"), # z.B. data/raw/2026-10-04/lsquic_msquic_handshakeloss_sim_trace_node_left.pcap

            # TCP-Flow-Abschluss erkennen (falls TCP)
            (pl.col("tcp.flags.syn").fill_null(False).sum() > 0).alias("has_syn"),
            (pl.col("tcp.flags.fin").fill_null(False).sum() > 0).alias("has_fin"),
            (pl.col("tcp.flags.reset").fill_null(False).sum() > 0).alias("has_rst"),
            (pl.col("tls.handshake.extensions_server_name").drop_nulls().list.first().first()).alias("quic_sni"),
            negotiated_version,
            token_lengths,
            token_length_final,
            retry_token_length,
            pl.col("tls.handshake.extension.type").drop_nulls().unique().list.eval(
                pl.element().cast(pl.Utf8)).list.join(",").alias("tls_extension_types"),
            pl.col("tls.handshake.extension.len").drop_nulls().unique().list.eval(
                pl.element().cast(pl.Utf8)).list.join(",").alias("tls_extension_lens"),

            pl.col("tls.handshake.type").drop_nulls().unique().list.explode().alias("tls_handshake_types"),
            pl.col("quic.connection.number").drop_nulls().unique().alias("quic_connection_numbers"),
            pl.col("quic.connection.number").drop_nulls().n_unique().alias("quic_connection_count"),
            # QUIC: alle beobachteten Connection-IDs sammeln (falls vorhanden)
            pl.col("quic.dcid").drop_nulls().explode().drop_nulls().unique(maintain_order=True).alias("quic_dcids_seen"),
            pl.col("quic.scid").drop_nulls().explode().drop_nulls().unique(maintain_order=True).alias("quic_scids_seen"),
            pl.col("quic.odcid").drop_nulls().explode().drop_nulls().unique(maintain_order=True).alias("quic_odcids_seen"),
            retry_scid,
            retry_scids,
            pl.col("frame.number").first().alias("first_frame"),
            pl.col("frame.number").last().alias("last_frame"),
        ])
        .with_columns([
            (pl.col("t_end") - pl.col("t_start")).alias("duration_s"),
            pl.when(pl.col("quic_retry_token_length").is_not_null())
            .then(pl.concat_list(pl.col("quic_retry_token_length")))
            .otherwise(pl.col("quic_token_lengths"))
            .alias("quic_token_lengths"),
            ]
        )
        .join(multiplexed_df, on="flow_key", how="left")
        .with_columns(
            pl.col("quic_multiplexed").fill_null(False)
        )
        .sort("bytes_total", descending=True)
    )
    return flows


def prefix_columns(df: pl.DataFrame, prefix, exclude):
    return df.rename({
        col: f"{prefix}_{col}" for col in df.columns if col not in exclude
    })

META_COLS = [
    "flow_key",
    "tshark_first_frame",
    "tshark_last_frame",
    "tshark_t_start",
    "tshark_packet_count",
    "tshark_quic_connection_numbers",
]


def failed_report(failed: pl.DataFrame, *cols) -> dict:
    meta = [c for c in META_COLS if c in failed.columns and c not in cols]
    return {
        "result": "failed",
        "count": failed.height,
        "df": json.loads(failed.select(*meta, *cols).write_json()),
    }

def test_dataframe(df: pl.DataFrame, col_ipfix, col_tshark, threshold=0):
    if df[col_ipfix].dtype == pl.String and df[col_tshark].dtype == pl.String:
        diff = df[col_ipfix].ne(df[col_tshark])
        failed = df.filter(diff)
    else:
        diff = (df[col_ipfix] - df[col_tshark]).abs()
        mismatch_null = df[col_ipfix].is_null() != df[col_tshark].is_null()
        failed = df.filter((diff > threshold) | mismatch_null)

    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)


def test_dataframe_time(df: pl.DataFrame, col_ipfix, col_tshark, threshold=0):
    diff = (df[col_ipfix].cast(pl.Int64) - df[col_tshark].cast(pl.Int64)).abs()
    failed = df.filter(diff > threshold)
    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)


def test_dataframe_str_isin(df: pl.DataFrame, col_ipfix, col_tshark, place=-1):
    relevant = df.filter(
        pl.col(col_ipfix).is_not_null() & (pl.col(col_ipfix) != "")
    )
    if place == -1:
        failed = relevant.filter(~pl.col(col_tshark).list.contains(pl.col(col_ipfix)))
    else:
        failed = relevant.filter(~pl.col(col_tshark).list.get(place, null_on_oob=True).eq(pl.col(col_ipfix)))
    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)

def test_dataframe_int_isin(df: pl.DataFrame, col_ipfix, col_tshark, drop_number_null=False):
    relevant = df
    if drop_number_null:
        relevant = relevant.with_columns(pl.col(col_ipfix).replace(0, None))

    relevant = relevant.filter(
        pl.col(col_ipfix).is_not_null()
    )

    failed = relevant.filter(~pl.col(col_tshark).list.contains(pl.col(col_ipfix)))

    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)


def test_dataframe_integer(df: pl.DataFrame, col_ipfix, col_tshark):
    # used to compare raw numbers to each other
    diff = df[col_ipfix].ne(df[col_tshark])
    failed = df.filter(diff)
    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)


def test_dataframe_lists(df: pl.DataFrame, col_ipfix, col_tshark):
    relevant = df.filter(
        pl.col(col_ipfix).is_not_null() & (pl.col(col_ipfix) != "")
    )
    failed = relevant.filter(~pl.col(col_tshark).list.contains(pl.col(col_ipfix)))
    if failed.is_empty():
        return {"result": "passed"}
    else:
        return failed_report(failed, col_ipfix, col_tshark)

def test_token_length(df: pl.DataFrame, col_ipfix, col_tshark_set):
    # Richtigkeit: der ipfixprobe-Wert muss in mindestens einem Client-Initial des Flows
    # vorkommen (tshark-Menge, siehe aggregate_flows).
    relevant = df.filter(pl.col(col_ipfix).is_not_null())
    # 0 ohne ein einziges Client-Initial im Flow (z.B. Nicht-QUIC-UDP) = "kein Token",
    # das ist kein Widerspruch.
    relevant = relevant.filter(
        ~((pl.col(col_ipfix) == 0) & (pl.col(col_tshark_set).list.len().fill_null(0) == 0))
    )
    # cast: ipfixprobe liefert die Laenge ggf. als UInt16, die Liste ist Int64
    failed = relevant.filter(
        ~pl.col(col_tshark_set).list.contains(pl.col(col_ipfix).cast(pl.Int64)).fill_null(False)
    )
    if failed.is_empty():
        return {"result": "passed"}
    return failed_report(failed, col_ipfix, col_tshark)


def test_multiplexed(df: pl.DataFrame, col_ipfix, col_tshark):
    # Richtigkeit: meldet ipfixprobe Multiplexing (>0), muss tshark es bestaetigen.
    # ipfixprobe == 0 ist "nicht erkannt" -> Vollstaendigkeit, wird nicht bewertet.
    relevant = df.filter(pl.col(col_ipfix).cast(pl.Int64).fill_null(0) > 0)
    failed = relevant.filter(pl.col(col_tshark).cast(pl.Int64).fill_null(0) <= 0)
    if failed.is_empty():
        return {"result": "passed"}
    return {"result": "failed",
            "df": json.loads(failed.select(col_ipfix, col_tshark).write_json())}

def main():
    ap = argparse.ArgumentParser(
        description="Vergleicht eine tshark-Referenz-Parquet-Datei mit einer "
                    "ipfixprobe/flowpipeline-Parquet-Datei auf Flow-Ebene."
    )
    ap.add_argument("--tshark-file", required=True, help="Pfad zur tshark-Parquet-Datei (Referenz)")
    ap.add_argument("--pipeline-file", required=True, help="Pfad zur ipfixprobe/flowpipeline-Parquet-Datei")
    ap.add_argument("--out", required=True, help="Pfad für das Ergebnis-JSON")
    args = ap.parse_args()

    tshark_path = Path(args.tshark_file)
    pipeline_path = Path(args.pipeline_file)
    out_path = Path(args.out)

    tshark_original = load_and_normalize(tshark_path)

    flow_df, nonflow_df = split_flow_vs_nonflow(tshark_original)
    # print(f"Pakete gesamt: {len(tshark_original)} | mit L4-Flow (TCP/UDP): {len(flow_df)} "
    #      f"| ohne (ARP/ICMPv6/...): {len(nonflow_df)}")

    flows_with_key = add_flow_key(flow_df)
    flows_tshark = aggregate_flows(flows_with_key)

    IANA_PROTO = {
        1: "icmp",
        6: "tcp",
        17: "udp",
        41: "ipv6",
        58: "icmpv6",
    }
    try:
        df_loaded = pl.read_parquet(pipeline_path)
    except pl.exceptions.ComputeError:
        print(f"Could not load pipeline file {pipeline_path}!")
        exit(2)
    df_sum = (df_loaded
              .with_columns(pl.sum_horizontal(pl.col("bytes"), pl.col("bytes_rev")).alias("bytes_total"))
              .with_columns(pl.sum_horizontal(pl.col("packets"), pl.col("packets_rev")).alias("packets_count"))
              )
    df_duration = (df_sum
                   .with_columns(
        (pl.col("time_flow_end_ns") - pl.col("time_flow_start_ns")).alias("duration_s")
    )
                   .with_columns(pl.from_epoch(pl.col("time_flow_start_ns"), time_unit="ns"))
                   .with_columns(pl.from_epoch(pl.col("time_flow_end_ns"), time_unit="ns"))
                   )
    df_only_udp_tcp = df_duration.filter(pl.col("proto").is_in([6, 17]))
    df_mapped = df_only_udp_tcp.with_columns(
        pl.col("proto").replace(IANA_PROTO, default=pl.col("proto").cast(pl.Utf8)).alias("proto"))
    df_mapped = df_mapped.with_columns(pl.col("quic_version").replace(1798521807,
                                                                      2))  # mapping because official version number of quic 2 is 0x6B3343CF = 1798521807
    df_concat_ip_ports = (df_mapped
                          .with_columns(
        pl.concat_str([pl.col("src_addr"), pl.col("src_port")], separator=":").alias("endpoint_a"))
                          .with_columns(
        pl.concat_str([pl.col("dst_addr"), pl.col("dst_port")], separator=":").alias("endpoint_b"))
                          )
    flows_pipeline = df_concat_ip_ports.with_columns(
        pl.struct(["proto", "endpoint_a", "endpoint_b"])
        .map_elements(lambda r: canonical_key(r["proto"], r["endpoint_a"], r["endpoint_b"]))
        .alias("flow_key")
    )

    df_pipeline = prefix_columns(flows_pipeline, "ipfixprobe", ["flow_key"])
    df_tshark = prefix_columns(flows_tshark, "tshark", ["flow_key"])

    joined = df_pipeline.join(df_tshark, on="flow_key", suffix="_ref", how="inner")
    THRESHOLD_TIME_NS = 1000
    results = {
        "start_times": test_dataframe_time(joined, "ipfixprobe_time_flow_start_ns", "tshark_t_start", 1000),
        "end_times": test_dataframe_time(joined, "ipfixprobe_time_flow_end_ns", "tshark_t_end", 1000),
        "packet_counts": test_dataframe(joined, "ipfixprobe_packets_count", "tshark_packet_count"),
        "total_bytes": test_dataframe(joined, "ipfixprobe_bytes_total", "tshark_bytes_total"),
        "quic_sni": test_dataframe(joined, "ipfixprobe_quic_sni", "tshark_quic_sni"),
        "quic_occid": test_dataframe_str_isin(joined, "ipfixprobe_quic_occid", "tshark_quic_scids_seen", 0),
        "quic_scid": test_dataframe_str_isin(joined, "ipfixprobe_quic_scid", "tshark_quic_scids_seen"),
        "quic_oscid": test_dataframe_str_isin(joined, "ipfixprobe_quic_oscid", "tshark_quic_dcids_seen", 0),
        "quic_version": test_dataframe_integer(joined, "ipfixprobe_quic_version", "tshark_quic_version"),
        "quic_token_length": test_token_length(joined, "ipfixprobe_quic_token_length", "tshark_quic_token_lengths"),
        "quic_tls_ext_types": test_dataframe_lists(joined, "ipfixprobe_quic_tls_ext_type", "tshark_tls_extension_types"),
        "quic_tls_ext_len": test_dataframe_lists(joined, "ipfixprobe_quic_tls_ext_len", "tshark_tls_extension_lens"),
        "quic_ch_parsed": test_dataframe_int_isin(joined, "ipfixprobe_quic_ch_parsed", "tshark_tls_handshake_types", drop_number_null=True),
        "quic_retry_scid": test_dataframe(joined, "ipfixprobe_quic_retry_scid", "tshark_quic_retry_scid", 0),
        "quic_multiplexed": test_multiplexed(joined, "ipfixprobe_quic_multiplexed", "tshark_quic_multiplexed"),
    }
    with open(out_path, "w") as file:
        file.write(json.dumps(results))


if __name__ == "__main__":
    main()