import tkinter as tk
from tkinter import ttk
from datetime import datetime
import re
import io
import sys
import tkinter.font as tkfont
import node


TS_FMT = "%Y-%m-%d %H:%M:%S.%f"

HIGHLIGHT_RULES = [
    # startup
    ("node_started", r"Node started at"),

    # hello
    ("hello_sent", r"Sent HELLO to"),
    ("hello_recv", r"Received HELLO from"),
    ("hello_regular", r"Received REGULAR HELLO"),
    ("hello_error", r"Error sending HELLO to"),
    ("hello_no_domains", r"No domains found for UPDATE to NS\."),

    # neighbor updates
    ("neighbor_update_rx", r"Received NEIGHBOR UPDATE"),
    ("neighbor_update_tx", r"Forwarded NEIGHBOR UPDATE"),
    ("neighbor_update_buf", r"buffering NEIGHBOR UPDATE"),
    ("neighbor_update_err", r"Error forwarding NEIGHBOR UPDATE"),
    ("neighbor_no_domain_ns", r"No domain\(s\) found for forwarding neighbor update"),
    ("neighbor_added", r"Added neighbor .* to neighbor_table"),
    ("neighbor_exists", r"Neighbor .* already exists in neighbor_table"),
    ("neighbor_removed_stale", r"Removed stale neighbor"),

    # update / fib stuff
    ("ns_update_rx", r"Received UPDATE from"),
    ("ns_update_ignored", r"Ignored NS UPDATE"),
    ("ns_update_tx", r"Sent (NS|topology) UPDATE"),
    ("ns_update_route_missing", r"No FIB entry for NameServer|No FIB entry for domain NameServer"),
    ("fib_updated", r"FIB updated:"),
    ("fib_stored", r"Stored FIB entry for"),
    ("fib_loop", r"FIB next-hop .* incoming iface|FIB loop detected"),

    # interest
    ("interest_recv", r"Received INTEREST"),
    ("interest_pit_add", r"Added .* to PIT with interfaces"),
    ("interest_pit_update", r"Updated PIT for"),
    ("interest_forward_fib", r"Forwarding INTEREST for .* via FIB"),
    ("interest_forward_direct", r"forwarding directly"),
    ("interest_drop_direct", r"Dropped interest for .* as it's a direct neighbor without filename"),

    # encap
    ("encap_forward", r"Forwarded ENCAP packet"),
    ("encap_ns_query", r"Sent NS QUERY for border"),
    ("encap_no_ns", r"No NS to query for border"),

    # ns queries
    ("ns_query_sent", r"Sent NS QUERY for"),
    ("ns_query_fw", r"Forwarded NS QUERY|FORWARDED QUERY ->"),
    ("ns_query_err", r"Error forwarding NS query|Forward-to-NS failed|Forward-to-known-NS failed"),
    ("ns_query_recorded", r"Recorded NS query origin iface"),

    # cs / pit / data path
    ("cs_hit", r"Data found in CS for"),
    ("data_recv", r"Received DATA from"),
    ("data_fragment", r"Received DATA fragment"),
    ("data_reassembled", r"All fragments received\. Reassembled payload"),
    ("data_forwarded_pit", r"Forwarded DATA to PIT interface|Forwarded reassembled DATA"),
    ("pit_removed", r"Removed .* from PIT\."),
    ("pit_removed_iface", r"Removed interface .* from PIT entry"),
    ("pit_removed_empty", r"Removed .* from PIT \(no interfaces left\)"),

    # route data
    ("route_rx", r"Received ROUTE DATA from"),
    ("route_dropped", r"DROPPED ROUTE DATA"),
    ("route_rx2", r"ROUTE_RX from"),
    ("route_debug", r"ROUTE_DEBUG"),
    ("route_buf_snapshot", r"BUFFER_SNAPSHOT count="),
    ("route_buf_entry", r"BUFFER\[\d+\] dest="),
    ("route_buf_match", r"BUFFER_MATCH"),
    ("route_reply_missing", r"Route reply missing dest/next_hop info"),
    ("route_meta_err", r"Failed to install FIB from ROUTE META"),
    ("route_ns_iface", r"Forwarded ROUTE DATA for .* to NS-query iface"),
    ("route_prev_hop", r"Forwarded ROUTE DATA for .* to previous hop"),
    ("route_direct_origin", r"[Ff]orwarded ROUTE DATA directly to origin"),
    ("route_fallback_pit", r"Falling back to PIT forwarding for ROUTE DATA"),
    ("route_mismatch", r"ROUTING_DATA origin_name mismatch"),

    # buffer / queueing
    ("buffer_add", r"Added packet to buffer"),
    ("buffer_proc", r"BUFFER_PROC checking"),
    ("buffer_sent", r"BUFFER_SENT dest="),
    ("buffer_no_pkt", r"BUFFER_NO_PACKET"),
    ("buffer_cannot_resolve", r"BUFFER_PROC cannot resolve next_hop"),
    ("buffer_send_exc", r"BUFFER_SEND_EXC"),
    ("buffer_entry_exc", r"BUFFER_ENTRY_PROC_EXC"),
    ("buffer_dump_exc", r"BUFFER_DUMP_EXC"),
    ("buffer_mark_resolved", r"Marked buffered entry for .* resolved -> next_hop"),
    ("buffer_snapshot", r"BUFFER_SNAPSHOT count="),

    # errors / unknown
    ("listener_err", r"Listener error"),
    ("hello_send_fail", r"HELLO send failed"),
    ("route_handle_exc", r"_handle_route_data EXC"),
    ("process_buffer_exc", r"_process_buffer_loop EXC"),
    ("unknown_packet", r"Unknown packet type"),
    # parse / update errors
    ("ns_parse_neighbor_update_err", r"\[NS parse_neighbor_update_packet] Error parsing packet"),
    ("neighbor_update_parse_err", r"\[parse_neighbor_update_packet] Error parsing packet"),
    ("update_parse_err", r"\[parse_update_packet] Error parsing UPDATE packet"),

    # FIB / route errors
    ("fib_install_route_path_err", r"Error installing FIB from ROUTE path"),
    ("fib_store_ns_err", r"Error storing FIB from NS reply"),

    # buffered / route forwarding errors
    ("buffer_send_err", r"Error sending buffered interest to port"),
    ("route_pit_iface_err", r"Error forwarding ROUTE DATA to PIT iface"),
    ("route_ns_iface_err", r"Error forwarding ROUTE DATA to NS-query iface"),
    ("route_prev_hop_err", r"Error forwarding ROUTE DATA to previous hop"),
    ("route_direct_origin_err", r"Failed direct forward to origin"),
    ("route_pit_port_err", r"Error forwarding ROUTE DATA to PIT port"),

    # NS / HELLO / ENCAP / NS-query errors
    ("ns_update_send_err", r"Error sending UPDATE to NS"),
    ("hello_handle_err", r"Error handling HELLO from"),
    ("encap_forward_err", r"Error forwarding ENCAP to"),
    ("ns_query_send_err", r"Error sending NS query for border|Error forwarding INTEREST query to NS via port|Error sending NS query for .* due to FIB loop"),

    # parse NEIGHBOR UPDATE generic NS message
    ("ns_parse_neighbor_err", r"\[NS parse_neighbor_update_packet] Error parsing packet"),

    # listener stopped
    ("broadcast_listener_stopped", r"Broadcast listener stopped"),


    # ns topology
    ("ns_topology_warn", r"WARNING: topology file"),
    ("ns_topology_err", r"ERROR loading topology"),
    ("ns_topology_saved", r"Topology updated and saved to"),
    ("ns_topology_write_err", r"Error writing topology file"),

    # ns hello / neighbors
    ("ns_error_hello_send", r"Error sending HELLO packet to"),
    ("ns_error_load_neighbors", r"Error loading neighbors from"),

    # ns update
    ("ns_failed_parse_update", r"Failed to parse UPDATE from"),
    ("ns_update_missing", r"Ignored UPDATE missing node or neighbor data"),
    ("ns_update_not_in_domain", r"Ignored UPDATE not in domain"),
    ("ns_update_accept", r"UPDATE accepted:"),
    ("ns_error_handle_update", r"Error handling UPDATE"),

    # ns interest / routing
    ("ns_interest_unknown", r"INTEREST from unknown"),
    ("ns_interest_req", r"ROUTE REQ:"),
    ("ns_encap_forward", r"ENCAP-FORWARDED INTEREST"),
    ("ns_target_not_local", r"Target domain .* not local and no reachable border port found"),
    ("ns_name_not_found", r"No path\. Sent DATA\(NameNotFound\)"),
    ("ns_send_route", r"Sent ROUTE \(next_hop=|Sent ROUTE packet to"),
    ("ns_err_forward_interest", r"Error forwarding INTEREST"),

    # ???
    ("route_next_hop_unknown", r"ROUTE contains next_hop .* but no port known locally"),
    ("ns_route_missing", r"No route to NameServer .* Will keep buffered"),
    ("route_no_pit_direct_origin", r"No PIT for .*; forwarded ROUTE DATA directly to origin"),
    ("fib_installed", r"Installed FIB for"),
    ("fib_updated2", r"Updated FIB:"),
    ("ns_send_route_pkt", r"Sent ROUTE packet to"),
    ("route_pit_iface", r"Forwarded ROUTE DATA for .* to PIT iface port"),
    ("route_pit_port", r"Forwarded ROUTE DATA to PIT port"),
    ("buffer_forwarded_real", r"Forwarded buffered real interest for"),
    ("buffer_added_listener", r"Received packet from .* added to buffer"),
    ("interest_sent", r"Sent INTEREST packet to"),
    ("data_fragment_sent", r"Sent DATA fragment"),
    ("data_sent", r"Sent DATA packet to"),

    ("fib_table_snapshot", r"FIB TABLE SNAPSHOT"),
    ("pit_table_snapshot", r"PIT TABLE SNAPSHOT"),
    ("cs_table_snapshot", r"CS TABLE SNAPSHOT"),

    ("interest_initiated", r"Initiating Interest for"),
    ("fib_hit", r"FIB HIT: REAL_INTEREST"),
    ("pit_entry_added", r"Added PIT entry for"),
    ("ns_query_redirect", r"NS QUERY redirect"),
    ("buffered_originated", r"Buffered originated interest for"),
    ("skipped_forwarding", r"Skipped forwarding .* back to incoming iface"),
    ("destination_direct_neighbor", r"Destination .* is a direct neighbor"),
    ("sent_dropped_error", r"Sent DROPPED_ERROR for"),
    ("sent_error_data_not_found", r"Sent ERROR \(Data Not Found\) for"),
    ("ignoring_ns_query_registration", r"Ignoring ns_query_table registration"),
    ("ignored_registering", r"Ignored registering"),
    ("routed_interest_flag", r"Routed INTEREST with 0x1 flag"),
    ("asked_own_ns", r"Asked own NS"),
    ("registered_ack_only", r"Registered ack-only NS query"),
    ("forwarded_interdomain", r"Forwarded interdomain interest"),
    ("border_ns_query", r"BORDER NS QUERY"),
    ("border_no_suitable_ns", r"BORDER: No suitable NS found"),
    
    ("route_ack_received", r"Received ROUTE_ACK"),
    ("route_ack_forwarded", r"Forwarded ROUTE_ACK"),
    ("no_pending_ns_query", r"No pending NS-query interfaces"),
    ("sent_route_ack_encap", r"Sent ROUTE_ACK for .* to ENCAP origin"),
    ("sent_route_ack_ns_query", r"Sent ROUTE_ACK for .* to NS-query iface"),
    
    ("error_received", r"Received ERROR"),
    ("format_error_received", r"FORMAT_ERROR received"),
    ("forwarded_name_error", r"Forwarded NAME_ERROR"),
    ("forwarded_error_dropped", r"Forwarded ERROR \(Packet Dropped\)"),
    ("forwarded_error_not_found", r"Forwarded ERROR \(Data Not Found\)"),
    
    ("resolved_next_hop_own_port", r"Resolved next_hop_port == self\.port|Next hop resolved to own port"),
    ("forwarded_route_next_hop", r"Forwarded ROUTE_DATA to next_hop"),
    ("forwarded_route_explicit", r"Forwarded ROUTE DATA \(explicit next_hop_port"),
    ("forwarded_buffered_interest", r"Forwarded buffered interest for"),
    ("cannot_resolve_port", r"Cannot resolve port for next_hop_name"),
    ("marked_buffered_resolved", r"Marked buffered entry for .* resolved"),
    
    ("ns_sent_route", r"Sent ROUTE packet to"),
    ("ns_no_border_routers", r"No border routers for domain"),
    ("ns_failed_parse_interest", r"Failed to parse INTEREST"),
    ("ns_sent_format_error", r"Sent FORMAT_ERROR to"),
    ("ns_route_request", r"ROUTE REQ:"),
    ("ns_preparing_route_reply", r"Preparing ROUTE_DATA reply"),
    ("ns_no_pending_encap", r"No pending ENCAP interest for"),
    ("ns_forwarded_route_ack", r"Forwarded ROUTE_ACK → next hop"),
    
    # ns listener error
    ("ns_listener_err", r"\[NS .*] Listener error"),
    
    ("error_sending_real_interest", r"ERROR sending REAL_INTEREST to port"),
    ("failed_forwarding_route_data", r"Failed forwarding ROUTE_DATA to"),
    ("error_forwarding_buffered", r"Error forwarding buffered interests"),
    ("error_forwarding_route_data", r"Error forwarding ROUTE_DATA to"),
    ("error_forwarding_route_ack_iface", r"Error forwarding ROUTE_ACK to iface"),
    ("error_forwarding_route_ack_ns", r"Error forwarding ROUTE_ACK to own NS"),
    ("error_forwarding_route_response", r"Error forwarding ROUTE response to NS-query iface"),
    ("failed_forwarding_to_target", r"Failed forwarding to .* :"),
    ("error_forwarding_ns_query", r"Error forwarding NS query to"),
    ("error_forwarding_interest_query_ns", r"Error forwarding INTEREST query to NS"),
    
    ("ns_failed_send_format_error", r"Failed to send FORMAT_ERROR to"),
    ("ns_error_forwarding_interest", r"Error forwarding INTEREST to .* :"),
    ("ns_error_forwarding_interest_alias", r"Error forwarding INTEREST to alias"),
    ("ns_failed_send_name_error", r"Failed to send NAME_ERROR to"),
    ("ns_error_forwarding_ack", r"Error forwarding ACK to:"),
    ("ns_failed_send_route", r"Failed to send ROUTE to origin"),
    ("ns_failed_send_route_data", r"Failed to send ROUTE_DATA to origin"),
    
    ("forwarded_route_data_pit_port", r"Forwarded ROUTE DATA to PIT port"),
    ("ns_sent_route_with_next_hop", r"Sent ROUTE \(next_hop=.*\) to"),
    ("ns_sent_route_ack_encap", r"Sent ROUTE_ACK for ENCAP name="),
    ("ns_received_route_ack_for", r"Received ROUTE_ACK for .* from"),
    
    ("forwarded_route_data_next_hop", r"Forwarded ROUTE_DATA to next_hop"),
    ("forwarded_route_data_explicit", r"Forwarded ROUTE DATA \(explicit next_hop_port="),
    ("forwarded_route_data_path_origin", r"Forwarded ROUTE DATA along path_to_origin"),
    ("forwarded_route_data_ns_query", r"Forwarded ROUTE DATA for .* to NS-query iface"),
    ("forwarded_route_data_prev_hop", r"Forwarded ROUTE DATA for .* to previous hop"),
    ("forwarded_route_data_origin", r"Forwarded ROUTE DATA directly to origin"),
    ("forwarded_interest_next_hop", r"Forwarded INTEREST packet (for .* )?to next hop"),
    ("forwarded_ns_query", r"Forwarded NS QUERY for"),
    ("forwarded_query_neighbor", r"FORWARDED QUERY -> neighbor"),
    ("forwarded_query_known", r"FORWARDED QUERY -> .* \(port \d+\) for"),
    ("forwarded_error_pit", r"Forwarded ERROR .* for .* to PIT iface"),
    
    ("received_interest_port", r"Received INTEREST from port"),
    ("received_route_data_timestamp", r"Received ROUTE DATA from .* at \d{4}"),
    ("received_error_details", r"Received ERROR .* for .* seq="),
    
    ("received_packet_from", r"Received packet from \('"),
    
    ("ns_computed_path", r"Computed path_from_origin:.*path_to_origin:"),
    ("ns_first_visited_domain", r"First visited domain matches NS domain:"),
    ("ns_reduced_encap", r"Reduced ENCAP for ROUTE_ACK:"),
    ("ns_suppressing_duplicate", r"Suppressing duplicate ENCAP for"),
    ("ns_current_pending", r"Current Pending Interests:"),
    
    ("ns_query_table_display", r"ns_query_table:"),
    ("ns_query_table_add", r"ns_query_table\[.*\] add iface"),
    
    ("sent_ns_query_seq", r"Sent NS QUERY \(seq=\d+\) for"),
]

def _get_node_name(n):
    return getattr(n, "name", getattr(n, "ns_name", "Unknown"))


def _get_node_domains(n):
    raw = _get_node_name(n)
    parts = [p for p in raw.split(" ") if p.strip()]
    domains = set()
    for part in parts:
        part = part.lstrip("/")
        segs = part.split("/")
        if segs and segs[0]:
            domains.add(segs[0])
    return sorted(domains)


def _parse_ts(ts):
    try:
        return datetime.strptime(ts, TS_FMT)
    except Exception:
        return datetime.min


class LogGUI:
    def __init__(self, controller, title="NDN Debugger – Logs"):
        self.controller = controller
        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry("1100x700")
        self.root.minsize(900, 550)

        self.selected_nodes = set()
        self.auto_refresh = tk.BooleanVar(value=True)
        self.search_term = tk.StringVar(value="")
        self.command_entries = []

        # for node tables
        self.current_table = "FIB"
        self.table_buttons = {}
        self.table_tree = None
        self.table_tree_scroll = None
        self.table_message = None

        self._build_layout()
        self._populate_filters()
        self._start_refresh_loop()
        self._update_table_tab_styles()
        self._update_node_table()

    # tables for logs
    def _format_table(self, headers, rows):
        col_widths = []
        for i, h in enumerate(headers):
            max_len = len(str(h))
            for r in rows:
                if i < len(r):
                    max_len = max(max_len, len(str(r[i])))
            col_widths.append(max_len)

        def fmt_row(row):
            return "  " + "  ".join(
                str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)
            )

        lines = []
        lines.append(fmt_row(headers))
        lines.append("  " + "  ".join("-" * w for w in col_widths))
        for r in rows:
            lines.append(fmt_row(r))
        return "\n".join(lines)

    def _format_fib_table_for_node(self, node):
        fib = getattr(node, "fib", {}) or {}
        headers = ["Pos", "Name", "NextHop", "HopCount"]
        rows = []
        for idx, (name, info) in enumerate(fib.items(), start=1):
            nh = info.get("NextHops", "")
            hc = info.get("HopCount", "")
            rows.append([idx, name, nh, hc])

        if not rows:
            rows.append(["-", "(empty)", "-", "-"])

        return self._format_table(headers, rows)

    # ui
    def _build_layout(self):
        self.root.configure(bg="white")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        # for resizable panels
        self.paned_window = tk.PanedWindow(
            self.root, 
            orient=tk.HORIZONTAL, 
            sashwidth=8,
            bg="#cccccc",
            sashrelief=tk.RAISED
        )
        self.paned_window.grid(row=0, column=0, sticky="nsew")

        # global logs
        left_wrap = tk.Frame(self.paned_window, bg="#e0e0e0")
        self.paned_window.add(left_wrap, minsize=400)
        left = tk.Frame(left_wrap, bg="#e0e0e0")
        left.pack(fill="both", expand=True, padx=8, pady=8)

        header = ttk.Label(
            left,
            text="Global Logs",
            font=("Segoe UI", 14, "bold"),
            background="#e0e0e0",
        )
        header.pack(anchor="w")

        controls = tk.Frame(left, bg="#e0e0e0")
        controls.pack(fill="x", pady=(6, 6))
        ttk.Checkbutton(controls, text="Auto refresh", variable=self.auto_refresh).pack(
            side="left"
        )
        ttk.Button(controls, text="Refresh now", command=self.refresh).pack(
            side="left", padx=(8, 0)
        )
        ttk.Button(controls, text="Clear", command=self._clear_logs_view).pack(
            side="left", padx=(8, 0)
        )

        ttk.Label(controls, text="Search:").pack(side="left", padx=(12, 4))
        search_entry = ttk.Entry(controls, textvariable=self.search_term, width=24)
        search_entry.pack(side="left")
        search_entry.bind("<Return>", lambda e: self.refresh())

        # scrollable text
        log_container = tk.Frame(left, bg="#e0e0e0")
        log_container.pack(expand=True, fill="both")

        self.log_text = tk.Text(
            log_container, wrap="word", state="disabled", bg="white", fg="black"
        )
        self.log_text.pack(side="left", fill="both", expand=True)
        self.log_text.tag_configure("match", background="#fff2a8")

        # font and colors for global logs
        self.log_font = tkfont.nametofont("TkFixedFont")
        self.log_bold_font = self.log_font.copy()
        self.log_bold_font.configure(weight="bold")

        self.log_text.tag_configure("neighbor_update", foreground="HotPink2")

        # bold node names
        self.log_text.tag_configure("node_name", font=self.log_bold_font)
        

        # startup / topology / ns-ish stuff
        for tag in (
            "node_started",
            "hello_sent", "hello_recv", "hello_regular",
            "neighbor_update_rx", "neighbor_update_tx",
            "ns_update_rx", "ns_update_tx",
            "ns_query_sent", "ns_query_fw",
            "route_rx", "route_rx2",
            # ns
            "ns_topology_saved", "ns_topology_warn",
            "ns_update_accept",
            "ns_interest_req", "ns_encap_forward", "ns_send_route",
            "ns_sent_route", "ns_route_request", "ns_preparing_route_reply",
            "ns_computed_path", "ns_first_visited_domain",
            "ns_reduced_encap", "ns_suppressing_duplicate",
        ):
            self.log_text.tag_configure(tag, foreground="HotPink2")

        # interest / data / cs / pit / successful path
        for tag in (
            "cs_hit",
            "data_recv", "data_fragment", "data_reassembled",
            "data_forwarded_pit", "interest_recv",
            "pit_removed", "pit_removed_iface", "pit_removed_empty",
            "interest_pit_add", "interest_pit_update",
            "interest_forward_fib", "interest_forward_direct",
            "encap_forward", "interest_sent", "data_fragment_sent", "data_sent",
            "interest_initiated", "fib_hit", "pit_entry_added",
            "destination_direct_neighbor", "route_ack_received", "route_ack_forwarded",
            "ns_forwarded_route_ack",
            # ns
            "ns_encap_forward", "ns_send_route",
            "forwarded_interest_next_hop", "forwarded_ns_query",
            "forwarded_query_neighbor", "forwarded_query_known",
            "forwarded_error_pit", "received_interest_port",
            "received_error_details", "sent_ns_query_seq",
        ):
            self.log_text.tag_configure(tag, foreground="dark green")


        # buffer / debug info
        for tag in ("buffer_add", "buffer_proc", "buffer_sent",
                    "buffer_no_pkt", "buffer_cannot_resolve",
                    "buffer_mark_resolved",
                    "buffer_snapshot", "route_debug", "route_buf_snapshot",
                    "route_buf_entry", "route_buf_match",
                    "buffer_forwarded_real", "ns_query_recorded", "buffer_added_listener",
                    "buffered_originated", "forwarded_buffered_interest",
                    "marked_buffered_resolved", "ignoring_ns_query_registration",
                    "ignored_registering", "registered_ack_only",
                    "forwarded_interdomain", "ns_query_redirect",
                    "ns_query_table_display", "ns_query_table_add",
                    "ns_current_pending", "received_packet_from"):
            self.log_text.tag_configure(tag, foreground="purple")

        # warnings
        for tag in (
            "fib_loop", "ns_update_route_missing",
            "interest_drop_direct",
            "route_dropped", "route_reply_missing",
            "route_fallback_pit", "route_mismatch",
            "ns_route_missing", "encap_no_ns", "hello_no_domains",
            "neighbor_update_buf", "neighbor_no_domain_ns",
            "route_next_hop_unknown", "route_no_pit_direct_origin",
            "skipped_forwarding", "sent_dropped_error", "sent_error_data_not_found",
            "no_pending_ns_query", "cannot_resolve_port",
            "resolved_next_hop_own_port", "routed_interest_flag",
            "border_ns_query", "border_no_suitable_ns",
            # ns warnings
            "ns_update_missing", "ns_update_not_in_domain",
            "ns_target_not_local", "ns_name_not_found",
            "ns_route_missing", "ns_no_border_routers",
            "ns_no_pending_encap",
        ):
            self.log_text.tag_configure(tag, foreground="DarkGoldenrod3")


        # errors / exceptions / failures
        for tag in (
            "hello_error", "hello_send_fail",
            "ns_query_err", "neighbor_update_err",
            "listener_err", "route_meta_err",
            "route_handle_exc", "process_buffer_exc",
            "buffer_entry_exc", "buffer_dump_exc",
            "unknown_packet",
            "error_received", "format_error_received",
            "forwarded_name_error", "forwarded_error_dropped", "forwarded_error_not_found",
            "asked_own_ns",
            # ns errors
            "ns_topology_err", "ns_topology_write_err",
            "ns_error_hello_send", "ns_error_load_neighbors",
            "ns_failed_parse_update", "ns_error_handle_update",
            "ns_err_forward_interest", "ns_listener_err",
            "ns_failed_parse_interest", "ns_sent_format_error",
            "ns_parse_neighbor_update_err", "neighbor_update_parse_err",
            "update_parse_err", "fib_install_route_path_err",
            "fib_store_ns_err", "buffer_send_err",
            "route_pit_iface_err", "route_ns_iface_err",
            "route_prev_hop_err", "route_direct_origin_err",
            "route_pit_port_err", "ns_update_send_err",
            "hello_handle_err", "encap_forward_err",
            "ns_query_send_err", "broadcast_listener_stopped",
            "error_sending_real_interest", "failed_forwarding_route_data",
            "error_forwarding_buffered", "error_forwarding_route_data",
            "error_forwarding_route_ack_iface", "error_forwarding_route_ack_ns",
            "error_forwarding_route_response", "failed_forwarding_to_target",
            "error_forwarding_ns_query", "error_forwarding_interest_query_ns",
            "ns_failed_send_format_error", "ns_error_forwarding_interest",
            "ns_error_forwarding_interest_alias", "ns_failed_send_name_error",
            "ns_error_forwarding_ack", "ns_failed_send_route",
            "ns_failed_send_route_data",
        ):
            self.log_text.tag_configure(tag, foreground="red")


        # fib updates / routing info
        for tag in ("fib_updated", "fib_stored",
                    "route_ns_iface", "route_prev_hop",
                    "route_direct_origin", "fib_installed", "fib_updated2",
                    "ns_send_route_pkt",
                    "route_pit_iface", "route_pit_port", 
                    "fib_table_snapshot", "pit_table_snapshot", "cs_table_snapshot",
                    "forwarded_route_next_hop", "forwarded_route_explicit",
                    "sent_route_ack_encap", "sent_route_ack_ns_query",
                    "forwarded_route_data_pit_port",
                    "ns_sent_route_with_next_hop", "ns_sent_route_ack_encap",
                    "ns_received_route_ack_for",
                    "forwarded_route_data_next_hop", "forwarded_route_data_explicit",
                    "forwarded_route_data_path_origin", "forwarded_route_data_ns_query",
                    "forwarded_route_data_prev_hop", "forwarded_route_data_origin",
                    "received_route_data_timestamp"):
            self.log_text.tag_configure(tag, foreground="blue")

        # -----------------------------------------------

        yscroll = ttk.Scrollbar(
            log_container, orient="vertical", command=self.log_text.yview
        )
        yscroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=yscroll.set)

        # bottom input area
        bottom = tk.Frame(left, bg="#e0e0e0")
        bottom.pack(fill="x", pady=(10, 0))
        self.footer_box = tk.Text(bottom, height=3)
        self.footer_box.pack(fill="x")

        # for commands
        cmd_bar = tk.Frame(left, bg="#e0e0e0")
        cmd_bar.pack(fill="x", pady=(6, 0))
        ttk.Button(cmd_bar, text="Send", command=self._send_command).pack(side="right")
        ttk.Label(cmd_bar, text="Command (press Enter to send):").pack(side="left")

        def _on_return(event):
            self._send_command()
            return "break"

        self.footer_box.bind("<Return>", _on_return)
        self.footer_box.bind("<Control-Return>", lambda e: None)

        # logs filter + node tables
        right_wrap = tk.Frame(self.paned_window, bg="#e0e0e0")
        self.paned_window.add(right_wrap, minsize=300)
        right = tk.Frame(right_wrap, bg="#e0e0e0")
        right.pack(fill="both", expand=True, padx=8, pady=8)

        rf_head = ttk.Label(
            right,
            text="Logs Filter",
            font=("Segoe UI", 14, "bold"),
            background="#e0e0e0",
        )
        rf_head.pack(anchor="w")

        # top scrollable filter
        filters_container = tk.Frame(right, bg="#e0e0e0")
        filters_container.pack(fill="both", expand=True)

        self.filter_canvas = tk.Canvas(
            filters_container, highlightthickness=0, bg="#e0e0e0"
        )
        self.filter_scroll = ttk.Scrollbar(
            filters_container, orient="vertical", command=self.filter_canvas.yview
        )
        self.filter_canvas.configure(yscrollcommand=self.filter_scroll.set)
        self.filter_scroll.pack(side="right", fill="y")
        self.filter_canvas.pack(side="left", fill="both", expand=True)

        self.filters_frame = tk.Frame(self.filter_canvas, bg="#e0e0e0")
        self.filter_canvas.create_window(
            (0, 0), window=self.filters_frame, anchor="nw"
        )
        self.filters_frame.bind(
            "<Configure>",
            lambda e: self.filter_canvas.configure(
                scrollregion=self.filter_canvas.bbox("all")
            ),
        )

        # bottom tables (FIB / CS / PIT / Neighbors / Buffer / Logs / Registry)
        self.tables_panel = tk.Frame(right, bg="#e0e0e0")
        self.tables_panel.pack(fill="both", expand=False, pady=(8, 0))
        self._build_node_tables(self.tables_panel)

    # tables ui
    def _build_node_tables(self, parent):
        title = ttk.Label(
            parent,
            text="Node Tables",
            font=("Segoe UI", 12, "bold"),
            background="#e0e0e0",
        )
        title.pack(anchor="w")

        modes_row = tk.Frame(parent, bg="#e0e0e0")
        modes_row.pack(fill="x", pady=(4, 2))

        def make_mode_button(label, mode):
            btn = tk.Button(
                modes_row,
                text=label,
                bg="white",
                fg="black",
                activebackground="#f0f0f0",
                activeforeground="black",
                relief="flat",
                padx=8,
                pady=4,
                bd=1,
                highlightthickness=1,
                highlightbackground="#000000",
                command=lambda m=mode: self._set_table_mode(m),
            )
            btn.pack(side="left", padx=(0, 4))
            self.table_buttons[mode] = btn

        # main modes
        make_mode_button("FIB", "FIB")
        make_mode_button("CS", "CS")
        make_mode_button("PIT", "PIT")
        make_mode_button("Neighbors", "NEIGHBORS")
        make_mode_button("Buffer", "BUFFER")
        make_mode_button("Logs", "LOGS")
        make_mode_button("Registry", "REGISTRY")

        # refresh button
        refresh_row = tk.Frame(parent, bg="#e0e0e0")
        refresh_row.pack(fill="x", pady=(0, 4))
        ttk.Button(
            refresh_row, text="Refresh Table", command=self._update_node_table
        ).pack(side="left")

        # table
        self.table_container = tk.Frame(parent, bg="#e0e0e0")
        self.table_container.pack(fill="both", expand=True)

        # when no node selected
        self.table_message = ttk.Label(
            self.table_container,
            text="Select exactly one node to view FIB / CS / PIT / Neighbors / Buffer / Logs / Registry.",
            background="#e0e0e0",
            foreground="#555555",
        )
        self.table_message.pack(expand=True)

        # actual table
        self.table_tree = ttk.Treeview(self.table_container, show="headings")
        self.table_tree_scroll = ttk.Scrollbar(
            self.table_container, orient="vertical", command=self.table_tree.yview
        )
        self.table_tree.configure(yscrollcommand=self.table_tree_scroll.set)

    def _set_table_mode(self, mode):
        self.current_table = mode
        self._update_table_tab_styles()
        self._update_node_table()

    def _update_table_tab_styles(self):
        for mode, btn in self.table_buttons.items():
            if mode == self.current_table:
                btn.configure(
                    bg="black",
                    fg="white",
                    activebackground="#333333",
                    activeforeground="white",
                    relief="raised",
                    bd=2,
                    highlightbackground="#000000",
                )
            else:
                btn.configure(
                    bg="white",
                    fg="black",
                    activebackground="#f0f0f0",
                    activeforeground="black",
                    relief="flat",
                    bd=1,
                    highlightbackground="#000000",
                )

    def _get_selected_single_node(self):
        if len(self.selected_nodes) != 1:
            return None
        target_name = next(iter(self.selected_nodes))
        for n in self.controller.nodes.values():
            if _get_node_name(n) == target_name:
                return n
        return None

    def _update_node_table(self):
        node = self._get_selected_single_node()

        if node is None:
            self.table_tree.pack_forget()
            self.table_tree_scroll.pack_forget()
            self.table_message.configure(
                text="Select exactly one node to view FIB / CS / PIT / Neighbors / Buffer / Logs / Registry."
            )
            self.table_message.pack(expand=True)
            return

        self.table_message.pack_forget()
        self.table_tree.pack(side="left", fill="both", expand=True)
        self.table_tree_scroll.pack(side="right", fill="y")

        # clear
        for col in self.table_tree["columns"]:
            self.table_tree.heading(col, text="")
        self.table_tree.delete(*self.table_tree.get_children())

        mode = self.current_table
        rows = []

        if mode == "FIB":
            cols = ("name", "next_hop", "hop_count")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("name", width=300, anchor="w")
            self.table_tree.column("next_hop", width=120, anchor="center")
            self.table_tree.column("hop_count", width=120, anchor="center")

            fib = getattr(node, "fib", {})
            for name, info in fib.items():
                nh = info.get("NextHops", "")
                hc = info.get("HopCount", "")
                rows.append((name, nh, hc))

        elif mode == "CS":
            cols = ("name", "data")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("name", width=260, anchor="w")
            self.table_tree.column("data", width=260, anchor="w")

            cs = getattr(node, "cs", {})
            for name, data in cs.items():
                if isinstance(data, bytes):
                    text = data.decode('utf-8', errors='replace')
                elif data is None:
                    text = ""
                else:
                    text = str(data)
                if len(text) > 80:
                    text = text[:77] + "..."
                rows.append((name, text))

        elif mode == "PIT":
            cols = ("name", "interfaces")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("name", width=260, anchor="w")
            self.table_tree.column("interfaces", width=180, anchor="w")

            pit = getattr(node, "pit", {})
            for name, interfaces in pit.items():
                if isinstance(interfaces, (list, tuple, set)):
                    iface_str = ", ".join(str(i) for i in interfaces)
                else:
                    iface_str = str(interfaces)
                rows.append((name, iface_str))

        elif mode == "NEIGHBORS":
            cols = ("neighbor", "last_seen")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("neighbor", width=260, anchor="w")
            self.table_tree.column("last_seen", width=180, anchor="center")

            neighbor_table = getattr(node, "neighbor_table", None)
            if neighbor_table is None and hasattr(node, "get_neigbors"):
                try:
                    neighbor_table = node.get_neigbors()
                except Exception:
                    neighbor_table = {}
            if neighbor_table is None:
                neighbor_table = {}

            for name, ts in neighbor_table.items():
                rows.append((name, ts))

        elif mode == "BUFFER":
            cols = (
                "packet",
                "source",
                "destination",
                "status",
                "timestamp",
                "hop_history",
                "reason",
                "next_hop",
                "forwarded_to_ns",
            )
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())

            self.table_tree.column("packet", width=100, anchor="w")
            self.table_tree.column("source", width=100, anchor="w")
            self.table_tree.column("destination", width=160, anchor="w")
            self.table_tree.column("status", width=80, anchor="center")
            self.table_tree.column("timestamp", width=150, anchor="center")
            self.table_tree.column("hop_history", width=140, anchor="w")
            self.table_tree.column("reason", width=160, anchor="w")
            self.table_tree.column("next_hop", width=80, anchor="center")
            self.table_tree.column("forwarded_to_ns", width=110, anchor="center")

            buf = getattr(node, "buffer", [])
            try:
                iterator = list(buf)
            except TypeError:
                iterator = []

            for entry in iterator:
                pkt = entry.get("packet", "")
                pkt_str = repr(pkt)
                if len(pkt_str) > 40:
                    pkt_str = pkt_str[:37] + "..."

                src = entry.get("source", "")
                dest = entry.get("destination", "")
                status = entry.get("status", "")
                ts = entry.get("timestamp", "")

                hop_history = entry.get("hop_history", [])
                if isinstance(hop_history, (list, tuple, set)):
                    hop_str = " → ".join(str(h) for h in hop_history)
                else:
                    hop_str = str(hop_history)

                reason = entry.get("reason", "")
                nh = entry.get("next_hop", "")

                fwd = entry.get("forwarded_to_ns", "")
                if isinstance(fwd, bool):
                    fwd_str = "Yes" if fwd else "No"
                else:
                    fwd_str = str(fwd)

                rows.append(
                    (
                        pkt_str,
                        src,
                        dest,
                        status,
                        ts,
                        hop_str,
                        reason,
                        nh,
                        fwd_str,
                    )
                )

        elif mode == "LOGS":
            cols = ("timestamp", "message")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("timestamp", width=170, anchor="center")
            self.table_tree.column("message", width=320, anchor="w")

            logs = getattr(node, "logs", [])
            for entry in logs:
                ts = entry.get("timestamp", "")
                msg = entry.get("message", "")
                rows.append((ts, msg))

        elif mode == "REGISTRY":
            cols = ("name", "info")
            self.table_tree["columns"] = cols
            for c in cols:
                self.table_tree.heading(c, text=c.replace("_", " ").title())
            self.table_tree.column("name", width=260, anchor="w")
            self.table_tree.column("info", width=240, anchor="w")

            reg = getattr(node, "registry", getattr(node, "registered_nodes", {}))
            if reg is None:
                reg = {}
            if isinstance(reg, dict):
                for name, info in reg.items():
                    rows.append((name, str(info)))
            else:
                rows.append(("Registry", str(reg)))

        # alternating row colors
        for idx, row in enumerate(rows):
            tag = "odd" if idx % 2 else "even"
            self.table_tree.insert("", "end", values=row, tags=(tag,))

        self.table_tree.tag_configure("even", background="#ffffff")
        self.table_tree.tag_configure("odd", background="#f5f5f5")

    # nodes
    def _populate_filters(self):
        by_domain = {}
        for n in self.controller.nodes.values():
            for d in _get_node_domains(n):
                by_domain.setdefault(d, []).append(n)

        for child in self.filters_frame.winfo_children():
            child.destroy()

        self.node_buttons = {}

        for domain, nodes in sorted(by_domain.items(), key=lambda kv: kv[0]):
            box = tk.LabelFrame(
                self.filters_frame,
                text=domain,
                bg="#e0e0e0",
                fg="black",
                padx=8,
                pady=8,
            )
            box.pack(fill="x", padx=4, pady=6)

            # select all / clear
            row = tk.Frame(box, bg="#e0e0e0")
            row.pack(fill="x", pady=(0, 6))
            ttk.Button(row, text="Select all", command=lambda ns=nodes: self._select_nodes(ns)).pack(
                side="left"
            )
            ttk.Button(row, text="Clear", command=lambda ns=nodes: self._deselect_nodes(ns)).pack(
                side="left", padx=6
            )

            # node buttons
            for n in sorted(nodes, key=lambda x: _get_node_name(x).lower()):
                name = _get_node_name(n)
                btn = tk.Button(
                    box,
                    text=name,
                    bg="white",
                    fg="black",
                    activebackground="#f0f0f0",
                    activeforeground="black",
                    relief="flat",
                    padx=10,
                    pady=6,
                    bd=1,
                    highlightthickness=1,
                    highlightbackground="#000000",
                )
                btn.pack(fill="x", pady=3)
                self.node_buttons[name] = btn

                def _toggle(ev=None, nm=name, b=btn):
                    if nm in self.selected_nodes:
                        self.selected_nodes.remove(nm)
                    else:
                        self.selected_nodes.add(nm)
                    self._update_button_styles()
                    self.refresh()
                    self._update_node_table()

                btn.bind("<Button-1>", _toggle)

        # reset selection
        bottom = tk.Frame(self.filters_frame, bg="#e0e0e0")
        bottom.pack(fill="x", pady=10)
        ttk.Button(bottom, text="Reset selection", command=self._reset_selection).pack(
            side="left"
        )

        self._update_button_styles()

    def _select_nodes(self, nodes):
        for n in nodes:
            self.selected_nodes.add(_get_node_name(n))
        self._update_button_styles()
        self.refresh()
        self._update_node_table()

    def _deselect_nodes(self, nodes):
        for n in nodes:
            self.selected_nodes.discard(_get_node_name(n))
        self._update_button_styles()
        self.refresh()
        self._update_node_table()

    def _reset_selection(self):
        self.selected_nodes.clear()
        self._update_button_styles()
        self.refresh()
        self._update_node_table()

    def _update_button_styles(self):
        for name, btn in self.node_buttons.items():
            if name in self.selected_nodes:
                btn.configure(
                    bg="black",
                    fg="white",
                    activebackground="#333333",
                    activeforeground="white",
                    relief="raised",
                    bd=2,
                    highlightbackground="#000000",
                )
            else:
                btn.configure(
                    bg="white",
                    fg="black",
                    activebackground="#f0f0f0",
                    activeforeground="black",
                    relief="flat",
                    bd=1,
                    highlightbackground="#000000",
                )

    def _collect_logs(self):
        selected = self.selected_nodes
        
        if hasattr(node, '_global_log_buffer'):
            all_logs = list(node._global_log_buffer)
        else:
            all_logs = []
        
        all_logs.extend(self.command_entries)
        
        if selected:
            filtered_logs = []
            for ts, line in all_logs:
                if line.startswith("[CMD]"):
                    filtered_logs.append((ts, line))
                else:
                    for node_name in selected:
                        if f"[{node_name}]" in line:
                            filtered_logs.append((ts, line))
                            break
            return filtered_logs
        
        return all_logs


    def _clear_logs_view(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def refresh(self):
        logs = self._collect_logs()
        self._clear_logs_view()
        self.log_text.configure(state="normal")
        self.log_text.tag_configure("divider", foreground="#888888")

        last_was_cmd = False
        for ts, line in logs:
            if line.startswith("[CMD]") and not last_was_cmd:
                self.log_text.insert(
                    "end", "------------------------------\n", ("divider",)
                )

            # no timestamp in global logs
            start_index = self.log_text.index("end-1c linestart")
            self.log_text.insert("end", line + "\n")
            end_index = self.log_text.index("end-1c")

            # If entry contains an `Object:`/table or a `Timestamp` row, add
            # an extra blank line to separate it from the next log entry.
            try:
                if "\n" in line or re.search(r'^\s*Timestamp\s+\d{4}-\d{2}-\d{2} ', line, re.M) or line.strip().startswith("Object:"):
                    self.log_text.insert("end", "\n")
            except Exception:
                pass

            # colors
            for tag_name, pattern in HIGHLIGHT_RULES:
                for m in re.finditer(pattern, line):
                    tag_start = f"{start_index}+{m.start()}c"
                    tag_end   = f"{start_index}+{m.end()}c"
                    self.log_text.tag_add(tag_name, tag_start, tag_end)

            # bold node names
            for m in re.finditer(r"\[[^\]]+\]", line):
                tag_start = f"{start_index}+{m.start()}c"
                tag_end   = f"{start_index}+{m.end()}c"
                self.log_text.tag_add("node_name", tag_start, tag_end)

            # table snapshots
            if "Installed FIB for" in line or "Updated FIB:" in line or "FIB updated:" in line:
                m = re.match(r"\[([^\]]+)\]", line)
                if m:
                    node_name = m.group(1)
                    node_obj = None
                    for n in self.controller.nodes.values():
                        if _get_node_name(n) == node_name:
                            node_obj = n
                            break

                    if node_obj is not None:
                        table_str = self._format_fib_table_for_node(node_obj)
                        header = f"[{node_name}] FIB TABLE SNAPSHOT:\n"
                        self.log_text.insert("end", header, ("fib_table_snapshot",))
                        self.log_text.insert("end", table_str + "\n")
            
            # prints FIB into tables
            if " FIB: " in line and "{" in line:
                parts = line.split(" FIB: ", 1)
                if len(parts) == 2:
                    node_label = parts[0].strip()
                    fib_str = parts[1].strip()
                    
                    try:
                        import ast
                        fib_dict = ast.literal_eval(fib_str)
                        
                        if isinstance(fib_dict, dict) and fib_dict:
                            max_name_len = max(len(name) for name in fib_dict.keys())
                            max_name_len = max(max_name_len, len("Name"))
                            
                            table_lines = []
                            table_lines.append(f"\n{node_label} FIB:")
                            table_lines.append(f"  {'Name'.ljust(max_name_len)}  {'NextHop'.ljust(10)}  {'HopCount'.ljust(10)}")
                            table_lines.append(f"  {'-' * max_name_len}  {'-' * 10}  {'-' * 10}")
                            
                            for name, info in fib_dict.items():
                                next_hop = str(info.get('NextHops', ''))
                                hop_count = str(info.get('HopCount', ''))
                                table_lines.append(f"  {name.ljust(max_name_len)}  {next_hop.ljust(10)}  {hop_count.ljust(10)}")
                            
                            self.log_text.delete(start_index, end_index)
                            self.log_text.insert(start_index, "\n".join(table_lines) + "\n")
                    except:
                        pass
            
            # prints neighbors into tables
            if " neighbors:" in line and "{" in line:
                parts = line.split(" neighbors:", 1)
                if len(parts) == 2:
                    node_label = parts[0].strip()
                    neighbor_str = parts[1].strip()
                    
                    try:
                        import ast
                        neighbor_dict = ast.literal_eval(neighbor_str)
                        
                        if isinstance(neighbor_dict, dict) and neighbor_dict:
                            max_name_len = max(len(name) for name in neighbor_dict.keys())
                            max_name_len = max(max_name_len, len("Neighbor"))
                            max_time_len = max(len(str(ts)) for ts in neighbor_dict.values())
                            max_time_len = max(max_time_len, len("Last Seen"))
                            
                            table_lines = []
                            table_lines.append(f"\n{node_label} neighbors:")
                            table_lines.append(f"  {'Neighbor'.ljust(max_name_len)}  {'Last Seen'.ljust(max_time_len)}")
                            table_lines.append(f"  {'-' * max_name_len}  {'-' * max_time_len}")
                            
                            for name, timestamp in neighbor_dict.items():
                                table_lines.append(f"  {name.ljust(max_name_len)}  {str(timestamp).ljust(max_time_len)}")
                            
                            self.log_text.delete(start_index, end_index)
                            self.log_text.insert(start_index, "\n".join(table_lines) + "\n")
                    except:
                        pass
            
            # prints parsed into tables
            if line.startswith("Parsed:") and "{" in line:
                parsed_str = line.split("Parsed:", 1)[1].strip()
                
                try:
                    import ast
                    parsed_dict = ast.literal_eval(parsed_str)
                    
                    if isinstance(parsed_dict, dict) and parsed_dict:
                        max_key_len = max(len(str(k)) for k in parsed_dict.keys())
                        max_key_len = max(max_key_len, len("Field"))
                        max_val_len = max(len(str(v)) for v in parsed_dict.values())
                        max_val_len = max(max_val_len, len("Value"))
                        
                        table_lines = []
                        table_lines.append("\nParsed:")
                        table_lines.append(f"  {'Field'.ljust(max_key_len)}  {'Value'.ljust(max_val_len)}")
                        table_lines.append(f"  {'-' * max_key_len}  {'-' * max_val_len}")
                        
                        for key, value in parsed_dict.items():
                            table_lines.append(f"  {str(key).ljust(max_key_len)}  {str(value).ljust(max_val_len)}")
                        
                        self.log_text.delete(start_index, end_index)
                        self.log_text.insert(start_index, "\n".join(table_lines) + "\n")
                except:
                    pass
            
            # prints object into tables
            if line.startswith("Object:") and "<" in line and ">" in line:
                obj_str = line.split("Object:", 1)[1].strip()
                
                try:
                    if obj_str.startswith("<") and obj_str.endswith(">"):
                        content = obj_str[1:-1]
                        parts = content.split(None, 1)
                        
                        if len(parts) == 2:
                            class_name = parts[0]
                            fields_str = parts[1]
                            
                            fields = {}
                            # Find key=value pairs where value may contain spaces
                            for m in re.finditer(r'([A-Za-z0-9_]+)=((?:(?!\s+[A-Za-z0-9_]+=).)*)', fields_str):
                                key = m.group(1)
                                val = m.group(2).strip()
                                fields[key] = val
                            
                            if fields:
                                max_key_len = max(len(str(k)) for k in fields.keys())
                                max_key_len = max(max_key_len, len("Field"))
                                max_val_len = max(len(str(v)) for v in fields.values())
                                max_val_len = max(max_val_len, len("Value"))
                                
                                table_lines = []
                                table_lines.append(f"\nObject: {class_name}")
                                table_lines.append(f"  {'Field'.ljust(max_key_len)}  {'Value'.ljust(max_val_len)}")
                                table_lines.append(f"  {'-' * max_key_len}  {'-' * max_val_len}")
                                
                                for key, value in fields.items():
                                    table_lines.append(f"  {str(key).ljust(max_key_len)}  {str(value).ljust(max_val_len)}")
                                
                                self.log_text.delete(start_index, end_index)
                                self.log_text.insert(start_index, "\n".join(table_lines) + "\n")
                except:
                    pass

            last_was_cmd = line.startswith("[CMD]") or line.startswith("[CMD-OUT]")

        # highlight search
        term = self.search_term.get().strip()
        self.log_text.tag_remove("match", "1.0", "end")
        if term:
            pattern = re.escape(term)
            start = "1.0"
            while True:
                idx = self.log_text.search(
                    pattern, start, nocase=True, stopindex="end", regexp=False
                )
                if not idx:
                    break
                end = f"{idx}+{len(term)}c"
                self.log_text.tag_add("match", idx, end)
                start = end

        # auto scroll
        self.log_text.see("end")
        self.log_text.configure(state="disabled")


    def _refresh_tick(self):
        if self.auto_refresh.get():
            self.refresh()
            self._update_node_table()
        self.root.after(800, self._refresh_tick)

    def _start_refresh_loop(self):
        self.root.after(800, self._refresh_tick)

    # commands
    def _send_command(self):
        raw = self.footer_box.get("1.0", "end-1c").strip()
        if not raw:
            return
        self.footer_box.delete("1.0", "end")

        for line in [ln.strip() for ln in raw.splitlines() if ln.strip()]:
            buf = io.StringIO()
            old = sys.stdout
            try:
                sys.stdout = buf
                try:
                    self.controller.process_command(line)
                except Exception as e:
                    print(f"[GUI] Error: {e}")
            finally:
                sys.stdout = old
            out = buf.getvalue().strip()
            ts = datetime.now().strftime(TS_FMT)
            self.command_entries.append((ts, f"[CMD] {line}"))
            if out:
                for ol in out.splitlines():
                    self.command_entries.append((ts, f"[CMD-OUT] {ol}"))
        self.refresh()

    def run(self):
        self.refresh()
        self._update_node_table()
        self.root.mainloop()


# just for testing
if __name__ == "__main__":
    class DummyNode:
        def __init__(self, name):
            self.name = name
            self.logs = []
            self.fib = {}
            self.cs = {}
            self.pit = {}
            self.neighbor_table = {}
            self.buffer = []

        def add(self, msg, ts):
            self.logs.append({"timestamp": ts, "message": msg})

    class DummyController:
        def __init__(self, nodes):
            self.nodes = {n.name: n for n in nodes}

    a = DummyNode("/DLSU/Andrew")
    g = DummyNode("/DLSU/Gokongwei")
    r = DummyNode("/DLSU/Router1 /ADMU/Router1")
    a.add("Sent INTEREST to 5003", "2025-10-19 23:11:19.000000")
    g.add(
        "Added /DLSU/Gokongwei/hello.txt to PIT with interfaces: [5002]",
        "2025-10-19 23:11:20.100000",
    )
    g.add(
        "Data found in CS for /DLSU/Gokongwei/hello.txt, sending DATA back to ('127.0.0.1', 5002)",
        "2025-10-19 23:11:20.300000",
    )
    r.add("Forwarded ROUTING_DATA to PIT port 5002", "2025-10-19 23:11:20.400000")

    a.fib["/DLSU/Andrew/PC1"] = {
        "NextHops": 5001,
        "HopCount": 1,
        "ExpirationTime": 5000,
    }
    a.cs["/DLSU/Andrew/data.txt"] = "Sample payload for Andrew"
    a.pit["/DLSU/Andrew/request.txt"] = [5002, 5003]
    a.neighbor_table["/DLSU/Gokongwei"] = "2025-10-19 23:11:18.000000"
    a.buffer.append({
        "packet": b"\x10\x01...",
        "source": "/DLSU/Andrew",
        "destination": "/UP/Salcedo/PC1/status.txt",
        "status": "waiting",
        "timestamp": "2025-10-19 23:11:25.000000",
        "hop_history": [5002, 5005],
        "reason": "No FIB route available",
        "next_hop": "",
        "forwarded_to_ns": False,
    })

    ctrl = DummyController([a, g, r])
    LogGUI(ctrl).run()
