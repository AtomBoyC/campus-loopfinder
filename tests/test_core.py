"""Unit and integration tests for LoopFinder core engines and HTTP API."""

from __future__ import annotations

import http.client
import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest

from loopfinder.core.capture import CaptureController
from loopfinder.core.console_inspector import (
    compute_counter_deltas,
    inspect_switch_console,
    list_serial_ports,
    parse_counters_table,
    parse_lldp_brief,
    parse_single_huawei_interface_bcast,
)
from loopfinder.core.inventory import SwitchInventory
from loopfinder.core.l3_tracer import parse_traceroute_output, run_l3_loop_trace
from loopfinder.core.ledger import PortLedger, normalize_port_name
from loopfinder.core.packet_parser import (
    PROBE_ETHERTYPE,
    build_dhcp_discover_frame,
    build_loop_probe_frame,
    parse_ethernet_frame,
)
from loopfinder.core.pcap_writer import build_pcap_bytes
from loopfinder.core.simulator import _build_sim_arp_frame, _build_sim_dhcp_offer, _build_sim_lldp_frame
from loopfinder.core.snmp import (
    PDU_RESPONSE,
    TAG_INTEGER,
    TAG_SEQUENCE,
    SnmpV2Client,
    _decode_tlv,
    _encode_tlv,
    batch_scan_switches,
    encode_integer,
    encode_octet_string,
    encode_oid,
    lookup_mac_in_scan,
    scan_switch_snmp,
    trace_loop_hops,
)
from loopfinder.core.cli_parser import SAMPLE_CLI_OUTPUT, parse_switch_cli_output
from loopfinder.core.syslog_listener import SyslogRadar
from loopfinder.data.oui_vendors import lookup_mac_vendor, normalize_mac
from loopfinder.web.server import AppContext, create_server


class TestPacketParser(unittest.TestCase):
    def test_loop_probe_roundtrip(self) -> None:
        frame = build_loop_probe_frame("02:4C:4F:4F:50:0A", session_id=424242, seq=7)
        self.assertGreaterEqual(len(frame), 60)
        pkt = parse_ethernet_frame(frame)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertEqual(pkt["ethertype"], PROBE_ETHERTYPE)
        self.assertEqual(pkt["proto"], "LOOP_PROBE")
        self.assertTrue(pkt["is_broadcast"])
        self.assertEqual(pkt["src_mac"], "02:4C:4F:4F:50:0A")
        self.assertEqual(pkt["probe"]["session_id"], 424242)
        self.assertEqual(pkt["probe"]["seq"], 7)

    def test_vlan_tagged_frame_parsing(self) -> None:
        raw_arp = _build_sim_arp_frame("D8:0D:17:6A:3B:9C", "192.168.1.1", "192.168.1.1")
        # Insert 802.1Q tag (VLAN 20) after 12-byte MAC header
        vlan_tagged = raw_arp[:12] + struct.pack("!HH", 0x8100, 20) + raw_arp[12:]
        pkt = parse_ethernet_frame(vlan_tagged)
        self.assertIsNotNone(pkt)
        assert pkt is not None
        self.assertEqual(pkt["vlan_id"], 20)
        self.assertEqual(pkt["proto"], "ARP")
        self.assertEqual(pkt["arp"]["sender_ip"], "192.168.1.1")
        self.assertTrue(pkt["arp"]["gratuitous"])

    def test_lldp_and_dhcp_parsing(self) -> None:
        lldp = _build_sim_lldp_frame(
            "54:89:98:AA:12:34", "GigabitEthernet0/0/14", "HW-3F-SW", "Huawei S5735", "10.10.2.12", 20
        )
        pkt = parse_ethernet_frame(lldp)
        assert pkt is not None
        self.assertEqual(pkt["proto"], "LLDP")
        self.assertEqual(pkt["neighbor"]["sys_name"], "HW-3F-SW")
        self.assertEqual(pkt["neighbor"]["port_id"], "GigabitEthernet0/0/14")
        self.assertEqual(pkt["neighbor"]["mgmt_ip"], "10.10.2.12")
        self.assertEqual(pkt["neighbor"]["vlan_id"], 20)

        offer = _build_sim_dhcp_offer("D8:0D:17:6A:3B:9C", "192.168.1.1", "192.168.1.105", "192.168.1.1")
        dpkt = parse_ethernet_frame(offer)
        assert dpkt is not None
        self.assertEqual(dpkt["proto"], "DHCP")
        self.assertEqual(dpkt["dhcp"]["msg_name"], "OFFER")
        self.assertEqual(dpkt["dhcp"]["server_ip"], "192.168.1.1")
        self.assertEqual(dpkt["dhcp"]["offered_ip"], "192.168.1.105")

        disc = build_dhcp_discover_frame("AA:BB:CC:DD:EE:FF", 0xABCDEF01)
        disc_pkt = parse_ethernet_frame(disc)
        assert disc_pkt is not None
        self.assertEqual(disc_pkt["proto"], "DHCP")
        self.assertEqual(disc_pkt["dhcp"]["msg_name"], "DISCOVER")
        self.assertEqual(disc_pkt["dhcp"]["xid"], 0xABCDEF01)


class TestOuiAndLedger(unittest.TestCase):
    def test_oui_vendor_lookup(self) -> None:
        self.assertEqual(normalize_mac("d80d-176a-3b9c"), "D8:0D:17:6A:3B:9C")
        v = lookup_mac_vendor("d80d.176a.3b9c")
        self.assertIn("TP-LINK", v["vendor"])
        self.assertEqual(v["category"], "soho_router")

        sw = lookup_mac_vendor("54:89:98:11:22:33")
        self.assertIn("Huawei", sw["vendor"])
        self.assertEqual(sw["category"], "switch")

    def test_ledger_port_normalization_and_csv(self) -> None:
        self.assertEqual(normalize_port_name("GigabitEthernet0/0/14"), "ge0/0/14")
        self.assertEqual(normalize_port_name("GE0/0/14"), "ge0/0/14")
        self.assertEqual(normalize_port_name("Gi0/0/14"), "ge0/0/14")

        with tempfile.TemporaryDirectory() as d:
            ledger = PortLedger(storage_path=os.path.join(d, "ledger.json"))
            ledger.upsert({
                "switch_ip": "10.10.9.9",
                "port": "GigabitEthernet0/0/7",
                "building": "综合楼",
                "room": "401教研室",
                "wall_jack": "西墙2号口",
                "note": "测试",
            })
            loc = ledger.format_location("10.10.9.9", "GE0/0/7")
            self.assertIn("401教研室", loc)
            self.assertIn("西墙2号口", loc)

            csv_out = ledger.export_csv_text()
            self.assertIn("401教研室", csv_out)


class TestSnmpBerAndMockSwitch(unittest.TestCase):
    def test_ber_roundtrip_and_udp_get(self) -> None:
        encoded = encode_oid("1.3.6.1.2.1.1.5.0")
        tag, val, _ = _decode_tlv(encoded, 0)
        self.assertEqual(val, "1.3.6.1.2.1.1.5.0")

        for num in (0, 1, 127, 128, 65535, 12345678, -1, -300):
            t, v, _ = _decode_tlv(encode_integer(num), 0)
            self.assertEqual(t, TAG_INTEGER)
            self.assertEqual(v, num)

        # Verify full SNMPv2c Response PDU encoding & decoding in memory
        req_id = 98765
        vb = _encode_tlv(
            TAG_SEQUENCE,
            encode_oid("1.3.6.1.2.1.1.5.0") + encode_octet_string(b"TEST-SW-01"),
        )
        pdu = _encode_tlv(
            PDU_RESPONSE,
            encode_integer(req_id) + encode_integer(0) + encode_integer(0) + _encode_tlv(TAG_SEQUENCE, vb),
        )
        msg = _encode_tlv(
            TAG_SEQUENCE,
            encode_integer(1) + encode_octet_string(b"public") + pdu,
        )
        _, top, _ = _decode_tlv(msg, 0)
        self.assertEqual(top[0][1], 1)
        self.assertEqual(top[1][1], b"public")
        pdu_items = top[2][1]
        self.assertEqual(pdu_items[0][1], req_id)
        vb_pair = pdu_items[3][1][0][1]
        self.assertEqual(vb_pair[0][1], "1.3.6.1.2.1.1.5.0")
        self.assertEqual(vb_pair[1][1], b"TEST-SW-01")

        # Also verify live UDP loopback exchange when host environment permits UDP sockets
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]

        def responder() -> None:
            srv.settimeout(1.5)
            try:
                req, addr = srv.recvfrom(4096)
                _, rtop, _ = _decode_tlv(req, 0)
                rid = rtop[2][1][0][1]
                rpdu = _encode_tlv(
                    PDU_RESPONSE,
                    encode_integer(rid) + encode_integer(0) + encode_integer(0) + _encode_tlv(TAG_SEQUENCE, vb),
                )
                rmsg = _encode_tlv(
                    TAG_SEQUENCE,
                    encode_integer(1) + encode_octet_string(b"public") + rpdu,
                )
                srv.sendto(rmsg, addr)
            except OSError:
                pass
            finally:
                srv.close()

        t_srv = threading.Thread(target=responder, daemon=True)
        t_srv.start()
        client = SnmpV2Client("127.0.0.1", community="public", port=port, timeout=0.6, retries=0)
        try:
            res = client.get(["1.3.6.1.2.1.1.5.0"])
            self.assertEqual(res.get("1.3.6.1.2.1.1.5.0"), b"TEST-SW-01")
        except TimeoutError as e:
            if "Operation not permitted" not in str(e):
                raise

    def test_simulated_snmp_and_mac_lookup(self) -> None:
        scan = scan_switch_snmp("10.10.1.1", simulate=True)
        self.assertEqual(scan["sys_name"], "H3C-3F-Agg-SW01")
        self.assertGreater(len(scan["suspect_ports"]), 0)
        self.assertGreater(len(scan["mac_flaps"]), 0)

        hit = lookup_mac_in_scan(scan, "d8-0d-17-6a-3b-9c")
        self.assertTrue(hit["found"])
        self.assertEqual(hit["port"], "GigabitEthernet1/0/14")
        self.assertEqual(hit["lldp_neighbor"]["remote_ip"], "10.10.2.12")


class TestCliParser(unittest.TestCase):
    def test_parse_multi_vendor_cli(self) -> None:
        ledger = PortLedger()
        parsed = parse_switch_cli_output(SAMPLE_CLI_OUTPUT, switch_ip="10.10.2.12", ledger=ledger)
        self.assertGreaterEqual(parsed["finding_count"], 3)
        ports = {p["port"] for p in parsed["affected_ports"]}
        self.assertTrue(any("0/0/14" in p for p in ports))
        macs = {m["mac"] for m in parsed["involved_macs"]}
        self.assertIn("D8:0D:17:6A:3B:9C", macs)

        cisco_log = "%SW_MATM-4-MACFLAP_NOTIF: Host d80d.176a.3b9c in vlan 20 is flapping between port Gi1/0/14 and port Gi1/0/15"
        c_parsed = parse_switch_cli_output(cisco_log)
        self.assertEqual(c_parsed["finding_count"], 1)
        self.assertEqual(c_parsed["findings"][0]["type"], "MAC_FLAP")


class TestSimulationAndHttpApi(unittest.TestCase):
    def test_capture_controller_simulation_lifecycle(self) -> None:
        ledger = PortLedger()
        ctrl = CaptureController(ledger)
        try:
            res = ctrl.start(interface="__SIMULATION__", mode="active", backend="simulation")
            self.assertTrue(res["ok"])
            time.sleep(1.4)

            snap = ctrl.get_snapshot()
            self.assertEqual(snap["status"], "LOOP_DETECTED")
            self.assertGreaterEqual(snap["loop_confidence"], 60)
            self.assertIsNotNone(snap["upstream_switch"])
            self.assertEqual(snap["upstream_switch"]["sys_name"], "HW-3F-East-SW02")
            self.assertTrue(any(s["is_rogue"] for s in snap["dhcp_servers"]))
            self.assertGreater(len(snap["dup_clusters"]), 0)

            # Simulate unplugging the looped branch -> verify storm drops & recovery triggers!
            ctrl.set_simulation_state(loop_active=False)
            time.sleep(1.3)
            snap2 = ctrl.get_snapshot()
            self.assertNotEqual(snap2["status"], "LOOP_DETECTED")
            self.assertTrue(snap2["just_recovered"])
        finally:
            ctrl.stop()

    def test_end_to_end_http_api(self) -> None:
        server, ctx = create_server(host="127.0.0.1", port=0)
        port = server.server_address[1]
        th = threading.Thread(target=server.serve_forever, daemon=True)
        th.start()

        def http_req(method: str, path: str, data: dict | None = None) -> tuple[int, str]:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                body = json.dumps(data).encode("utf-8") if data is not None else None
                headers = {"Content-Type": "application/json"} if data is not None else {}
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                return resp.status, resp.read().decode("utf-8")
            finally:
                conn.close()

        try:
            # Always verify report generator & context directly in-process
            snmp_sim = scan_switch_snmp("10.10.1.1", simulate=True, ledger=ctx.ledger)
            ctx.save_snmp_scan(snmp_sim)
            self.assertEqual(len(ctx.get_snmp_history()), 1)
            report_inproc = ctx.build_html_report()
            self.assertIn("故障排查工单报告", report_inproc)
            self.assertIn("H3C-3F-Agg-SW01", report_inproc)

            # Verify live HTTP routes when loopback TCP connect is permitted
            try:
                code, raw = http_req("GET", "/api/system")
            except PermissionError:
                return

            self.assertEqual(code, 200)
            sys_info = json.loads(raw)
            self.assertIn("capabilities", sys_info)

            code, html = http_req("GET", "/")
            self.assertEqual(code, 200)
            self.assertIn("LoopFinder", html)

            code, raw = http_req("POST", "/api/capture/start", {"interface": "__SIMULATION__", "mode": "active", "backend": "simulation"})
            self.assertEqual(code, 200)
            self.assertTrue(json.loads(raw)["ok"])
            time.sleep(1.0)

            code, raw = http_req("GET", "/api/state")
            self.assertEqual(code, 200)
            snap = json.loads(raw)
            self.assertEqual(snap["status"], "LOOP_DETECTED")

            code, report_html = http_req("GET", "/api/report")
            self.assertEqual(code, 200)
            self.assertIn("故障排查工单报告", report_html)
        finally:
            ctx.capture.stop()
            ctx.syslog.stop()
            server.shutdown()
            server.server_close()


class TestV2Enhancements(unittest.TestCase):
    def test_pcap_writer_valid_libpcap_format(self) -> None:
        f1 = build_loop_probe_frame("02:4C:4F:4F:50:01", 12345, 1)
        f2 = _build_sim_arp_frame("D8:0D:17:6A:3B:9C", "192.168.1.1", "192.168.1.1")
        raw_pcap = build_pcap_bytes([(1700000000.125, f1), (1700000001.5, f2)])
        magic, vmaj, vmin, _, _, snaplen, linktype = struct.unpack_from("<IHHiIII", raw_pcap, 0)
        self.assertEqual(magic, 0xA1B2C3D4)
        self.assertEqual((vmaj, vmin, linktype), (2, 4, 1))
        self.assertEqual(snaplen, 65535)
        sec1, usec1, cap1, orig1 = struct.unpack_from("<IIII", raw_pcap, 24)
        self.assertEqual(sec1, 1700000000)
        self.assertAlmostEqual(usec1, 125000, delta=2)
        self.assertEqual(cap1, len(f1))
        parsed1 = parse_ethernet_frame(raw_pcap[40 : 40 + cap1])
        assert parsed1 is not None
        self.assertEqual(parsed1["proto"], "LOOP_PROBE")

    def test_arp_conflict_passive_soho_and_pcap_ring(self) -> None:
        ctrl = CaptureController(PortLedger())
        now = time.time()
        # Inject conflicting ARP frames for gateway 10.10.20.1
        ctrl._ingest_raw_frame(_build_sim_arp_frame("00:23:89:01:02:03", "10.10.20.1", "10.10.20.5"), now)
        ctrl._ingest_raw_frame(_build_sim_arp_frame("D8:0D:17:6A:3B:9C", "10.10.20.1", "10.10.20.5"), now + 0.1)
        # Inject passive ARP from Xiaomi SOHO router on 192.168.31.1 (no DHCP offer needed!)
        ctrl._ingest_raw_frame(_build_sim_arp_frame("64:09:80:AA:BB:CC", "192.168.31.1", "192.168.31.1"), now + 0.2)
        ctrl.set_sensitivity("strict")

        snap = ctrl.get_snapshot()
        self.assertEqual(snap["sensitivity"], "strict")
        self.assertEqual(snap["pcap_count"], 3)
        self.assertEqual(len(snap["arp_conflicts"]), 1)
        self.assertEqual(snap["arp_conflicts"][0]["ip"], "10.10.20.1")
        self.assertTrue(snap["arp_conflicts"][0]["is_gateway"])
        self.assertTrue(any(s["server_ip"] == "192.168.31.1" and s["is_rogue"] for s in snap["dhcp_servers"]))
        pcap_bytes = ctrl.export_pcap_bytes()
        self.assertGreater(len(pcap_bytes), 200)

    def test_inventory_batch_scan_and_3hop_trace(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            inv = SwitchInventory(storage_path=os.path.join(d, "sw.json"))
            # Starts clean on first launch (no fake switches polluting user's real table)
            self.assertEqual(len(inv.list_switches()), 0)
            inv.load_sample()
            self.assertGreaterEqual(len(inv.list_switches()), 4)
            inv.upsert({"ip": "10.10.9.1", "name": "TEST-SW", "building": "测试楼", "community": "ro_key", "snmp_version": "1"})
            self.assertIsNotNone(inv.get_by_ip("10.10.9.1"))
            self.assertIn("TEST-SW", inv.export_csv_text())
            inv.delete("10.10.9.1")

            ledger = PortLedger(storage_path=os.path.join(d, "empty_ledger.json"))
            self.assertEqual(len(ledger.list_entries()), 0)
            bldg_sws = inv.list_switches(building="第一教学楼")
            batch = batch_scan_switches(bldg_sws, ledger, simulate=True)
            self.assertTrue(batch["ok"])
            self.assertEqual(batch["scanned_count"], 3)
            # Hottest switch should rank before healthy Ruijie switch
            self.assertGreater(batch["switches"][0]["max_risk"], 60)
            self.assertEqual(batch["switches"][-1]["switch_ip"], "10.10.2.13")

            # 3-hop automatic drill-down: Core 10.10.0.1 -> Agg 10.10.1.1 -> Access 10.10.2.12 (GE0/0/14)
            # Even with empty user ledger, simulation mode resolves demo room names cleanly!
            trace = trace_loop_hops("10.10.0.1", ledger=ledger, inventory=inv, simulate=True)
            self.assertTrue(trace["ok"])
            self.assertEqual(len(trace["hops"]), 3)
            self.assertEqual([h["switch_ip"] for h in trace["hops"]], ["10.10.0.1", "10.10.1.1", "10.10.2.12"])
            self.assertEqual(trace["hops"][-1]["port"], "GigabitEthernet0/0/14")
            self.assertIn("302大教研室", trace["hops"][-1]["location"])

            # Explicit sample loading works for Ledger too
            loaded = ledger.load_sample(persist=True)
            self.assertGreaterEqual(loaded, 8)

            # Target-MAC 3-hop trace
            mac_trace = trace_loop_hops("10.10.0.1", ledger=ledger, inventory=inv, target_mac="d80d-176a-3b9c", simulate=True)
            self.assertEqual(len(mac_trace["hops"]), 3)
            self.assertEqual(mac_trace["hops"][-1]["port"], "GigabitEthernet0/0/14")

    def test_syslog_radar_l3_tracer_and_html_report(self) -> None:
        ctx = AppContext()
        demo = ctx.syslog.inject_demo_alert()
        self.assertTrue(demo["ok"])
        st = ctx.syslog.get_state()
        self.assertGreaterEqual(st["alert_count"], 2)
        self.assertTrue(any("302大教研室" in a["location"] for a in st["alerts"]))

        # L3 routing loop detection (simulated cycle + clean path)
        l3_loop = run_l3_loop_trace("10.20.1.1", simulate=True)
        self.assertTrue(l3_loop["ok"])
        self.assertTrue(l3_loop["has_loop"])
        self.assertIn("10.10.1.1", l3_loop["loop_ips"])
        self.assertIn("10.10.0.1", l3_loop["loop_ips"])
        ctx.last_l3_trace = l3_loop

        clean = parse_traceroute_output(" 1 10.10.20.1 1.0 ms\n 2 10.10.1.1 2.0 ms\n 3 223.5.5.5 9.0 ms", "223.5.5.5")
        self.assertFalse(clean["has_loop"])

        # Unified HTML report must carry everything the removed Markdown report had
        ctx.save_snmp_scan(scan_switch_snmp("10.10.1.1", simulate=True, ledger=ctx.ledger))
        ctx.last_console_result = inspect_switch_console("__SIM_CONSOLE__", switch_ip="10.10.1.1", simulate=True, ledger=ctx.ledger)
        html_doc = ctx.build_html_report()
        self.assertIn("<!DOCTYPE html>", html_doc)
        self.assertIn("H3C-3F-Agg-SW01", html_doc)
        self.assertIn("实时 Syslog 交换机告警", html_doc)
        self.assertIn("三层路由环路探测", html_doc)
        self.assertIn("Console 串口直连定位", html_doc)
        self.assertIn("漂移 MAC", html_doc)
        self.assertNotIn("<script", html_doc.split("<body>")[1].replace("window.print()", ""))

    def test_console_inspector_parsers_and_simulation(self) -> None:
        # 1. Serial port listing returns a valid list on any OS
        ports = list_serial_ports()
        self.assertIsInstance(ports, list)

        # 2. Huawei brief utilization & single-interface broadcast parser
        hw_brief = """
        Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors
        GigabitEthernet0/0/1        up    up        0.04% 72.10%          0          0
        GigabitEthernet0/0/14       up    up       84.50% 15.20%         12          0
        """
        parsed_hw = parse_counters_table(hw_brief)
        self.assertAlmostEqual(parsed_hw["GigabitEthernet0/0/14"]["in_uti_pct"], 84.5)
        self.assertAlmostEqual(parsed_hw["GigabitEthernet0/0/1"]["out_uti_pct"], 72.1)

        hw_single = """
        GigabitEthernet0/0/14 current state : UP
        Last 300 seconds input rate 85000000 bits/sec, 9800 packets/sec
        Input:  99123456 packets, 10200300 bytes
          Unicast: 12000, Multicast: 45000, Broadcast: 8812345
        Output: 1200345 packets, 900123 bytes
          Unicast: 11000, Multicast: 2000, Broadcast: 99123
        """
        in_b, out_b = parse_single_huawei_interface_bcast(hw_single)
        self.assertEqual(in_b, 8812345)
        self.assertEqual(out_b, 99123)

        # 3. Cisco & Ruijie counter table parsers
        cisco_txt = """
        Port            Broadcast   Multicast
        Gi1/0/1              100         20
        Gi1/0/14           50000        400
        """
        c_parsed = parse_counters_table(cisco_txt)
        self.assertEqual(c_parsed["Gi1/0/14"]["broadcast"], 50000)

        ruijie_txt = """
        Interface              InOctets        InUcastPkts     InMcastPkts     InBcastPkts
        GigabitEthernet0/14    99482110        410200          412000          18429100
        """
        r_parsed = parse_counters_table(ruijie_txt)
        self.assertEqual(r_parsed["GigabitEthernet0/14"]["broadcast"], 18429100)

        # 4. LLDP brief parser
        lldp_out = "GE1/0/14  HW-3F-East-SW02  GE0/0/24\n"
        lldp = parse_lldp_brief(lldp_out)
        self.assertEqual(lldp["GE1/0/14"]["remote_sys"], "HW-3F-East-SW02")

        # 5. End-to-end simulated Console 2-pass inspection
        res = inspect_switch_console("__SIM_CONSOLE__", switch_ip="10.10.1.1", simulate=True, ledger=PortLedger())
        self.assertTrue(res["ok"])
        self.assertEqual(res["ranked_ports"][0]["port"], "GE1/0/14")
        self.assertGreater(res["ranked_ports"][0]["in_broadcast_pps"], 5000)
        self.assertIn("源头", res["ranked_ports"][0]["direction"])
        self.assertEqual(res["ranked_ports"][0]["lldp_neighbor"]["remote_sys"], "HW-3F-East-SW02")

        # 6. SNMP scan includes In/Out broadcast direction verdict
        snmp_res = scan_switch_snmp("10.10.1.1", simulate=True)
        p14 = next(p for p in snmp_res["ports"] if p["name"] == "GigabitEthernet1/0/14")
        p2 = next(p for p in snmp_res["ports"] if p["name"] == "GigabitEthernet1/0/2")
        self.assertIn("源头", p14["broadcast_direction"])
        self.assertIn("受害转发口", p2["broadcast_direction"])


class TestAuditRegressions(unittest.TestCase):
    """Regression tests for the bugs found during the v2.2 audit."""

    def test_cisco_dual_in_out_table_does_not_overwrite_inbound(self) -> None:
        cisco_real = """
Port            InOctets    InUcastPkts    InMcastPkts    InBcastPkts
Gi1/0/1         1000000          5000            100            200
Gi1/0/14       99000000          8000          40000        9000000

Port           OutOctets   OutUcastPkts   OutMcastPkts   OutBcastPkts
Gi1/0/1       88000000          4000          30000        7000000
Gi1/0/14        500000           100             10             20
"""
        r = parse_counters_table(cisco_real)
        self.assertEqual(r["Gi1/0/14"]["broadcast"], 9000000)
        self.assertEqual(r["Gi1/0/1"]["broadcast"], 200)

        # End-to-end: the source port must rank first, the victim port must not
        r2 = parse_counters_table(cisco_real.replace("9000000", "9030000").replace("        200\n", "        206\n"))
        ranked = compute_counter_deltas(r, r2, 3.0, {}, set(), "", PortLedger())
        self.assertEqual(ranked[0]["port"], "Gi1/0/14")
        self.assertIn("源头", ranked[0]["direction"])

    def test_ruijie_block_format_counters(self) -> None:
        ruijie_block = """
Interface : GigabitEthernet 0/14
  InOctets          : 99482110
  InUcastPkts       : 410200
  InMulticastPkts   : 412000
  InBroadcastPkts   : 18429100
  OutBroadcastPkts  : 77
Interface : GigabitEthernet 0/1
  InOctets          : 1000
  InUcastPkts       : 10
  InMulticastPkts   : 2
  InBroadcastPkts   : 3
"""
        r = parse_counters_table(ruijie_block)
        self.assertEqual(set(r.keys()), {"GigabitEthernet0/14", "GigabitEthernet0/1"})
        self.assertEqual(r["GigabitEthernet0/14"]["broadcast"], 18429100)
        self.assertEqual(r["GigabitEthernet0/14"]["multicast"], 412000)
        self.assertEqual(r["GigabitEthernet0/1"]["broadcast"], 3)

    def test_user_data_stored_outside_code_dir_with_legacy_migration(self) -> None:
        from loopfinder.core import paths

        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("LOOPFINDER_DATA_DIR")
            os.environ["LOOPFINDER_DATA_DIR"] = os.path.join(d, "lfdata")
            try:
                ledger = PortLedger()
                pkg_dir = os.path.dirname(os.path.dirname(os.path.abspath(paths.__file__)))
                self.assertFalse(ledger.storage_path.startswith(pkg_dir))
                ledger.upsert({"switch_ip": "10.9.9.9", "port": "GE0/0/1", "room": "测试室"})
                self.assertTrue(os.path.isfile(os.path.join(d, "lfdata", "campus_ledger.json")))
                self.assertIn("测试室", PortLedger().format_location("10.9.9.9", "GigabitEthernet0/0/1"))

                inv = SwitchInventory()
                inv.upsert({"ip": "10.9.9.1", "name": "X"})
                self.assertTrue(os.path.isfile(os.path.join(d, "lfdata", "campus_switches.json")))
                self.assertTrue(os.path.isfile(paths.resource_path("loopfinder", "web", "static", "index.html")))
            finally:
                if old is None:
                    os.environ.pop("LOOPFINDER_DATA_DIR", None)
                else:
                    os.environ["LOOPFINDER_DATA_DIR"] = old

    def test_api_rejects_cross_site_and_dns_rebinding_requests(self) -> None:
        server, ctx = create_server(host="127.0.0.1", port=0)
        try:
            handler_cls = server.RequestHandlerClass
            h = handler_cls.__new__(handler_cls)

            h.headers = {"Host": "127.0.0.1:18765", "Content-Type": "application/json"}
            self.assertTrue(h._is_trusted_request(is_post=True))

            h.headers = {"Host": "localhost:18765", "Origin": "http://localhost:18765", "Content-Type": "application/json"}
            self.assertTrue(h._is_trusted_request(is_post=True))

            # Simple cross-site form/text POST (no preflight) must be refused
            h.headers = {"Host": "127.0.0.1:18765", "Content-Type": "text/plain"}
            self.assertFalse(h._is_trusted_request(is_post=True))

            # Foreign origin
            h.headers = {"Host": "127.0.0.1:18765", "Origin": "https://evil.example", "Content-Type": "application/json"}
            self.assertFalse(h._is_trusted_request(is_post=True))

            # DNS rebinding: attacker hostname resolving to 127.0.0.1
            h.headers = {"Host": "evil.example:18765"}
            self.assertFalse(h._is_trusted_request(is_post=False))
        finally:
            server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
