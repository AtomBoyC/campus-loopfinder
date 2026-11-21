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
from loopfinder.core.ssh_inspector import (
    SAMPLE_CLI_OUTPUT,
    generate_hardening_config,
    parse_switch_cli_output,
)
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


class TestSshParser(unittest.TestCase):
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
            report_inproc = ctx.build_markdown_report()
            self.assertIn("现场环路排查报告", report_inproc)
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

            code, report_md = http_req("GET", "/api/report?format=md")
            self.assertEqual(code, 200)
            self.assertIn("现场环路排查报告", report_md)
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
            self.assertGreaterEqual(len(inv.list_switches()), 4)
            inv.upsert({"ip": "10.10.9.1", "name": "TEST-SW", "building": "测试楼", "community": "ro_key", "snmp_version": "1"})
            self.assertIsNotNone(inv.get_by_ip("10.10.9.1"))
            self.assertIn("TEST-SW", inv.export_csv_text())
            inv.delete("10.10.9.1")

            ledger = PortLedger()
            bldg_sws = inv.list_switches(building="第一教学楼")
            batch = batch_scan_switches(bldg_sws, ledger, simulate=True)
            self.assertTrue(batch["ok"])
            self.assertEqual(batch["scanned_count"], 3)
            # Hottest switch should rank before healthy Ruijie switch
            self.assertGreater(batch["switches"][0]["max_risk"], 60)
            self.assertEqual(batch["switches"][-1]["switch_ip"], "10.10.2.13")

            # 3-hop automatic drill-down: Core 10.10.0.1 -> Agg 10.10.1.1 -> Access 10.10.2.12 (GE0/0/14)
            trace = trace_loop_hops("10.10.0.1", ledger=ledger, inventory=inv, simulate=True)
            self.assertTrue(trace["ok"])
            self.assertEqual(len(trace["hops"]), 3)
            self.assertEqual([h["switch_ip"] for h in trace["hops"]], ["10.10.0.1", "10.10.1.1", "10.10.2.12"])
            self.assertEqual(trace["hops"][-1]["port"], "GigabitEthernet0/0/14")
            self.assertIn("302大教研室", trace["hops"][-1]["location"])

            # Target-MAC 3-hop trace
            mac_trace = trace_loop_hops("10.10.0.1", ledger=ledger, inventory=inv, target_mac="d80d-176a-3b9c", simulate=True)
            self.assertEqual(len(mac_trace["hops"]), 3)
            self.assertEqual(mac_trace["hops"][-1]["port"], "GigabitEthernet0/0/14")

    def test_syslog_radar_l3_tracer_hardening_and_html_report(self) -> None:
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

        clean = parse_traceroute_output(" 1 10.10.20.1 1.0 ms\n 2 10.10.1.1 2.0 ms\n 3 223.5.5.5 9.0 ms", "223.5.5.5")
        self.assertFalse(clean["has_loop"])

        # Hardening config generator across all 5 vendors
        for v in ("huawei", "h3c", "ruijie", "cisco", "tplink"):
            cfg = generate_hardening_config(v, port_start=1, port_end=20, syslog_host="10.10.20.88")
            self.assertIn("dhcp snooping", cfg["config"].lower())

        # HTML & Markdown reports
        ctx.save_snmp_scan(scan_switch_snmp("10.10.1.1", simulate=True, ledger=ctx.ledger))
        html_doc = ctx.build_html_report()
        self.assertIn("<!DOCTYPE html>", html_doc)
        self.assertIn("H3C-3F-Agg-SW01", html_doc)
        md_doc = ctx.build_markdown_report()
        self.assertIn("实时 Syslog 交换机告警", md_doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
