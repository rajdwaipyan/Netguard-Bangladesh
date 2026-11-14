import subprocess
import threading
import unittest
from datetime import datetime
from queue import Queue
from types import SimpleNamespace
from unittest.mock import Mock, patch

from netguard_bangladesh import (
    OBSERVED_IN_ARP_CACHE,
    PREVIOUSLY_OBSERVED,
    STATUS_UNKNOWN,
    NetGuardBangladesh,
    NetworkAnalyzer,
)


class RuntimeProbeTests(unittest.TestCase):
    def setUp(self):
        self.app = NetGuardBangladesh.__new__(NetGuardBangladesh)

    def test_ping_router_parses_windows_response(self):
        completed = subprocess.CompletedProcess(
            args=["ping"],
            returncode=0,
            stdout="Reply from 192.168.1.1: bytes=32 time=4ms TTL=64",
            stderr="",
        )
        with patch("netguard_bangladesh.subprocess.run", return_value=completed):
            result = self.app.ping_router("192.168.1.1")
        self.assertEqual(result, {"success": True, "time": 4.0, "packet_loss": 0.0})

    def test_ping_router_parses_sub_millisecond_response(self):
        completed = subprocess.CompletedProcess(
            args=["ping"],
            returncode=0,
            stdout="Reply from 192.168.1.1: bytes=32 time<1ms TTL=64",
            stderr="",
        )
        with patch("netguard_bangladesh.subprocess.run", return_value=completed):
            result = self.app.ping_router("192.168.1.1")
        self.assertEqual(result["time"], 1.0)
        self.assertTrue(result["success"])

    def test_ping_router_rejects_invalid_address_without_running_command(self):
        with patch("netguard_bangladesh.subprocess.run") as run:
            result = self.app.ping_router("not-an-ip")
        self.assertFalse(result["success"])
        self.assertEqual(result["packet_loss"], 100.0)
        run.assert_not_called()

    def test_ping_router_handles_timeout(self):
        with patch(
            "netguard_bangladesh.subprocess.run",
            side_effect=subprocess.TimeoutExpired("ping", 3),
        ):
            result = self.app.ping_router("192.168.1.1")
        self.assertFalse(result["success"])
        self.assertEqual(result["packet_loss"], 100.0)

    def test_ping_router_handles_missing_executable(self):
        with patch(
            "netguard_bangladesh.subprocess.run",
            side_effect=FileNotFoundError("ping"),
        ):
            result = self.app.ping_router("192.168.1.1")
        self.assertFalse(result["success"])

    def test_ping_router_handles_failed_response(self):
        completed = subprocess.CompletedProcess(
            args=["ping"], returncode=1, stdout="Request timed out.", stderr=""
        )
        with patch("netguard_bangladesh.subprocess.run", return_value=completed):
            result = self.app.ping_router("192.168.1.1")
        self.assertFalse(result["success"])
        self.assertEqual(result["packet_loss"], 100.0)

    def test_ping_router_handles_malformed_success_output(self):
        completed = subprocess.CompletedProcess(
            args=["ping"], returncode=0, stdout="Reply received", stderr=""
        )
        with patch("netguard_bangladesh.subprocess.run", return_value=completed):
            result = self.app.ping_router("192.168.1.1")
        self.assertFalse(result["success"])

    def test_ping_router_handles_subprocess_error(self):
        with patch(
            "netguard_bangladesh.subprocess.run",
            side_effect=subprocess.SubprocessError("failed"),
        ):
            result = self.app.ping_router("192.168.1.1")
        self.assertFalse(result["success"])

    @patch("netguard_bangladesh.platform.system", return_value="Windows")
    @patch("netguard_bangladesh.subprocess.run")
    def test_discover_devices_reads_multiple_interfaces_and_entry_types(
        self, run, _system
    ):
        run.return_value = subprocess.CompletedProcess(
            args=["arp", "-a"],
            returncode=0,
            stdout=(
                "Interface: 192.168.1.5 --- 0x7\n"
                "  192.168.1.1     00-aa-bb-cc-dd-ee     dynamic\n"
                "  192.168.1.10    11-22-33-44-55-66     static\n"
                "Interface: 10.0.0.5 --- 0x8\n"
                "  10.0.0.1        aa-bb-cc-dd-ee-ff     dynamic\n"
            ),
            stderr="",
        )
        devices = self.app.discover_devices()
        self.assertEqual(len(devices), 3)
        self.assertEqual(devices[0]["interface"], "192.168.1.5")
        self.assertEqual(devices[2]["interface"], "10.0.0.5")
        self.assertTrue(all(d["observation_status"] == OBSERVED_IN_ARP_CACHE for d in devices))

    @patch("netguard_bangladesh.platform.system", return_value="Windows")
    @patch("netguard_bangladesh.subprocess.run")
    def test_discover_devices_handles_empty_table(self, run, _system):
        run.return_value = subprocess.CompletedProcess(
            args=["arp", "-a"], returncode=0, stdout="", stderr=""
        )
        self.assertEqual(self.app.discover_devices(), [])

    @patch("netguard_bangladesh.platform.system", return_value="Windows")
    @patch("netguard_bangladesh.subprocess.run")
    def test_discover_devices_skips_malformed_and_unsupported_entries(
        self, run, _system
    ):
        run.return_value = subprocess.CompletedProcess(
            args=["arp", "-a"],
            returncode=0,
            stdout=(
                "  invalid           not-a-mac             dynamic\n"
                "  192.168.1.2       00-aa-bb-cc-dd-ee     unsupported\n"
                "  192.168.1.3       00-aa-bb-cc-dd-ee\n"
            ),
            stderr="",
        )
        self.assertEqual(self.app.discover_devices(), [])

    @patch("netguard_bangladesh.platform.system", return_value="Windows")
    @patch("netguard_bangladesh.subprocess.run")
    def test_discover_devices_deduplicates_exact_entries(self, run, _system):
        output = "  192.168.1.2       00-aa-bb-cc-dd-ee     dynamic\n" * 2
        run.return_value = subprocess.CompletedProcess(
            args=["arp", "-a"], returncode=0, stdout=output, stderr=""
        )
        self.assertEqual(len(self.app.discover_devices()), 1)

    @patch("netguard_bangladesh.platform.system", return_value="Linux")
    def test_discover_devices_rejects_unsupported_platform(self, _system):
        with self.assertRaises(RuntimeError):
            self.app.discover_devices()


class DeviceObservationTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = NetworkAnalyzer.__new__(NetworkAnalyzer)
        self.analyzer.device_history = {}
        self.analyzer.save_data = Mock()

    def observation(self, ip="192.168.1.10", mac="00:aa:bb:cc:dd:ee"):
        return {
            "ip": ip,
            "mac": mac,
            "observation_source": "windows_arp_cache",
            "observation_collected_at": datetime.now().isoformat(),
            "interface": "192.168.1.5",
            "vendor": None,
            "observation_status": OBSERVED_IN_ARP_CACHE,
            "confidence_limitations": "ARP cache presence is not liveness evidence.",
        }

    def test_new_mapping_is_observed_not_confirmed_online(self):
        self.analyzer.update_device_history([self.observation()])
        record = self.analyzer.device_history["192.168.1.10"]
        self.assertEqual(record["observation_status"], OBSERVED_IN_ARP_CACHE)
        self.assertNotEqual(record["observation_status"], "ONLINE")
        self.assertEqual(record["observations"][0]["observation_source"], "windows_arp_cache")

    def test_existing_mapping_is_updated(self):
        self.analyzer.update_device_history([self.observation()])
        self.analyzer.update_device_history([self.observation()])
        record = self.analyzer.device_history["192.168.1.10"]
        self.assertEqual(record["appearance_count"], 2)
        self.assertEqual(record["mapping_changes"], [])

    def test_same_mac_at_new_ip_tracks_identity_history(self):
        mac = "00:aa:bb:cc:dd:ee"
        self.analyzer.update_device_history(
            [self.observation(ip="192.168.1.10", mac=mac)]
        )
        self.analyzer.update_device_history(
            [self.observation(ip="192.168.1.11", mac=mac)]
        )
        new_record = self.analyzer.device_history["192.168.1.11"]
        self.assertEqual(
            new_record["historical_ip_addresses"],
            ["192.168.1.10", "192.168.1.11"],
        )
        self.assertEqual(new_record["related_identity_ip"], "192.168.1.10")
        self.assertEqual(
            self.analyzer.device_history["192.168.1.10"]["identity_changes"][0][
                "classification"
            ],
            "IP_ADDRESS_CHANGED",
        )

    def test_changed_mapping_is_cautious_and_not_an_attack(self):
        self.analyzer.update_device_history([self.observation(mac="00:aa:bb:cc:dd:ee")])
        self.analyzer.update_device_history([self.observation(mac="11:22:33:44:55:66")])
        record = self.analyzer.device_history["192.168.1.10"]
        change = record["mapping_changes"][0]
        self.assertEqual(change["classification"], "ARP_MAPPING_CHANGED")
        self.assertEqual(change["severity"], "Informational")
        self.assertLess(change["confidence"], 0.5)
        self.assertNotIn("attacks", record)

    def test_conflicting_same_scan_is_not_confirmed_spoofing(self):
        self.analyzer.update_device_history([
            self.observation(mac="00:aa:bb:cc:dd:ee"),
            self.observation(mac="11:22:33:44:55:66"),
        ])
        change = self.analyzer.device_history["192.168.1.10"]["mapping_changes"][0]
        self.assertEqual(change["classification"], "CONFLICTING_ARP_RESPONSES")
        self.assertNotEqual(change["classification"], "POTENTIAL_ARP_SPOOFING")

    def test_duplicate_observation_is_counted(self):
        observation = self.observation()
        self.analyzer.update_device_history([observation, observation])
        self.assertEqual(
            self.analyzer.device_history["192.168.1.10"]["duplicate_observation_count"],
            1,
        )
        self.assertEqual(
            self.analyzer.device_history["192.168.1.10"]["anomalies"][0][
                "classification"
            ],
            "DUPLICATE_IP_OBSERVATION",
        )

    def test_missing_device_becomes_previously_observed(self):
        self.analyzer.update_device_history([self.observation()])
        self.analyzer.update_device_history([])
        self.assertEqual(
            self.analyzer.device_history["192.168.1.10"]["observation_status"],
            PREVIOUSLY_OBSERVED,
        )

    def test_unknown_status_is_preserved(self):
        observation = self.observation()
        observation["observation_status"] = STATUS_UNKNOWN
        self.analyzer.update_device_history([observation])
        self.assertEqual(
            self.analyzer.device_history["192.168.1.10"]["observation_status"],
            STATUS_UNKNOWN,
        )


class WorkerCommunicationTests(unittest.TestCase):
    def test_worker_can_publish_without_touching_tk(self):
        app = NetGuardBangladesh.__new__(NetGuardBangladesh)
        app.ui_queue = Queue()
        app.device_scan_stop_event = threading.Event()
        app.discover_devices = Mock(return_value=[])
        app.network_analyzer = Mock()
        app._device_scan_worker()
        self.assertEqual(app.ui_queue.get_nowait()[0], "devices")

    def test_worker_exception_is_published(self):
        app = NetGuardBangladesh.__new__(NetGuardBangladesh)
        app.ui_queue = Queue()
        app.device_scan_stop_event = threading.Event()
        app.discover_devices = Mock(side_effect=RuntimeError("probe failed"))
        app._device_scan_worker()
        event_type, message = app.ui_queue.get_nowait()
        self.assertEqual(event_type, "worker_error")
        self.assertIn("probe failed", message)

    def test_cancelled_worker_does_not_probe(self):
        app = NetGuardBangladesh.__new__(NetGuardBangladesh)
        app.ui_queue = Queue()
        app.device_scan_stop_event = threading.Event()
        app.device_scan_stop_event.set()
        app.discover_devices = Mock()
        app._device_scan_worker()
        app.discover_devices.assert_not_called()
        self.assertTrue(app.ui_queue.empty())

    def test_queue_polling_applies_results_on_main_thread(self):
        app = NetGuardBangladesh.__new__(NetGuardBangladesh)
        app.ui_queue = Queue()
        app.root = Mock()
        app.ping_status = Mock()
        app.packet_loss = Mock()
        app.router_status = Mock()
        app.status_indicator = Mock()
        app.log_text = Mock()
        app.ui_queue.put(("ping", {"success": True, "time": 4.0, "packet_loss": 0.0}))
        app.process_ui_queue()
        app.ping_status.set.assert_called_once_with("4.0 ms")
        app.root.after.assert_called_once()

    def test_firmware_worker_publishes_assessment_without_tk_access(self):
        from netguard_bangladesh import FirmwareIntelligenceEngine

        app = NetGuardBangladesh.__new__(NetGuardBangladesh)
        app.ui_queue = Queue()
        app.firmware_sync_stop_event = threading.Event()
        app.firmware_source_client = Mock()
        app.firmware_source_client.fetch_nvd_cves.return_value = []
        app.firmware_source_client.fetch_kev.return_value = {
            "catalog_version": "1", "vulnerabilities": []
        }
        product = {
            "router_id": "router-1", "manufacturer": "tp-link",
            "model": "Archer C7", "firmware_version": "1.0",
            "verification_status": "USER_CONFIRMED",
        }
        analyzer = SimpleNamespace(
            firmware_products=[product],
            nvd_records=[],
            cisa_kev={"vulnerabilities": []},
            manufacturer_advisories=[],
            intelligence_sync={
                "nvd": {"last_success": None},
                "cisa_kev": {"last_success": None},
            },
            save_firmware_assessment=Mock(),
            save_data=Mock(),
        )
        app.network_analyzer = analyzer
        app.firmware_intelligence_engine = FirmwareIntelligenceEngine()
        app._firmware_sync_worker()
        event_type, assessment = app.ui_queue.get_nowait()
        self.assertEqual(event_type, "firmware_complete")
        self.assertEqual(assessment["classification"], "NO_MATCH_FOUND")
        analyzer.save_firmware_assessment.assert_called_once()


class RouterScannerTests(unittest.TestCase):
    @patch("netguard_bangladesh.messagebox.showinfo")
    def test_disabled_router_scanner_reports_unavailable(self, showinfo):
        app = NetGuardBangladesh.__new__(NetGuardBangladesh)
        app.scan_router_vulnerabilities()
        showinfo.assert_called_once()
        self.assertIn("not reliably assess", showinfo.call_args.args[1])

    def test_simulated_vulnerability_scan_is_disabled(self):
        app = NetGuardBangladesh.__new__(NetGuardBangladesh)
        with self.assertRaises(RuntimeError):
            app.simulate_vulnerability_scan("192.168.1.1")


class RouterAssessmentPersistenceTests(unittest.TestCase):
    def test_assessment_history_deduplicates_by_assessment_id(self):
        analyzer = NetworkAnalyzer.__new__(NetworkAnalyzer)
        analyzer.router_assessments = []
        analyzer.save_data = Mock()
        assessment = {
            "assessment_id": "assessment-1",
            "gateway_ip": "192.168.1.1",
            "service_observations": [],
        }
        analyzer.save_router_assessment(assessment)
        analyzer.save_router_assessment(dict(assessment))
        self.assertEqual(analyzer.router_assessments, [assessment])
        analyzer.save_data.assert_called_once()

    def test_assessment_requires_an_id(self):
        analyzer = NetworkAnalyzer.__new__(NetworkAnalyzer)
        analyzer.router_assessments = []
        analyzer.save_data = Mock()
        with self.assertRaises(ValueError):
            analyzer.save_router_assessment({"gateway_ip": "192.168.1.1"})

    def test_upnp_and_dns_history_avoid_duplicate_snapshots(self):
        analyzer = NetworkAnalyzer.__new__(NetworkAnalyzer)
        analyzer.upnp_observations = []
        analyzer.dns_configuration_history = []
        analyzer.save_data = Mock()
        upnp = {
            "source_ip": "192.168.1.1",
            "usn": "uuid:one",
            "st": "upnp:rootdevice",
            "location": "http://192.168.1.1/device.xml",
        }
        analyzer.save_upnp_observations([upnp, dict(upnp)])
        analyzer.save_dns_configuration({"interface": "Ethernet", "servers": ["1.1.1.1"]})
        analyzer.save_dns_configuration({"interface": "Ethernet", "servers": ["1.1.1.1"]})
        self.assertEqual(len(analyzer.upnp_observations), 1)
        self.assertEqual(len(analyzer.dns_configuration_history), 1)

    def test_firmware_product_and_assessment_history_deduplicate_by_router(self):
        analyzer = NetworkAnalyzer.__new__(NetworkAnalyzer)
        analyzer.firmware_products = []
        analyzer.firmware_assessments = []
        analyzer.save_data = Mock()
        product = {"router_id": "router-1", "manufacturer": "tp-link", "model": "Archer C7"}
        analyzer.save_firmware_product(product)
        analyzer.save_firmware_product(dict(product, model="Archer C7 V5"))
        analyzer.save_firmware_assessment({
            "router_id": "router-1", "classification": "NO_MATCH_FOUND"
        })
        analyzer.save_firmware_assessment({
            "router_id": "router-1", "classification": "PRODUCT_MATCH_VERSION_UNKNOWN"
        })
        self.assertEqual(len(analyzer.firmware_products), 1)
        self.assertEqual(analyzer.firmware_products[0]["model"], "Archer C7 V5")
        self.assertEqual(len(analyzer.firmware_assessments), 1)
        self.assertEqual(
            analyzer.firmware_assessments[0]["classification"],
            "PRODUCT_MATCH_VERSION_UNKNOWN",
        )


if __name__ == "__main__":
    unittest.main()
