import threading
import unittest
import socket
import ssl
import struct
from urllib.error import HTTPError
from datetime import datetime
from unittest.mock import Mock, patch

from netguard_bangladesh import (
    DiscoveryEngine,
    NetworkInterface,
    RouterIdentificationEngine,
    RouterManagementAssessmentEngine,
    UPnPDiscoveryEngine,
    DNSConfigurationEngine,
    SecurityFindingsEngine,
    WirelessSecurityEngine,
    WirelessBaselineEngine,
    FirmwareVersionEngine,
    ManufacturerAdvisoryRegistry,
    FirmwareIntelligenceEngine,
    VulnerabilitySourceClient,
    FirmwareUpdateAdvisor,
)


IPCONFIG_SAMPLE = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : example.local
   Description . . . . . . . . . . . : Intel Ethernet
   Physical Address. . . . . . . . . : 00-AA-BB-CC-DD-EE
   IPv4 Address. . . . . . . . . . . : 192.168.50.10(Preferred)
   IPv6 Address. . . . . . . . . . . : fe80::1234%12(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.1

Wireless LAN adapter Wi-Fi:

   Description . . . . . . . . . . . : Example Wi-Fi VPN
   Physical Address. . . . . . . . . : 11-22-33-44-55-66
   IPv4 Address. . . . . . . . . . . : 10.10.0.5
   Subnet Mask . . . . . . . . . . . : 255.255.255.0

Tunnel adapter Example VPN:

   Media State . . . . . . . . . . . : Media disconnected
"""


class InterfaceDiscoveryTests(unittest.TestCase):
    def test_parse_ipconfig_extracts_interface_network_and_gateway(self):
        interfaces = DiscoveryEngine.parse_ipconfig(IPCONFIG_SAMPLE)
        ethernet = interfaces[0]
        self.assertEqual(ethernet.name, "Ethernet")
        self.assertEqual(ethernet.description, "Intel Ethernet")
        self.assertEqual(ethernet.mac_address, "00:aa:bb:cc:dd:ee")
        self.assertEqual(ethernet.network_cidr, "192.168.50.0/24")
        self.assertEqual(ethernet.broadcast_address, "192.168.50.255")
        self.assertEqual(ethernet.default_gateway, "192.168.50.1")
        self.assertEqual(ethernet.default_gateways, ["192.168.50.1"])
        self.assertEqual(ethernet.operational_status, "up")

    def test_parse_ipconfig_classifies_vpn_and_disconnected_adapters(self):
        interfaces = DiscoveryEngine.parse_ipconfig(IPCONFIG_SAMPLE)
        self.assertEqual(interfaces[1].adapter_category, "vpn")
        self.assertEqual(interfaces[2].operational_status, "disconnected")

    def test_parse_ipconfig_preserves_missing_gateway_and_invalid_subnet(self):
        interfaces = DiscoveryEngine.parse_ipconfig(
            "Ethernet adapter Broken:\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.4\n"
            "   Subnet Mask . . . . . . . . . . . : invalid\n"
        )
        self.assertIsNone(interfaces[0].default_gateway)
        self.assertIsNone(interfaces[0].network_cidr)

    def test_validate_scan_scope_rejects_missing_subnet(self):
        interface = NetworkInterface(name="Unknown")
        with self.assertRaises(ValueError):
            DiscoveryEngine.validate_scan_scope(interface)

    def test_validate_scan_scope_rejects_public_network(self):
        interface = NetworkInterface(
            name="Public",
            network_cidr="8.8.8.0/30",
        )
        with self.assertRaises(PermissionError):
            DiscoveryEngine.validate_scan_scope(interface)


class ActiveDiscoveryTests(unittest.TestCase):
    def interface(self, cidr="192.168.10.0/30"):
        network = cidr.split("/")[0]
        return NetworkInterface(name="Ethernet", network_cidr=cidr, ipv4_addresses=[network])

    def test_requires_explicit_approval(self):
        engine = DiscoveryEngine()
        with self.assertRaises(PermissionError):
            engine.active_discovery(
                self.interface(), False, threading.Event(), Mock(return_value=True)
            )

    def test_discovers_responding_hosts_without_fabricating_failures(self):
        engine = DiscoveryEngine()
        probe = Mock(side_effect=lambda ip: ip.endswith(".1"))
        result = engine.active_discovery(
            self.interface(),
            True,
            threading.Event(),
            probe,
            rate_limit=1000,
        )
        self.assertEqual(result["responding_ips"], ["192.168.10.1"])
        self.assertEqual(result["probed_hosts"], 2)
        self.assertFalse(result["cancelled"])

    def test_cancellation_stops_submission(self):
        engine = DiscoveryEngine()
        stop_event = threading.Event()
        stop_event.set()
        result = engine.active_discovery(
            self.interface(), True, stop_event, Mock(return_value=True)
        )
        self.assertEqual(result["probed_hosts"], 0)
        self.assertTrue(result["cancelled"])


    def test_large_scope_requires_explicit_large_scope_approval(self):
        engine = DiscoveryEngine()
        interface = NetworkInterface(name="Ethernet", network_cidr="192.168.0.0/16")
        with self.assertRaises(ValueError):
            engine.active_discovery(
                interface, True, threading.Event(), Mock(return_value=True)
            )

    def test_large_scope_can_be_explicitly_allowed(self):
        engine = DiscoveryEngine()
        interface = NetworkInterface(name="Ethernet", network_cidr="192.168.0.0/22")
        stop_event = threading.Event()
        stop_event.set()
        result = engine.active_discovery(
            interface,
            True,
            stop_event,
            Mock(return_value=True),
            allow_large_network=True,
        )
        self.assertEqual(result["probed_hosts"], 0)


class RouterIdentificationTests(unittest.TestCase):
    def setUp(self):
        self.engine = RouterIdentificationEngine()
        self.interface = NetworkInterface(
            name="Ethernet",
            default_gateway="192.168.50.1",
            default_gateway_ipv6="fe80::1",
        )

    def test_identifies_gateway_from_interface_and_arp_evidence(self):
        result = self.engine.identify(
            self.interface,
            [{
                "ip": "192.168.50.1",
                "mac": "00:11:22:33:44:55",
                "observation_source": "windows_arp_cache",
            }],
        )
        self.assertEqual(result["gateway_ipv4"], "192.168.50.1")
        self.assertEqual(result["gateway_ipv6"], "fe80::1")
        self.assertEqual(result["gateway_mac"], "00:11:22:33:44:55")
        self.assertIn("windows_arp_cache", result["sources"])
        self.assertEqual(result["management_interface_availability"], "NOT_ASSESSED")
        self.assertIsNone(result["model"])

    def test_unknown_gateway_does_not_invent_router_identity(self):
        result = self.engine.identify(self.interface, [])
        self.assertIsNone(result["gateway_mac"])
        self.assertIsNone(result["manufacturer"])
        self.assertIsNone(result["model"])
        self.assertIn("No matching gateway MAC", " ".join(result["confidence_limitations"]))

    def test_user_model_is_explicitly_unverified(self):
        result = self.engine.identify(
            self.interface,
            [],
            user_model="TP-Link Archer C6",
            user_firmware="1.3.6",
        )
        self.assertEqual(result["model"], "TP-Link Archer C6")
        self.assertEqual(result["firmware"], "1.3.6")
        self.assertEqual(result["confidence"], "user_provided_unverified")
        self.assertIn("user_provided", result["sources"])


class RouterManagementAssessmentTests(unittest.TestCase):
    class FakeSocket:
        def __init__(self, outcome="open"):
            self.outcome = outcome
            self.closed = False

        def settimeout(self, _timeout):
            return None

        def connect(self, _address):
            if self.outcome == "refused":
                raise ConnectionRefusedError()
            if self.outcome == "timeout":
                raise socket.timeout()
            if self.outcome == "error":
                raise OSError("network unavailable")

        def close(self):
            self.closed = True

    def interface(self, gateway="192.168.50.1"):
        return NetworkInterface(
            name="Ethernet",
            ipv4_addresses=["192.168.50.10"],
            network_cidr="192.168.50.0/24",
            default_gateway=gateway,
        )

    def identity(self, gateway="192.168.50.1"):
        return {"gateway_ipv4": gateway, "gateway_mac": "00:11:22:33:44:55"}

    def test_gateway_validation_rejects_public_and_unrelated_targets(self):
        engine = RouterManagementAssessmentEngine()
        with self.assertRaises(PermissionError):
            engine.validate_gateway(self.interface(), "8.8.8.8")
        with self.assertRaises(PermissionError):
            engine.validate_gateway(self.interface(), "10.0.0.1")

    def test_gateway_validation_rejects_stale_identity(self):
        engine = RouterManagementAssessmentEngine()
        with self.assertRaises(PermissionError):
            engine.assess_services(
                self.interface(),
                self.identity("192.168.50.2"),
                threading.Event(),
                ports=[],
            )

    def test_gateway_validation_accepts_link_local_ipv6_on_interface(self):
        engine = RouterManagementAssessmentEngine()
        interface = NetworkInterface(
            name="Wi-Fi",
            ipv6_addresses=["fe80::1234"],
            default_gateway_ipv6="fe80::1",
        )
        self.assertEqual(
            engine.validate_gateway(interface),
            "fe80::1",
        )

    def test_tcp_open_refused_timeout_and_error_are_distinct(self):
        outcomes = iter(["open", "refused", "timeout", "error"])

        def factory(_family, _kind):
            return self.FakeSocket(next(outcomes))

        engine = RouterManagementAssessmentEngine(socket_factory=factory)
        result = engine.assess_services(
            self.interface(),
            self.identity(),
            threading.Event(),
            rate_limit=1000,
            ports=[21, 22, 23, 53],
        )
        self.assertEqual(
            [item["connection_result"] for item in result["service_observations"]],
            ["OPEN", "REFUSED", "TIMEOUT", "ERROR"],
        )
        self.assertEqual(result["service_observations"][2]["classification"], "SERVICE_RESPONSE_UNAVAILABLE")

    def test_cancellation_prevents_connection_attempts(self):
        stop_event = threading.Event()
        stop_event.set()
        factory = Mock()
        engine = RouterManagementAssessmentEngine(socket_factory=factory)
        result = engine.assess_services(
            self.interface(), self.identity(), stop_event, ports=[80]
        )
        factory.assert_not_called()
        self.assertEqual(result["assessment_status"], "CANCELLED")
        self.assertEqual(result["service_observations"], [])

    def test_http_assessment_does_not_follow_external_redirect(self):
        response = Mock(status=302)
        response.getheaders.return_value = [
            ("Location", "https://example.com/login"),
            ("Server", "router-httpd"),
        ]
        connection = Mock()
        connection.getresponse.return_value = response
        engine = RouterManagementAssessmentEngine(
            http_connection_factory=Mock(return_value=connection)
        )
        observation = {
            "connection_result": "OPEN",
            "target_port": 80,
            "gateway_ip": "192.168.50.1",
        }
        result = engine.assess_http(observation)
        self.assertTrue(result["external_redirect"])
        connection.request.assert_called_once()

    def test_http_assessment_handles_connection_failure(self):
        engine = RouterManagementAssessmentEngine(
            http_connection_factory=Mock(side_effect=OSError("timeout"))
        )
        result = engine.assess_http({
            "connection_result": "OPEN",
            "target_port": 80,
            "gateway_ip": "192.168.50.1",
        })
        self.assertIn("timeout", result["error"])

    @patch("netguard_bangladesh.ssl.create_default_context")
    def test_tls_success_is_reported_only_after_verified_handshake(self, create_context):
        tls_socket = Mock()
        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.getpeercert.return_value = {
            "subject": ((("commonName", "router.local"),),),
            "issuer": ((("commonName", "Test CA"),),),
        }
        context = Mock()
        context.wrap_socket.return_value = tls_socket
        create_context.return_value = context
        raw_socket = self.FakeSocket()
        engine = RouterManagementAssessmentEngine(
            socket_factory=Mock(return_value=raw_socket)
        )
        result = engine.assess_tls({
            "connection_result": "OPEN",
            "target_port": 443,
            "gateway_ip": "192.168.50.1",
        })
        self.assertEqual(result["handshake"], "SUCCESS")
        self.assertTrue(result["certificate_trusted"])
        self.assertEqual(result["tls_version"], "TLSv1.3")

    @patch("netguard_bangladesh.ssl.create_default_context")
    def test_tls_failure_is_not_reported_as_secure(self, create_context):
        context = Mock()
        context.wrap_socket.side_effect = ssl.SSLError("certificate verify failed")
        create_context.return_value = context
        engine = RouterManagementAssessmentEngine(
            socket_factory=Mock(return_value=self.FakeSocket())
        )
        result = engine.assess_tls({
            "connection_result": "OPEN",
            "target_port": 443,
            "gateway_ip": "192.168.50.1",
        })
        self.assertEqual(result["handshake"], "FAILED")
        self.assertFalse(result["certificate_trusted"])


class UPnPDNSTests(unittest.TestCase):
    class SSDPSocket:
        def __init__(self):
            self.closed = False
            self.sent = False

        def settimeout(self, _timeout):
            return None

        def setsockopt(self, *_args):
            return None

        def sendto(self, _payload, _target):
            self.sent = True

        def recvfrom(self, _size):
            if self.sent:
                self.sent = False
                return (
                    b"HTTP/1.1 200 OK\r\n"
                    b"ST: upnp:rootdevice\r\n"
                    b"USN: uuid:device-1::upnp:rootdevice\r\n"
                    b"LOCATION: http://192.168.50.1:80/device.xml\r\n"
                    b"SERVER: test-router\r\n\r\n",
                    ("192.168.50.1", 1900),
                )
            raise socket.timeout()

        def close(self):
            self.closed = True

    def interface(self):
        return NetworkInterface(
            name="Ethernet",
            ipv4_addresses=["192.168.50.10"],
            network_cidr="192.168.50.0/24",
        )

    def test_ssdp_response_is_parsed_and_deduplicated(self):
        engine = UPnPDiscoveryEngine(socket_factory=Mock(return_value=self.SSDPSocket()))
        result = engine.discover(self.interface(), True, threading.Event(), response_window=0.1)
        self.assertEqual(len(result["observations"]), 1)
        self.assertEqual(result["observations"][0]["source_ip"], "192.168.50.1")
        self.assertEqual(result["observations"][0]["usn"], "uuid:device-1::upnp:rootdevice")

    def test_ssdp_requires_authorization_and_rejects_external_location(self):
        engine = UPnPDiscoveryEngine()
        with self.assertRaises(PermissionError):
            engine.discover(self.interface(), False, threading.Event())
        with self.assertRaises(PermissionError):
            engine.validate_location("http://8.8.8.8/device.xml", self.interface())
        with self.assertRaises(PermissionError):
            engine.validate_location("http://router.local/device.xml", self.interface())

    def test_device_description_rejects_entity_declarations(self):
        response = Mock(status=200)
        response.read.return_value = b"<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///secret'>]>"
        connection = Mock()
        connection.getresponse.return_value = response
        engine = UPnPDiscoveryEngine(http_connection_factory=Mock(return_value=connection))
        result = engine.retrieve_description(
            {"source_ip": "192.168.50.1", "location": "http://192.168.50.1/device.xml"},
            self.interface(),
        )
        self.assertIn("Unsafe XML", result["error"])

    def test_dns_configuration_parses_multiple_servers(self):
        output = (
            "Ethernet adapter Ethernet:\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.50.10\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
            "   DNS Servers . . . . . . . . . . . : 192.168.50.1\n"
            "                                       1.1.1.1\n"
            "   Default Gateway . . . . . . . . . : 192.168.50.1\n"
        )
        snapshots = DNSConfigurationEngine.parse_dns_servers(output)
        self.assertEqual(snapshots[0]["servers"], ["192.168.50.1", "1.1.1.1"])

    def test_dns_query_requires_consent_and_handles_timeout(self):
        engine = DNSConfigurationEngine(socket_factory=Mock())
        with self.assertRaises(PermissionError):
            engine.query("192.168.50.1", approved=False)
        fake_socket = Mock()
        fake_socket.recvfrom.side_effect = socket.timeout()
        engine = DNSConfigurationEngine(socket_factory=Mock(return_value=fake_socket))
        result = engine.query("192.168.50.1", approved=True, timeout=0.01)
        self.assertEqual(result["status"], "TIMEOUT")
        fake_socket.close.assert_called_once()

    def test_dns_response_parses_a_record(self):
        query_id = 0x1234
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        packet = (
            struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
            + question
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + b"\x5d\xb8\xd8\x22"
        )
        parsed = DNSConfigurationEngine.parse_response(packet, query_id, 1)
        self.assertEqual(parsed["response_code"], "NOERROR")
        self.assertEqual(parsed["answers"], ["93.184.216.34"])

    def test_dns_query_comparison_requires_consent(self):
        with self.assertRaises(PermissionError):
            DNSConfigurationEngine().compare(
                "192.168.50.1", "1.1.1.1", approved=False
            )

    def test_security_findings_keep_upnp_and_dns_observations_conservative(self):
        engine = SecurityFindingsEngine()
        upnp = engine.upnp_findings({
            "observations": [{
                "source_ip": "192.168.50.1",
                "usn": "uuid:router",
                "st": "upnp:rootdevice",
                "description": {
                    "device": {"devicetype": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"},
                    "services": [{"service_type": "WANIPConnection"}],
                },
            }],
            "errors": [],
        })
        self.assertTrue(any(item["category"] == "INTERNET_GATEWAY_DEVICE_IDENTIFIED" for item in upnp))
        self.assertTrue(all(item["severity"] == "INFORMATIONAL" for item in upnp))
        dns = engine.dns_configuration_findings(
            {"interface": "Ethernet", "servers": ["192.168.50.1"]},
            {"interface": "Ethernet", "servers": ["1.1.1.1"]},
        )
        self.assertEqual(dns[0]["category"], "DNS_CONFIGURATION_CHANGED")
        self.assertNotEqual(dns[0]["category"], "DNS_HIJACKING_CONFIRMED")


class WirelessSecurityTests(unittest.TestCase):
    INTERFACES = """
    Name                   : Wi-Fi
    Description            : Example Wireless Adapter
    GUID                   : {11111111-2222-3333-4444-555555555555}
    Physical address       : 00-11-22-33-44-55
    State                  : connected
    SSID                   : OfficeNet
    BSSID                  : aa-bb-cc-dd-ee-ff
    Network type           : Infrastructure
    Radio type             : 802.11ac
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Channel                : 36
    Signal                 : 78%
    """

    BSS = """
    SSID 1 : OfficeNet
        Network type           : Infrastructure
        Authentication         : WPA2-Personal
        Encryption             : CCMP
        BSSID 1                : aa-bb-cc-dd-ee-ff
             Signal            : 78%
             Radio type        : 802.11ac
             Channel           : 36
    SSID 2 :
        Network type           : Infrastructure
        Authentication         : WPA2-Personal
        Encryption             : CCMP
        BSSID 1                : 11-22-33-44-55-66
             Signal            : 40%
             Radio type        : 802.11n
             Channel           : 6
    """

    def test_interface_parser_preserves_missing_fields_as_unavailable(self):
        interfaces = WirelessSecurityEngine.parse_interfaces(self.INTERFACES)
        self.assertEqual(len(interfaces), 1)
        self.assertEqual(interfaces[0]["ssid"], "OfficeNet")
        self.assertEqual(interfaces[0]["bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(interfaces[0]["signal_percent"], 78)
        self.assertEqual(interfaces[0]["channel"], 36)

    def test_bss_parser_handles_multiple_bssids_and_hidden_ssid(self):
        observations = WirelessSecurityEngine.parse_bss_list(self.BSS)
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[0]["security_classification"], "WPA2-PERSONAL")
        self.assertIsNone(observations[1]["ssid"])

    def test_security_classification_does_not_infer_from_radio_type(self):
        self.assertEqual(
            WirelessSecurityEngine.classify_security("Unknown", "Unknown"),
            "UNKNOWN",
        )
        self.assertEqual(
            WirelessSecurityEngine.classify_security("WPA3-Personal", "GCMP"),
            "WPA3-PERSONAL",
        )

    def test_baseline_treats_new_bssid_and_open_network_conservatively(self):
        current = [{
            "ssid": "OfficeNet",
            "bssid": "11:22:33:44:55:66",
            "authentication": "Open",
            "cipher": "None",
            "security_classification": "OPEN",
            "adapter": "Wi-Fi",
            "source": "netsh",
        }]
        baseline = [{
            "ssid": "OfficeNet",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "security_classification": "WPA2-PERSONAL",
        }]
        findings = WirelessBaselineEngine().analyze(current, baseline)
        categories = {item["category"] for item in findings}
        self.assertIn("NEW_ACCESS_POINT_OBSERVED", categories)
        self.assertIn("POTENTIAL_EVIL_TWIN_INDICATOR", categories)
        self.assertTrue(all(item["severity"] == "INFORMATIONAL" for item in findings))

    def test_legitimate_multiple_bssids_do_not_become_confirmed_attack(self):
        current = [{
            "ssid": "Mesh",
            "bssid": "11:22:33:44:55:66",
            "security_classification": "WPA2-PERSONAL",
            "adapter": "Wi-Fi",
            "source": "netsh",
        }]
        baseline = [
            {"ssid": "Mesh", "bssid": "aa:bb:cc:dd:ee:ff",
             "security_classification": "WPA2-PERSONAL"},
            {"ssid": "Mesh", "bssid": "11:22:33:44:55:66",
             "security_classification": "WPA2-PERSONAL"},
        ]
        findings = WirelessBaselineEngine().analyze(current, baseline)
        self.assertFalse(any("CONFIRMED" in item["category"] for item in findings))

    @patch("netguard_bangladesh.platform.system", return_value="Windows")
    def test_wireless_commands_are_bounded_and_mockable(self, _platform):
        runner = Mock(return_value=Mock(returncode=0, stdout=self.INTERFACES, stderr=""))
        engine = WirelessSecurityEngine(command_runner=runner)
        self.assertEqual(len(engine.inspect_interfaces()), 1)
        runner.assert_called_once_with(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=15, check=False,
        )

    @patch("netguard_bangladesh.platform.system", return_value="Windows")
    def test_wireless_command_failure_is_explicit(self, _platform):
        runner = Mock(return_value=Mock(
            returncode=1, stdout="", stderr="Access is denied"
        ))
        with self.assertRaisesRegex(RuntimeError, "Access is denied"):
            WirelessSecurityEngine(command_runner=runner).inspect_drivers()


class FirmwareIntelligenceTests(unittest.TestCase):
    def product(self, **overrides):
        product = FirmwareIntelligenceEngine.register_product(
            "TP-Link", "Archer C7", "V5", "BD", "1.2.3",
            verification_status="USER_CONFIRMED",
        )
        product.update(overrides)
        return product

    def test_registration_preserves_unverified_and_confirmed_states(self):
        unverified = FirmwareIntelligenceEngine.register_product(
            "TP-Link", "Archer C7"
        )
        confirmed = FirmwareIntelligenceEngine.register_product(
            "TP-Link", "Archer C7", confirmed=True
        )
        self.assertEqual(unverified["verification_status"], "USER_PROVIDED_UNVERIFIED")
        self.assertEqual(confirmed["verification_status"], "USER_CONFIRMED")
        self.assertIsNone(unverified["last_verified_timestamp"])

    def test_version_comparison_and_boundaries(self):
        self.assertEqual(FirmwareVersionEngine.compare("1.2.10", "1.2.3"), 1)
        self.assertEqual(FirmwareVersionEngine.compare("1.2-beta", "1.2"), -1)
        self.assertTrue(FirmwareVersionEngine.in_range(
            "1.2.3", {"versionStartIncluding": "1.2.0", "versionEndExcluding": "1.3.0"}
        ))
        self.assertFalse(FirmwareVersionEngine.in_range(
            "1.3.0", {"versionStartIncluding": "1.2.0", "versionEndExcluding": "1.3.0"}
        ))
        self.assertIsNone(FirmwareVersionEngine.compare("R1.2", "1.2"))

    def test_cpe_product_match_rejects_product_mismatch(self):
        record = {"criteria": "cpe:2.3:o:tp-link:archer_c7:1.2.3:*:*:*:*:*:*:*", "vulnerable": True}
        self.assertTrue(FirmwareIntelligenceEngine.cpe_matches_product(self.product(), record))
        wrong = dict(record, criteria=record["criteria"].replace("archer_c7", "archer_c6"))
        self.assertFalse(FirmwareIntelligenceEngine.cpe_matches_product(self.product(), wrong))

    def test_logical_and_configuration_requires_all_children(self):
        product = self.product()
        record = {
            "configurations": [{
                "operator": "AND",
                "children": [
                    {"cpeMatch": [{
                        "criteria": "cpe:2.3:o:tp-link:archer_c7:*:*:*:*:*:*:*:*",
                        "vulnerable": True,
                        "versionStartIncluding": "1.0",
                        "versionEndIncluding": "2.0",
                    }]},
                    {"cpeMatch": [{
                        "criteria": "cpe:2.3:h:tp-link:archer_c7:*:*:*:*:*:*:*:*",
                        "vulnerable": True,
                    }]},
                ],
            }]
        }
        self.assertTrue(FirmwareIntelligenceEngine.record_applies(product, record))
        product["firmware_version"] = "2.1"
        self.assertFalse(FirmwareIntelligenceEngine.record_applies(product, record))

    def test_nvd_parser_handles_valid_and_malformed_payloads(self):
        payload = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2025-0001",
                    "descriptions": [{"lang": "en", "value": "Example"}],
                    "published": "2025-01-01",
                    "lastModified": "2025-01-02",
                    "metrics": {"cvssMetricV31": [{
                        "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH", "version": "3.1"}
                    }]},
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2025-0001"}],
                    "configurations": [],
                }
            }]
        }
        parsed = VulnerabilitySourceClient.parse_nvd_records(payload)
        self.assertEqual(parsed[0]["cve_id"], "CVE-2025-0001")
        self.assertEqual(parsed[0]["cvss_score"], 8.1)
        with self.assertRaises(ValueError):
            VulnerabilitySourceClient.parse_nvd_records({})

    def test_assessment_keeps_kev_separate_from_product_applicability(self):
        product = self.product()
        cve = {
            "cve_id": "CVE-2025-0001",
            "description": "Affected router",
            "configurations": [{
                "operator": "OR",
                "cpeMatch": [{
                    "criteria": "cpe:2.3:o:tp-link:archer_c7:1.2.3:*:*:*:*:*:*:*",
                    "vulnerable": True,
                }],
            }],
            "cvss_severity": "HIGH",
        }
        result = FirmwareIntelligenceEngine.assess(
            product, [cve], [], [{"cveID": "CVE-2025-0001"}]
        )
        self.assertEqual(result["classification"], "EXACT_VERIFIED_MATCH")
        self.assertTrue(result["findings"][0]["cisa_kev"])
        no_match = FirmwareIntelligenceEngine.assess(
            product, [], [], [{"cveID": "CVE-2025-9999"}]
        )
        self.assertEqual(no_match["classification"], "NO_MATCH_FOUND")
        self.assertIn("not proof", no_match["explanation"])

    def test_product_match_with_unknown_firmware_is_not_confirmed(self):
        product = self.product(firmware_version=None)
        cve = {
            "cve_id": "CVE-2025-0002",
            "configurations": [{
                "cpeMatch": [{
                    "criteria": "cpe:2.3:o:tp-link:archer_c7:*:*:*:*:*:*:*:*",
                    "vulnerable": True,
                }]
            }],
        }
        result = FirmwareIntelligenceEngine.assess(product, [cve], [], [])
        self.assertEqual(result["classification"], "PRODUCT_MATCH_VERSION_UNKNOWN")
        self.assertEqual(
            result["findings"][0]["match_classification"],
            "PRODUCT_MATCH_VERSION_UNKNOWN",
        )

    def test_freshness_marks_missing_invalid_and_old_sources(self):
        self.assertEqual(FirmwareIntelligenceEngine.freshness(None), "UNAVAILABLE")
        self.assertEqual(
            FirmwareIntelligenceEngine.freshness("not-a-date"), "UNAVAILABLE"
        )
        self.assertEqual(
            FirmwareIntelligenceEngine.freshness(
                "2026-01-01T00:00:00", now=datetime(2026, 1, 2)
            ),
            "CURRENT",
        )
        self.assertEqual(
            FirmwareIntelligenceEngine.freshness(
                "2025-01-01T00:00:00", now=datetime(2026, 1, 2)
            ),
            "OUTDATED",
        )

    def test_advisory_requires_official_https_source_and_deduplicates(self):
        advisory = ManufacturerAdvisoryRegistry.normalize({
            "advisory_id": "TPLINK-1",
            "manufacturer": "TP-Link",
            "affected_product": "Archer C7",
            "source_url": "https://www.tp-link.com/support/security-advisory/",
            "recommended_remediation": "Install the fixed release.",
        }, verified=True)
        self.assertEqual(advisory["verification_status"], "OFFICIAL_SOURCE_REGISTERED")
        with self.assertRaises(ValueError):
            ManufacturerAdvisoryRegistry.normalize(dict(advisory, source_url="http://example.test"))

    def test_kev_parser_and_client_retry_are_deterministic(self):
        class FakeResponse:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, _limit): return b'{"vulnerabilities": [{"cveID": "CVE-1"}]}'
        opener = Mock(side_effect=[HTTPError("url", 429, "busy", {}, None), FakeResponse()])
        client = VulnerabilitySourceClient(opener=opener, sleep=lambda _delay: None)
        catalog = client.fetch_kev()
        self.assertEqual(catalog["vulnerabilities"][0]["cveID"], "CVE-1")
        self.assertEqual(opener.call_count, 2)

    def test_update_advisor_never_enables_automatic_installation(self):
        result = FirmwareUpdateAdvisor.recommendations(
            self.product(),
            [{"cve_id": "CVE-1", "fixed_firmware_version": "1.2.4"}],
            [],
        )
        self.assertFalse(result[0]["automatic_installation"])


if __name__ == "__main__":
    unittest.main()
