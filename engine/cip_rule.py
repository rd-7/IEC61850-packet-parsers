from engine.base_rule import BaseRule
from utils.logger import log_alert

class CIPRule(BaseRule):
    """
    CIP (Common Industrial Protocol) rule engine that matches service codes, class codes,
    and encapsulation commands. Supports EtherNet/IP encapsulation and various CIP extensions.
    """

    def __init__(self, rules, exceptions=None, connection_management=None, file_operations=None, 
                 vendor_specific=None, safety_services=None, motion_services=None, 
                 sync_services=None, energy_services=None, class_objects=None, 
                 encapsulation_commands=None):
        self.rules = rules or {}
        self.exception_rules = exceptions or {}
        self.connection_management = connection_management or {}
        self.file_operations = file_operations or {}
        self.vendor_specific = vendor_specific or {}
        self.safety_services = safety_services or {}
        self.motion_services = motion_services or {}
        self.sync_services = sync_services or {}
        self.energy_services = energy_services or {}
        self.class_objects = class_objects or {}
        self.encapsulation_commands = encapsulation_commands or {}

    def match(self, packet):
        try:
            if "cip" in packet or "enip" in packet or "ethernet_ip" in packet:
                self._process_cip_packet(packet)
        except Exception as e:
            print(f"[CIP ERROR]  Exception while processing CIP packet: {e}")

    def _process_cip_packet(self, packet):
        """Process CIP packet and extract relevant information"""
        src_ip = getattr(packet.ip, "src", "N/A") if hasattr(packet, 'ip') else "N/A"
        dst_ip = getattr(packet.ip, "dst", "N/A") if hasattr(packet, 'ip') else "N/A"
        timestamp = packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else "N/A"

        print("=" * 60)
        print(f"[CIP]  CIP Packet Detected")

        # Check for EtherNet/IP encapsulation layer first
        if self._check_encapsulation_layer(packet, src_ip, dst_ip, timestamp):
            return

        # Check for CIP service codes
        service_code = self._extract_service_code(packet)
        if service_code:
            print(f"[CIP]  Service Code Detected: {service_code}")
            self._process_service_code(packet, service_code, src_ip, dst_ip, timestamp)

        # Check for CIP class codes
        class_code = self._extract_class_code(packet)
        if class_code:
            print(f"[CIP]  Class Code Detected: {class_code}")
            self._process_class_code(packet, class_code, src_ip, dst_ip, timestamp)

        # Check for CIP exceptions/errors
        self._check_cip_exceptions(packet, src_ip, dst_ip, timestamp)

    def _check_encapsulation_layer(self, packet, src_ip, dst_ip, timestamp):
        """Check EtherNet/IP encapsulation commands"""
        encap_command = self._extract_encapsulation_command(packet)
        if encap_command:
            print(f"[CIP]  Encapsulation Command: {encap_command}")
            
            rule = self.encapsulation_commands.get(encap_command)
            if rule:
                alert = self._create_alert(
                    rule, timestamp, src_ip, dst_ip, packet,
                    additional_fields={
                        "encapsulation_command": encap_command,
                        "layer": "encapsulation"
                    }
                )
                print(f"[CIP]  Encapsulation Match → {alert['event']} (Severity: {alert['severity']})")
                log_alert(alert)
                return True
        return False

    def _process_service_code(self, packet, service_code, src_ip, dst_ip, timestamp):
        """Process CIP service codes with specialized handling"""
        
        # Check for error response
        if service_code == "0x14":
            error_code = self._extract_error_code(packet)
            if error_code:
                self._handle_cip_error(packet, service_code, error_code, src_ip, dst_ip, timestamp)
                return

        # Check specialized service categories
        rule = None
        category_info = ""
        
        # Connection management services
        if service_code in self.connection_management:
            rule = self.connection_management[service_code]
            category_info = "Connection Management"
            self._handle_connection_service(packet, service_code, src_ip, dst_ip, timestamp)
        
        # File operation services
        elif service_code in self.file_operations:
            rule = self.file_operations[service_code]
            category_info = "File Operations"
            self._handle_file_operation(packet, service_code, src_ip, dst_ip, timestamp)
        
        # Vendor-specific services (e.g., Rockwell)
        elif service_code in self.vendor_specific:
            rule = self.vendor_specific[service_code]
            category_info = "Vendor Specific"
            self._handle_vendor_specific(packet, service_code, src_ip, dst_ip, timestamp)
        
        # Safety services
        elif service_code in self.safety_services:
            rule = self.safety_services[service_code]
            category_info = "Safety Services"
            self._handle_safety_service(packet, service_code, src_ip, dst_ip, timestamp)
        
        # Motion services
        elif service_code in self.motion_services:
            rule = self.motion_services[service_code]
            category_info = "Motion Services"
            self._handle_motion_service(packet, service_code, src_ip, dst_ip, timestamp)
        
        # Sync services
        elif service_code in self.sync_services:
            rule = self.sync_services[service_code]
            category_info = "Sync Services"
            self._handle_sync_service(packet, service_code, src_ip, dst_ip, timestamp)
        
        # Energy services
        elif service_code in self.energy_services:
            rule = self.energy_services[service_code]
            category_info = "Energy Services"
            self._handle_energy_service(packet, service_code, src_ip, dst_ip, timestamp)
        
        # Standard rules
        else:
            rule = self.rules.get(service_code)

        if rule:
            alert = self._create_alert(
                rule, timestamp, src_ip, dst_ip, packet,
                additional_fields={
                    "service_code": service_code,
                    "category_info": category_info
                }
            )
            print(f"[CIP]  Service Match → {alert['event']} (Severity: {alert['severity']}) [{category_info}]")
            log_alert(alert)
        else:
            print(f"[CIP]  No rule matched for service code: {service_code}")

    def _process_class_code(self, packet, class_code, src_ip, dst_ip, timestamp):
        """Process CIP class codes"""
        rule = self.class_objects.get(class_code)
        
        if rule:
            alert = self._create_alert(
                rule, timestamp, src_ip, dst_ip, packet,
                additional_fields={
                    "class_code": class_code,
                    "object_type": "class"
                }
            )
            print(f"[CIP]  Class Object → {alert['event']} (Severity: {alert['severity']})")
            log_alert(alert)
        else:
            print(f"[CIP]  Unknown class code: {class_code}")

    def _check_cip_exceptions(self, packet, src_ip, dst_ip, timestamp):
        """Check for CIP exceptions and error conditions"""
        error_code = self._extract_general_status(packet)
        if error_code:
            rule = self.exception_rules.get(error_code)
            
            if rule:
                alert = self._create_alert(
                    rule, timestamp, src_ip, dst_ip, packet,
                    additional_fields={
                        "error_code": error_code,
                        "error_type": "general_status"
                    }
                )
                print(f"[CIP]  Exception Detected → {alert['event']} (Severity: {alert['severity']})")
                log_alert(alert)

    def _handle_connection_service(self, packet, service_code, src_ip, dst_ip, timestamp):
        """Handle connection management specific processing"""
        if service_code == "0x54":  # Forward Open
            connection_path = self._extract_connection_path(packet)
            print(f"[CIP]  🔗 Forward Open - Connection Path: {connection_path}")
        elif service_code == "0x4E":  # Forward Close
            connection_id = self._extract_connection_id(packet)
            print(f"[CIP]  🔗 Forward Close - Connection ID: {connection_id}")

    def _handle_file_operation(self, packet, service_code, src_ip, dst_ip, timestamp):
        """Handle file operation specific processing"""
        if service_code in ["0x4B", "0x4C"]:  # Upload/Download operations
            file_name = self._extract_file_name(packet)
            print(f"[CIP]  📁 File Operation - File: {file_name}")

    def _handle_vendor_specific(self, packet, service_code, src_ip, dst_ip, timestamp):
        """Handle vendor-specific services (e.g., Rockwell tag operations)"""
        if service_code in ["0x4C", "0x4D"]:  # Read/Write Tag
            tag_name = self._extract_tag_name(packet)
            print(f"[CIP]  🏷️  Tag Operation - Tag: {tag_name}")

    def _handle_safety_service(self, packet, service_code, src_ip, dst_ip, timestamp):
        """Handle CIP Safety specific processing"""
        safety_state = self._extract_safety_state(packet)
        print(f"[CIP]  🛡️  Safety Service - State: {safety_state}")

    def _handle_motion_service(self, packet, service_code, src_ip, dst_ip, timestamp):
        """Handle CIP Motion specific processing"""
        axis_info = self._extract_axis_info(packet)
        print(f"[CIP]  ⚙️  Motion Service - Axis: {axis_info}")

    def _handle_sync_service(self, packet, service_code, src_ip, dst_ip, timestamp):
        """Handle CIP Sync specific processing"""
        sync_time = self._extract_sync_time(packet)
        print(f"[CIP]  🕒 Sync Service - Time: {sync_time}")

    def _handle_energy_service(self, packet, service_code, src_ip, dst_ip, timestamp):
        """Handle CIP Energy specific processing"""
        energy_data = self._extract_energy_data(packet)
        print(f"[CIP]  ⚡ Energy Service - Data: {energy_data}")

    def _handle_cip_error(self, packet, service_code, error_code, src_ip, dst_ip, timestamp):
        """Handle CIP error responses"""
        rule = self.exception_rules.get(error_code)
        
        if rule:
            alert = self._create_alert(
                rule, timestamp, src_ip, dst_ip, packet,
                additional_fields={
                    "service_code": service_code,
                    "error_code": error_code,
                    "error_response": True
                }
            )
            print(f"[CIP]  Error Response → {alert['event']} (Code: {error_code}, Severity: {alert['severity']})")
            log_alert(alert)

    def _create_alert(self, rule, timestamp, src_ip, dst_ip, packet, additional_fields=None):
        """Create standardized alert structure"""
        alert = {
            "event_id": rule.get("id"),
            "timestamp": timestamp,
            "protocol": "CIP",
            "event": rule.get("event", "Unknown"),
            "category": rule.get("category", "unknown"),
            "severity": rule.get("severity", "low"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_mac": getattr(packet.eth, "src", "N/A") if hasattr(packet, 'eth') else "N/A",
            "dst_mac": getattr(packet.eth, "dst", "N/A") if hasattr(packet, 'eth') else "N/A",
            "summary": f"{rule.get('event')} from {src_ip} to {dst_ip}"
        }
        
        if additional_fields:
            alert.update(additional_fields)
        
        return alert

    # Extraction methods for various CIP fields
    def _extract_service_code(self, packet):
        """Extract CIP service code from packet"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'service'):
                return f"0x{int(packet.cip.service):02x}"
            elif hasattr(packet, 'enip') and hasattr(packet.enip, 'cip_service'):
                return f"0x{int(packet.enip.cip_service):02x}"
        except:
            pass
        return None

    def _extract_class_code(self, packet):
        """Extract CIP class code from packet"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'class_id'):
                return f"0x{int(packet.cip.class_id):02x}"
        except:
            pass
        return None

    def _extract_encapsulation_command(self, packet):
        """Extract EtherNet/IP encapsulation command"""
        try:
            if hasattr(packet, 'enip') and hasattr(packet.enip, 'command'):
                return f"0x{int(packet.enip.command):04x}"
        except:
            pass
        return None

    def _extract_error_code(self, packet):
        """Extract CIP error code"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'status'):
                return f"0x{int(packet.cip.status):02x}"
        except:
            pass
        return None

    def _extract_general_status(self, packet):
        """Extract general status code"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'general_status'):
                return f"0x{int(packet.cip.general_status):02x}"
        except:
            pass
        return None

    def _extract_connection_path(self, packet):
        """Extract connection path for Forward Open"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'connection_path'):
                return packet.cip.connection_path
        except:
            pass
        return "N/A"

    def _extract_connection_id(self, packet):
        """Extract connection ID"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'connection_id'):
                return f"0x{int(packet.cip.connection_id):08x}"
        except:
            pass
        return "N/A"

    def _extract_file_name(self, packet):
        """Extract file name for file operations"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'file_name'):
                return packet.cip.file_name
        except:
            pass
        return "N/A"

    def _extract_tag_name(self, packet):
        """Extract tag name for Rockwell tag operations"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'tag_name'):
                return packet.cip.tag_name
        except:
            pass
        return "N/A"

    def _extract_safety_state(self, packet):
        """Extract safety state information"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'safety_state'):
                return packet.cip.safety_state
        except:
            pass
        return "N/A"

    def _extract_axis_info(self, packet):
        """Extract motion axis information"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'axis_id'):
                return f"Axis {packet.cip.axis_id}"
        except:
            pass
        return "N/A"

    def _extract_sync_time(self, packet):
        """Extract synchronization time"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'sync_time'):
                return packet.cip.sync_time
        except:
            pass
        return "N/A"

    def _extract_energy_data(self, packet):
        """Extract energy-related data"""
        try:
            if hasattr(packet, 'cip') and hasattr(packet.cip, 'energy_value'):
                return packet.cip.energy_value
        except:
            pass
        return "N/A"