"""
MITRE EMBED Framework Integration
Provides device property assessment and mapping functionality
"""

import json
import logging
from typing import Dict, List, Any

class MitreEmbedIntegrator:
    """Integration with MITRE EMBED framework for IoT/embedded device security"""
    
    # MITRE EMBED Device Properties Structure - Hierarchical PID Format
    DEVICE_PROPERTIES = {
        "Hardware": {
            "PID-11": { "label": "Device includes a microprocessor" },
            "PID-12": {
                "label": "Device includes Memory/Storage (external to CPU)",
                "children": {
                    "PID-121": { "label": "Device includes buses for external memory/storage" },
                    "PID-122": { "label": "Device includes discrete chips/devices that have access to the same physical memory" },
                    "PID-123": { "label": "Device includes ROM, VRAM, or removable Storage" },
                    "PID-124": {
                        "label": "Device includes Random Access Memory (RAM) chips",
                        "children": {
                            "PID-1241": { "label": "Device includes DDR DRAM" }
                        }
                    }
                }
            },
            "PID-13": { "label": "Device includes peripheral chips and integrated data buses" },
            "PID-14": { "label": "Device includes external peripheral interconnects (e.g., USB, Serial)" },
            "PID-15": { "label": "Device includes a hardware access port (e.g., UART, JTAG)" }
        },
        "System Software": {
            "PID-21": { "label": "Device includes a bootloader" },
            "PID-22": { "label": "Device includes a debugging capabilities" },
            "PID-23": { "label": "Device includes OS/kernel" },
            "PID-231": { "label": "Device includes an operating system that uses drivers/modules that can be loaded" },
            "PID-232": {
                "label": "Device includes separate users/processes with access to different OS data or functions",
                "children": {
                    "PID-2321": { "label": "Device lacks an access enforcement/privilege mechanism" },
                    "PID-2322": {
                        "label": "Device deploys an access enforcement/privilege mechanism",
                        "children": {
                            "PID-23221": { "label": "Device includes and enforces OS user accounts" },
                            "PID-23222": { "label": "Device includes a memory management model, including protections of memory access (read-only, executable, writable)" }
                        }
                    }
                }
            },
            "PID-24": {
                "label": "Device includes virtualization and containers",
                "children": {
                    "PID-241": { "label": "Device includes containers" },
                    "PID-242": { "label": "Device includes hypervisor" }
                }
            },
            "PID-25": {
                "label": "Device includes software/hardware root of trust",
                "children": {
                    "PID-251": { "label": "Root of Trust is physically accessible or is not immutable" },
                    "PID-252": { "label": "Root of Trust is immutable" }
                }
            },
            "PID-26": { "label": "Device lacks firmware/software update support" },
            "PID-27": {
                "label": "Device includes support for firmware/software updates",
                "children": {
                    "PID-271": { "label": "Device has firmware or software that is not cryptographically checked for integrity validation" },
                    "PID-272": {
                        "label": "Device includes cryptographic firmware/software integrity protection mechanisms",
                        "children": {
                            "PID-2721": { "label": "Device includes a shared key for firmware integrity validation" },
                            "PID-2722": { "label": "Device includes digitally signed firmware (with private key)" }
                        }
                    },
                    "PID-273": { "label": "Device has unencrypted firmware updates" },
                    "PID-274": { "label": "Device includes user firmware/software version selection during updates" },
                    "PID-275": { "label": "Device includes remotely-initiated firmware/software updates" }
                }
            },
            "PID-28": { "label": "Device stores logs of system events and information" }
        },
        "Application Software": {
            "PID-31": { "label": "Application-level software is present and running on the device" },
            "PID-311": { "label": "Device includes the usage of a web/HTTP applications" },
            "PID-312": {
                "label": "Device includes programming languages and libraries",
                "children": {
                    "PID-3121": { "label": "Device includes support for object oriented programming languages (e.g., Java, Python, PHP, C++)" },
                    "PID-3122": { "label": "Device includes support for manual memory management programming languages (e.g., C, C++)" }
                }
            },
            "PID-32": {
                "label": "Device includes the ability to deploy custom or external programs",
                "children": {
                    "PID-321": { "label": "Device includes ability to deploy custom programs from engineering software or IDE" },
                    "PID-322": { "label": "Device includes a program runtime environment for custom or external programs" },
                    "PID-323": {
                        "label": "Device includes support for program executable formats",
                        "children": {
                            "PID-3231": { "label": "Device includes ability to run custom/external programs as native binary without a confined/restricted environment" },
                            "PID-3232": { "label": "Device includes ability to run custom/external programs/processes through an execution sandboxed environment" }
                        }
                    },
                    "PID-324": { "label": "Device includes support for 'program uploads' to retrieve programs from the device from an engineering workstation" }
                }
            },
            "PID-33": {
                "label": "Device includes interactive applications, services, or user interfaces",
                "children": {
                    "PID-331": { "label": "Device includes unauthenticated services" },
                    "PID-332": {
                        "label": "Device includes authenticated services",
                        "children": {
                            "PID-3321": { "label": "Device includes passwords to authenticate the users" },
                            "PID-3322": { "label": "Device includes cryptographic mechanism to authenticate users and sessions" }
                        }
                    }
                }
            },
            "PID-34": { "label": "Device stores logs of application events and information" }
        },
        "Networking": {
            "PID-41": { "label": "Device exposes remote network services" },
            "PID-411": {
                "label": "Device exposes remote services with the ability to send, receive, view or modify sensitive information or configurations",
                "children": {
                    "PID-4111": { "label": "Device lacks protocol support for message authentication" },
                    "PID-4112": { "label": "Device lacks protocol support for message encryption" },
                    "PID-4113": { "label": "Device includes cryptographic functions for sensitive data, such as encryption or authentication" }
                }
            },
            "PID-42": { "label": "Device includes procedure to forward or route network messages" }
        }
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_device_properties_form(self) -> Dict[str, Any]:
        """Return the complete device properties structure for form generation"""
        return self.DEVICE_PROPERTIES

    def get_flat_properties_for_desktop(self) -> Dict[str, Dict[str, str]]:
        """Return flattened properties structure for desktop app compatibility"""
        flat_props = {}
        
        def flatten_properties(props_dict, category_key):
            """Recursively flatten nested properties"""
            result = {}
            for pid, prop_data in props_dict.items():
                if isinstance(prop_data, dict):
                    if "label" in prop_data:
                        result[pid] = prop_data["label"]
                        # Add children if they exist
                        if "children" in prop_data:
                            children_flat = flatten_properties(prop_data["children"], category_key)
                            result.update(children_flat)
                    else:
                        # Old format compatibility
                        result[pid] = prop_data
            return result
        
        for category, props in self.DEVICE_PROPERTIES.items():
            category_key = category.lower().replace(" ", "_")
            flat_props[category_key] = flatten_properties(props, category_key)
        
        return flat_props
    
    def assess_device_properties(self, selected_properties: Dict[str, List[str]]) -> Dict[str, Any]:
        """Assess device based on selected properties and return security implications"""
        assessment = {
            'selected_properties': selected_properties,
            'security_implications': {},
            'threat_vectors': [],
            'recommended_controls': []
        }
        
        # Analyze each category
        for category, properties in selected_properties.items():
            if category in self.DEVICE_PROPERTIES:
                assessment['security_implications'][category] = self._analyze_category_security(
                    category, properties
                )
        
        # Generate threat vectors based on selected properties
        assessment['threat_vectors'] = self._generate_threat_vectors(selected_properties)
        
        # Generate recommended controls
        assessment['recommended_controls'] = self._generate_embed_controls(selected_properties)
        
        return assessment
    
    def _analyze_category_security(self, category: str, selected_properties: List[str]) -> Dict[str, Any]:
        """Analyze security implications for a specific category"""
        implications = {
            'attack_surface': 'low',
            'risk_factors': [],
            'vulnerabilities': []
        }
        
        # Category-specific analysis
        if category == 'hardware':
            implications.update(self._analyze_hardware_security(selected_properties))
        elif category == 'system_software':
            implications.update(self._analyze_system_software_security(selected_properties))
        elif category == 'application_software':
            implications.update(self._analyze_application_security(selected_properties))
        elif category == 'networking':
            implications.update(self._analyze_networking_security(selected_properties))
        
        return implications
    
    def _analyze_hardware_security(self, properties: List[str]) -> Dict[str, Any]:
        """Analyze hardware-specific security implications"""
        attack_surface = 'low'
        risk_factors = []
        vulnerabilities = []
        
        if 'PID-19' in properties:  # Physical interfaces
            attack_surface = 'medium'
            risk_factors.append('Physical access vectors')
            vulnerabilities.append('Hardware tampering')
        
        if 'PID-22' in properties:  # Debugging capabilities
            attack_surface = 'high'
            risk_factors.append('Debug port exploitation')
            vulnerabilities.append('Firmware extraction')
        
        if 'PID-110' in properties:  # Wireless hardware
            attack_surface = 'medium'
            risk_factors.append('Wireless attack vectors')
            vulnerabilities.append('RF interference attacks')
        
        return {
            'attack_surface': attack_surface,
            'risk_factors': risk_factors,
            'vulnerabilities': vulnerabilities
        }
    
    def _analyze_system_software_security(self, properties: List[str]) -> Dict[str, Any]:
        """Analyze system software security implications"""
        attack_surface = 'low'
        risk_factors = []
        vulnerabilities = []
        
        if 'PID-22' in properties:  # Debugging capabilities
            attack_surface = 'high'
            risk_factors.append('Debug interface access')
            vulnerabilities.append('System-level debugging exploitation')
        
        if 'PID-28' in properties:  # Update mechanisms
            risk_factors.append('Update process vulnerabilities')
            vulnerabilities.append('Malicious update injection')
        
        if 'PID-23' in properties:  # Operating system
            attack_surface = 'medium'
            risk_factors.append('OS-level vulnerabilities')
            vulnerabilities.append('Privilege escalation')
        
        return {
            'attack_surface': attack_surface,
            'risk_factors': risk_factors,
            'vulnerabilities': vulnerabilities
        }
    
    def _analyze_application_security(self, properties: List[str]) -> Dict[str, Any]:
        """Analyze application software security implications"""
        attack_surface = 'low'
        risk_factors = []
        vulnerabilities = []
        
        if 'PID-311' in properties:  # Web/HTTP applications
            attack_surface = 'high'
            risk_factors.append('Web application vulnerabilities')
            vulnerabilities.extend(['XSS', 'SQL Injection', 'CSRF'])
        
        if 'PID-313' in properties:  # Third-party components
            attack_surface = 'medium'
            risk_factors.append('Third-party vulnerability dependencies')
            vulnerabilities.append('Supply chain attacks')
        
        if 'PID-319' in properties:  # API interfaces
            attack_surface = 'high'
            risk_factors.append('API security vulnerabilities')
            vulnerabilities.extend(['API abuse', 'Authentication bypass'])
        
        return {
            'attack_surface': attack_surface,
            'risk_factors': risk_factors,
            'vulnerabilities': vulnerabilities
        }
    
    def _analyze_networking_security(self, properties: List[str]) -> Dict[str, Any]:
        """Analyze networking security implications"""
        attack_surface = 'low'
        risk_factors = []
        vulnerabilities = []
        
        if 'PID-41' in properties:  # Remote network services
            attack_surface = 'high'
            risk_factors.append('Remote attack vectors')
            vulnerabilities.extend(['Network service exploitation', 'DDoS attacks'])
        
        if 'PID-412' in properties:  # Wireless networking
            attack_surface = 'high'
            risk_factors.append('Wireless security vulnerabilities')
            vulnerabilities.extend(['Man-in-the-middle', 'Eavesdropping'])
        
        if 'PID-418' in properties:  # Cloud connectivity
            attack_surface = 'medium'
            risk_factors.append('Cloud security dependencies')
            vulnerabilities.append('Cloud service vulnerabilities')
        
        return {
            'attack_surface': attack_surface,
            'risk_factors': risk_factors,
            'vulnerabilities': vulnerabilities
        }
    
    def _generate_threat_vectors(self, selected_properties: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Generate threat vectors based on selected device properties"""
        threat_vectors = []
        
        # Physical threats
        if any('PID-19' in props for props in selected_properties.values()):
            threat_vectors.append({
                'category': 'Physical',
                'threat': 'Hardware Tampering',
                'description': 'Unauthorized physical access to device interfaces',
                'severity': 'High'
            })
        
        # Network threats
        network_props = selected_properties.get('networking', [])
        if 'PID-41' in network_props:
            threat_vectors.append({
                'category': 'Network',
                'threat': 'Remote Code Execution',
                'description': 'Exploitation of network services',
                'severity': 'Critical'
            })
        
        # Application threats
        app_props = selected_properties.get('application_software', [])
        if 'PID-311' in app_props:
            threat_vectors.append({
                'category': 'Application',
                'threat': 'Web Application Attacks',
                'description': 'Common web vulnerabilities exploitation',
                'severity': 'High'
            })
        
        return threat_vectors
    
    def _generate_embed_controls(self, selected_properties: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Generate recommended cybersecurity controls based on MITRE EMBED"""
        controls = []
        
        # Hardware controls
        hardware_props = selected_properties.get('hardware', [])
        if 'PID-19' in hardware_props:  # Physical interfaces
            controls.append({
                'id': 'EMBED-HW-01',
                'control': 'Physical Access Control',
                'description': 'Implement physical security measures for device interfaces',
                'category': 'Hardware'
            })
        
        # System software controls
        system_props = selected_properties.get('system_software', [])
        if 'PID-22' in system_props:  # Debugging capabilities
            controls.append({
                'id': 'EMBED-SW-01',
                'control': 'Debug Interface Security',
                'description': 'Secure or disable debug interfaces in production',
                'category': 'System Software'
            })
        
        # Application controls
        app_props = selected_properties.get('application_software', [])
        if 'PID-311' in app_props:  # Web applications
            controls.append({
                'id': 'EMBED-APP-01',
                'control': 'Web Application Security',
                'description': 'Implement secure coding practices and input validation',
                'category': 'Application Software'
            })
        
        # Network controls
        network_props = selected_properties.get('networking', [])
        if 'PID-41' in network_props:  # Network services
            controls.append({
                'id': 'EMBED-NET-01',
                'control': 'Network Service Hardening',
                'description': 'Secure configuration and monitoring of network services',
                'category': 'Networking'
            })
        
        return controls