"""
MITRE EMBED Framework Integration
Provides device property assessment and mapping functionality
"""

import json
import logging
from typing import Dict, List, Any

class MitreEmbedIntegrator:
    """Integration with MITRE EMBED framework for IoT/embedded device security"""
    
    # MITRE EMBED Device Properties Structure
    DEVICE_PROPERTIES = {
        'hardware': {
            'PID-11': 'Device includes a microprocessor',
            'PID-12': 'Device includes Memory/Storage (external to CPU)',
            'PID-13': 'Device includes firmware/BIOS',
            'PID-14': 'Device includes hardware security module (HSM)',
            'PID-15': 'Device includes cryptographic processor',
            'PID-16': 'Device includes hardware random number generator',
            'PID-17': 'Device includes tamper detection/response mechanisms',
            'PID-18': 'Device includes secure boot capabilities',
            'PID-19': 'Device includes physical interfaces (USB, serial, etc.)',
            'PID-110': 'Device includes wireless communication hardware'
        },
        'system_software': {
            'PID-21': 'Device includes a bootloader',
            'PID-22': 'Device includes debugging capabilities',
            'PID-23': 'Device includes operating system',
            'PID-24': 'Device includes device drivers',
            'PID-25': 'Device includes system services/daemons',
            'PID-26': 'Device includes configuration management',
            'PID-27': 'Device includes logging and monitoring',
            'PID-28': 'Device includes update/patch mechanisms',
            'PID-29': 'Device includes access control mechanisms',
            'PID-210': 'Device includes cryptographic libraries'
        },
        'application_software': {
            'PID-31': 'Application-level software is present and running on the device',
            'PID-311': 'Device includes the usage of web/HTTP applications',
            'PID-312': 'Device includes mobile applications',
            'PID-313': 'Device includes third-party software components',
            'PID-314': 'Device includes custom/proprietary applications',
            'PID-315': 'Device includes data processing applications',
            'PID-316': 'Device includes user interface applications',
            'PID-317': 'Device includes communication protocols',
            'PID-318': 'Device includes database management',
            'PID-319': 'Device includes API interfaces',
            'PID-320': 'Device includes machine learning/AI components'
        },
        'networking': {
            'PID-41': 'Device exposes remote network services',
            'PID-411': 'Device exposes remote services with the ability to send, receive, view, or modify sensitive information or configurations',
            'PID-412': 'Device supports wireless networking (WiFi, Bluetooth, cellular)',
            'PID-413': 'Device supports wired networking (Ethernet)',
            'PID-414': 'Device includes network security protocols (TLS, VPN)',
            'PID-415': 'Device includes network authentication mechanisms',
            'PID-416': 'Device includes network monitoring capabilities',
            'PID-417': 'Device includes firewall or filtering capabilities',
            'PID-418': 'Device supports cloud connectivity',
            'PID-419': 'Device supports peer-to-peer networking',
            'PID-420': 'Device includes network time synchronization'
        }
    }

    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def get_device_properties_form(self) -> Dict[str, Dict[str, str]]:
        """Return the complete device properties structure for form generation"""
        return self.DEVICE_PROPERTIES
    
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