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
    
    def assess_device_properties(self, selected_properties: List[str]) -> Dict[str, Any]:
        """Assess device based on selected properties and return security implications"""
        assessment = {
            'selected_properties': selected_properties,
            'security_implications': {},
            'threat_vectors': [],
            'recommended_controls': []
        }
        
        # Categorize properties by type
        categorized_props = self._categorize_properties(selected_properties)
        
        # Analyze each category
        for category, properties in categorized_props.items():
            assessment['security_implications'][category] = self._analyze_category_security(
                category, properties
            )
        
        # Generate threat vectors based on selected properties
        assessment['threat_vectors'] = self._generate_threat_vectors(categorized_props)
        
        # Generate recommended controls
        assessment['recommended_controls'] = self._generate_embed_controls(categorized_props)
        
        return assessment
    
    def _categorize_properties(self, selected_properties: List[str]) -> Dict[str, List[str]]:
        """Categorize properties by type"""
        categorized = {
            'hardware': [],
            'system_software': [],
            'application_software': [],
            'networking': []
        }
        
        for prop in selected_properties:
            for category, props in self.DEVICE_PROPERTIES.items():
                if prop in props:
                    categorized[category].append(prop)
                    break
                    
        return categorized
    
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
        """Analyze system software-specific security implications"""
        attack_surface = 'low'
        risk_factors = []
        vulnerabilities = []
        
        if 'PID-22' in properties:  # Debugging capabilities
            attack_surface = 'high'
            risk_factors.append('Debug interface exploitation')
            vulnerabilities.append('Memory dump attacks')
        
        if 'PID-23' in properties:  # Operating system
            attack_surface = 'medium'
            risk_factors.append('OS-level attacks')
            vulnerabilities.append('Privilege escalation')
        
        if 'PID-28' in properties:  # Update mechanisms
            risk_factors.append('Update channel compromise')
            vulnerabilities.append('Supply chain attacks')
        
        return {
            'attack_surface': attack_surface,
            'risk_factors': risk_factors,
            'vulnerabilities': vulnerabilities
        }
    
    def _analyze_application_security(self, properties: List[str]) -> Dict[str, Any]:
        """Analyze application software-specific security implications"""
        attack_surface = 'low'
        risk_factors = []
        vulnerabilities = []
        
        if 'PID-311' in properties:  # Web applications
            attack_surface = 'high'
            risk_factors.append('Web application attacks')
            vulnerabilities.append('OWASP Top 10 vulnerabilities')
        
        if 'PID-319' in properties:  # API interfaces
            attack_surface = 'medium'
            risk_factors.append('API security issues')
            vulnerabilities.append('Broken authentication')
        
        return {
            'attack_surface': attack_surface,
            'risk_factors': risk_factors,
            'vulnerabilities': vulnerabilities
        }
    
    def _analyze_networking_security(self, properties: List[str]) -> Dict[str, Any]:
        """Analyze networking-specific security implications"""
        attack_surface = 'low'
        risk_factors = []
        vulnerabilities = []
        
        if 'PID-41' in properties:  # Remote network services
            attack_surface = 'high'
            risk_factors.append('Remote exploitation')
            vulnerabilities.append('Network service vulnerabilities')
        
        if 'PID-412' in properties:  # Wireless networking
            attack_surface = 'medium'
            risk_factors.append('Wireless attacks')
            vulnerabilities.append('Man-in-the-middle attacks')
        
        if 'PID-418' in properties:  # Cloud connectivity
            risk_factors.append('Cloud security issues')
            vulnerabilities.append('Data exposure in cloud')
        
        return {
            'attack_surface': attack_surface,
            'risk_factors': risk_factors,
            'vulnerabilities': vulnerabilities
        }
    
    def _generate_threat_vectors(self, categorized_props: Dict[str, List[str]]) -> List[Dict[str, str]]:
        """Generate threat vectors based on selected properties"""
        threat_vectors = []
        
        # Hardware threats
        if categorized_props['hardware']:
            if 'PID-19' in categorized_props['hardware']:
                threat_vectors.append({
                    'vector': 'Physical Access',
                    'description': 'Attacker gains physical access to device interfaces',
                    'impact': 'High'
                })
            if 'PID-110' in categorized_props['hardware']:
                threat_vectors.append({
                    'vector': 'RF Attacks',
                    'description': 'Radio frequency interference or jamming attacks',
                    'impact': 'Medium'
                })
        
        # Network threats
        if categorized_props['networking']:
            if 'PID-41' in categorized_props['networking']:
                threat_vectors.append({
                    'vector': 'Remote Exploitation',
                    'description': 'Remote attacks through network services',
                    'impact': 'Critical'
                })
            if 'PID-412' in categorized_props['networking']:
                threat_vectors.append({
                    'vector': 'Wireless Interception',
                    'description': 'Wireless communication interception',
                    'impact': 'High'
                })
        
        return threat_vectors
    
    def _generate_embed_controls(self, categorized_props: Dict[str, List[str]]) -> List[Dict[str, str]]:
        """Generate recommended EMBED security controls"""
        controls = []
        
        # Hardware controls
        if categorized_props['hardware']:
            controls.append({
                'control_id': 'EMB3D-HW-01',
                'control_name': 'Hardware Security Module',
                'description': 'Implement hardware-based cryptographic protection',
                'category': 'Hardware'
            })
            
            if 'PID-17' not in categorized_props['hardware']:
                controls.append({
                    'control_id': 'EMB3D-HW-02',
                    'control_name': 'Tamper Detection',
                    'description': 'Implement tamper detection and response mechanisms',
                    'category': 'Hardware'
                })
        
        # System software controls
        if categorized_props['system_software']:
            controls.append({
                'control_id': 'EMB3D-SYS-01',
                'control_name': 'Secure Boot',
                'description': 'Implement secure boot chain verification',
                'category': 'System Software'
            })
            
            if 'PID-28' in categorized_props['system_software']:
                controls.append({
                    'control_id': 'EMB3D-SYS-02',
                    'control_name': 'Secure Update',
                    'description': 'Implement secure software update mechanisms',
                    'category': 'System Software'
                })
        
        # Network controls
        if categorized_props['networking']:
            controls.append({
                'control_id': 'EMB3D-NET-01',
                'control_name': 'Network Encryption',
                'description': 'Implement end-to-end network encryption',
                'category': 'Network'
            })
            
            if 'PID-415' not in categorized_props['networking']:
                controls.append({
                    'control_id': 'EMB3D-NET-02',
                    'control_name': 'Network Authentication',
                    'description': 'Implement strong network authentication',
                    'category': 'Network'
                })
        
        return controls
    
    def process_embed_json(self, embed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process a MITRE EMBED JSON file and extract assessment data"""
        assessment = {
            'selected_properties': [],
            'security_implications': {},
            'threat_vectors': [],
            'recommended_controls': [],
            'assets': []
        }
        
        # Extract properties from JSON structure
        if 'properties' in embed_data:
            assessment['selected_properties'] = embed_data['properties']
        elif 'selected_properties' in embed_data:
            assessment['selected_properties'] = embed_data['selected_properties']
        
        # Extract assets if present
        if 'assets' in embed_data:
            assessment['assets'] = embed_data['assets']
        
        # If we have properties, run the assessment
        if assessment['selected_properties']:
            property_assessment = self.assess_device_properties(assessment['selected_properties'])
            assessment.update(property_assessment)
        
        return assessment