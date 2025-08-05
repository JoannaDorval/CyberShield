"""
EMB3D JSON Heatmap Parser
Simplified parser for MITRE EMB3D JSON heatmap files only
"""

import json
import logging
from typing import Dict, List, Any, Optional


class Embed3dJsonParser:
    """Parser for MITRE EMB3D JSON heatmap files exported from the EMB3D website"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse EMB3D JSON heatmap file and extract device properties and assessment data"""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            return self._normalize_embed3d_data(data)
        
        except Exception as e:
            self.logger.error(f"Failed to parse EMB3D JSON heatmap: {e}")
            raise
    
    def _normalize_embed3d_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize EMB3D JSON data to standard format"""
        normalized = {
            'selected_properties': {},
            'assessment_data': {},
            'threat_vectors': [],
            'recommended_controls': [],
            'metadata': {
                'source': 'embed3d_json_heatmap',
                'input_type': 'mitre_embed_json'
            }
        }
        
        # Extract device properties from EMB3D JSON structure
        if 'properties' in data:
            normalized['selected_properties'] = self._extract_device_properties(data['properties'])
        elif 'device_properties' in data:
            normalized['selected_properties'] = self._extract_device_properties(data['device_properties'])
        elif 'embed_properties' in data:
            normalized['selected_properties'] = self._extract_device_properties(data['embed_properties'])
        
        # Extract assessment data if present
        if 'assessment' in data:
            normalized['assessment_data'] = data['assessment']
        elif 'analysis' in data:
            normalized['assessment_data'] = data['analysis']
        
        # Extract threat information
        if 'threats' in data:
            normalized['threat_vectors'] = self._extract_threats(data['threats'])
        elif 'threat_vectors' in data:
            normalized['threat_vectors'] = self._extract_threats(data['threat_vectors'])
        
        # Extract controls/mitigations
        if 'controls' in data:
            normalized['recommended_controls'] = self._extract_controls(data['controls'])
        elif 'mitigations' in data:
            normalized['recommended_controls'] = self._extract_controls(data['mitigations'])
        elif 'recommended_controls' in data:
            normalized['recommended_controls'] = self._extract_controls(data['recommended_controls'])
        
        # Extract metadata
        if 'metadata' in data:
            normalized['metadata'].update(data['metadata'])
        
        self.logger.info(f"Parsed EMB3D JSON with {len(normalized['selected_properties'])} property categories")
        return normalized
    
    def _extract_device_properties(self, properties_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract device properties organized by category"""
        properties = {
            'hardware': [],
            'system_software': [],
            'application_software': [],
            'networking': []
        }
        
        # Handle different JSON structures
        if isinstance(properties_data, dict):
            for key, value in properties_data.items():
                # Determine category based on property ID or key
                category = self._determine_property_category(key)
                
                if isinstance(value, bool) and value:
                    # Property is selected (boolean true)
                    properties[category].append(key)
                elif isinstance(value, list):
                    # List of selected properties
                    properties[category].extend(value)
                elif isinstance(value, dict) and value.get('selected', False):
                    # Property object with selection status
                    properties[category].append(key)
        
        elif isinstance(properties_data, list):
            # List of property objects
            for prop in properties_data:
                if isinstance(prop, dict):
                    prop_id = prop.get('id', prop.get('property_id', ''))
                    if prop_id and prop.get('selected', False):
                        category = self._determine_property_category(prop_id)
                        properties[category].append(prop_id)
        
        return properties
    
    def _determine_property_category(self, property_id: str) -> str:
        """Determine the category of a property based on its ID"""
        if property_id.startswith('PID-1'):
            return 'hardware'
        elif property_id.startswith('PID-2'):
            return 'system_software'
        elif property_id.startswith('PID-3'):
            return 'application_software'
        elif property_id.startswith('PID-4'):
            return 'networking'
        else:
            # Default fallback based on common keywords
            prop_lower = property_id.lower()
            if any(term in prop_lower for term in ['hardware', 'hw', 'device', 'microprocessor', 'memory']):
                return 'hardware'
            elif any(term in prop_lower for term in ['system', 'os', 'bootloader', 'driver']):
                return 'system_software'
            elif any(term in prop_lower for term in ['app', 'application', 'software', 'web', 'api']):
                return 'application_software'
            elif any(term in prop_lower for term in ['network', 'networking', 'wireless', 'ethernet']):
                return 'networking'
            else:
                return 'hardware'  # Default fallback
    
    def _extract_threats(self, threats_data: List[Dict]) -> List[Dict]:
        """Extract threat information from EMB3D JSON"""
        threats = []
        
        if isinstance(threats_data, list):
            for threat in threats_data:
                if isinstance(threat, dict):
                    normalized_threat = {
                        'id': threat.get('id', threat.get('threat_id', '')),
                        'name': threat.get('name', threat.get('title', '')),
                        'description': threat.get('description', ''),
                        'category': threat.get('category', threat.get('type', '')),
                        'severity': threat.get('severity', threat.get('impact', 'Unknown')),
                        'likelihood': threat.get('likelihood', threat.get('probability', 'Unknown')),
                        'attack_vectors': threat.get('attack_vectors', []),
                        'affected_properties': threat.get('affected_properties', [])
                    }
                    threats.append(normalized_threat)
        
        return threats
    
    def _extract_controls(self, controls_data: List[Dict]) -> List[Dict]:
        """Extract control/mitigation information from EMB3D JSON"""
        controls = []
        
        if isinstance(controls_data, list):
            for control in controls_data:
                if isinstance(control, dict):
                    normalized_control = {
                        'id': control.get('id', control.get('control_id', '')),
                        'name': control.get('name', control.get('title', '')),
                        'description': control.get('description', ''),
                        'type': control.get('type', control.get('category', '')),
                        'effectiveness': control.get('effectiveness', 'Unknown'),
                        'implementation_guidance': control.get('implementation_guidance', 
                                                             control.get('guidance', '')),
                        'addresses_properties': control.get('addresses_properties', []),
                        'mitre_controls': control.get('mitre_controls', [])
                    }
                    controls.append(normalized_control)
        
        return controls