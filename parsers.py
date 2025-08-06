"""
EMB3D CSV Heatmap Parser
Simplified parser for MITRE EMB3D CSV heatmap files only
"""

import csv
import logging
from typing import Dict, List, Any, Optional


class Embed3dCsvParser:
    """Parser for EMB3D CSV heatmap files exported from MITRE EMB3D website"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse EMB3D CSV heatmap file and extract device properties and assessment data"""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                rows = list(reader)
            
            return self._normalize_embed3d_data(rows)
        
        except Exception as e:
            self.logger.error(f"Failed to parse EMB3D CSV heatmap: {e}")
            raise
    
    def _normalize_embed3d_data(self, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Normalize EMB3D CSV data to standard format"""
        normalized = {
            'selected_properties': {},
            'assessment_data': {},
            'threat_vectors': [],
            'recommended_controls': [],
            'metadata': {
                'source': 'embed3d_csv_heatmap',
                'input_type': 'mitre_embed_csv'
            }
        }
        
        # Extract device properties from EMB3D CSV structure
        selected_properties = {}
        
        for row in rows:
            # Check if property is selected (TRUE in CSV)
            if str(row.get('Selected', '')).upper() == 'TRUE':
                category = row.get('Category', 'Unknown')
                prop_id = row.get('Property ID', '')
                prop_name = row.get('Property Name', '')
                
                if category not in selected_properties:
                    selected_properties[category] = {}
                
                selected_properties[category][prop_id] = prop_name
        
        normalized['selected_properties'] = selected_properties
        
        # For CSV heatmaps, convert to simplified property structure for MitreEmbedIntegrator
        normalized['device_properties'] = self._convert_to_device_properties(selected_properties)
        
        # Add basic assessment data from CSV
        normalized['assessment_data'] = {
            'total_properties': len(rows),
            'selected_properties_count': sum(len(props) for props in selected_properties.values()),
            'categories': list(selected_properties.keys())
        }
        
        self.logger.info(f"Parsed EMB3D CSV with {len(normalized['selected_properties'])} property categories")
        return normalized
    
    def _convert_to_device_properties(self, selected_properties: Dict[str, Any]) -> Dict[str, List[str]]:
        """Convert CSV property structure to device properties format expected by MitreEmbedIntegrator"""
        device_properties = {
            'hardware': [],
            'system_software': [],
            'application_software': [],
            'networking': []
        }
        
        # Map CSV categories to device property categories
        category_mapping = {
            'Hardware Platform': 'hardware',
            'Software Platform': 'system_software', 
            'Data': 'system_software',
            'Communication': 'networking',
            'Lifecycle': 'hardware'
        }
        
        for csv_category, properties in selected_properties.items():
            target_category = category_mapping.get(csv_category, 'hardware')
            for prop_id, prop_name in properties.items():
                device_properties[target_category].append(prop_id)
        
        return device_properties
    
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