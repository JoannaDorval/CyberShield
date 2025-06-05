import json
import yaml
import os
import logging
from PIL import Image
import xml.etree.ElementTree as ET
from typing import Dict, List, Any

class ThreatModelParser:
    """Parser for threat model files (JSON/YAML)"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse threat model file and extract relevant data"""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                # Determine file type and parse accordingly
                if filepath.lower().endswith('.json'):
                    data = json.load(file)
                elif filepath.lower().endswith(('.yaml', '.yml')):
                    data = yaml.safe_load(file)
                else:
                    raise ValueError("Unsupported file format")
            
            # Extract and normalize threat model data
            return self._normalize_threat_model(data)
        
        except Exception as e:
            self.logger.error(f"Failed to parse threat model: {e}")
            raise

    def _normalize_threat_model(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize threat model data to standard format"""
        normalized = {
            'threats': [],
            'assets': [],
            'risks': [],
            'mitigations': []
        }
        
        # Handle different threat model formats
        if 'threats' in data:
            normalized['threats'] = self._extract_threats(data['threats'])
        elif 'threat_list' in data:
            normalized['threats'] = self._extract_threats(data['threat_list'])
        
        if 'assets' in data:
            normalized['assets'] = self._extract_assets(data['assets'])
        elif 'asset_list' in data:
            normalized['assets'] = self._extract_assets(data['asset_list'])
        
        if 'risks' in data:
            normalized['risks'] = self._extract_risks(data['risks'])
        elif 'risk_list' in data:
            normalized['risks'] = self._extract_risks(data['risk_list'])
        
        if 'mitigations' in data:
            normalized['mitigations'] = self._extract_mitigations(data['mitigations'])
        elif 'mitigation_list' in data:
            normalized['mitigations'] = self._extract_mitigations(data['mitigation_list'])
        elif 'controls' in data:
            normalized['mitigations'] = self._extract_mitigations(data['controls'])
        
        return normalized
    
    def _extract_threats(self, threats_data: List[Dict]) -> List[Dict]:
        """Extract and normalize threat information"""
        threats = []
        for threat in threats_data:
            normalized_threat = {
                'id': threat.get('id', ''),
                'name': threat.get('name', threat.get('title', '')),
                'description': threat.get('description', ''),
                'category': threat.get('category', threat.get('type', '')),
                'severity': threat.get('severity', threat.get('impact', 'Unknown')),
                'likelihood': threat.get('likelihood', threat.get('probability', 'Unknown')),
                'affected_assets': threat.get('affected_assets', threat.get('assets', [])),
                'attack_vectors': threat.get('attack_vectors', threat.get('vectors', [])),
                'references': threat.get('references', [])
            }
            threats.append(normalized_threat)
        return threats
    
    def _extract_assets(self, assets_data: List[Dict]) -> List[Dict]:
        """Extract and normalize asset information"""
        assets = []
        for asset in assets_data:
            normalized_asset = {
                'id': asset.get('id', ''),
                'name': asset.get('name', ''),
                'type': asset.get('type', asset.get('category', '')),
                'description': asset.get('description', ''),
                'criticality': asset.get('criticality', asset.get('importance', 'Medium')),
                'location': asset.get('location', ''),
                'dependencies': asset.get('dependencies', []),
                'security_requirements': asset.get('security_requirements', {})
            }
            assets.append(normalized_asset)
        return assets
    
    def _extract_risks(self, risks_data: List[Dict]) -> List[Dict]:
        """Extract and normalize risk information"""
        risks = []
        for risk in risks_data:
            normalized_risk = {
                'id': risk.get('id', ''),
                'name': risk.get('name', ''),
                'description': risk.get('description', ''),
                'threat_id': risk.get('threat_id', ''),
                'asset_id': risk.get('asset_id', ''),
                'impact': risk.get('impact', 'Unknown'),
                'likelihood': risk.get('likelihood', 'Unknown'),
                'risk_score': risk.get('risk_score', risk.get('score', 0)),
                'existing_controls': risk.get('existing_controls', [])
            }
            risks.append(normalized_risk)
        return risks
    
    def _extract_mitigations(self, mitigations_data: List[Dict]) -> List[Dict]:
        """Extract and normalize mitigation information"""
        mitigations = []
        for mitigation in mitigations_data:
            normalized_mitigation = {
                'id': mitigation.get('id', ''),
                'name': mitigation.get('name', ''),
                'description': mitigation.get('description', ''),
                'type': mitigation.get('type', mitigation.get('category', '')),
                'effectiveness': mitigation.get('effectiveness', 'Unknown'),
                'implementation_cost': mitigation.get('implementation_cost', mitigation.get('cost', 'Unknown')),
                'addresses_threats': mitigation.get('addresses_threats', mitigation.get('threats', [])),
                'addresses_risks': mitigation.get('addresses_risks', mitigation.get('risks', [])),
                'implementation_notes': mitigation.get('implementation_notes', '')
            }
            mitigations.append(normalized_mitigation)
        return mitigations


class BlockDiagramParser:
    """Parser for block diagram files (SVG/PNG)"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse block diagram and extract components and data flows"""
        try:
            file_ext = os.path.splitext(filepath)[1].lower()
            
            if file_ext == '.svg':
                return self._parse_svg(filepath)
            elif file_ext in ['.png', '.jpg', '.jpeg']:
                return self._parse_image(filepath)
            else:
                raise ValueError("Unsupported diagram format")
        
        except Exception as e:
            self.logger.error(f"Failed to parse block diagram: {e}")
            raise
    
    def _parse_svg(self, filepath: str) -> Dict[str, Any]:
        """Parse SVG diagram for components and connections"""
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
            
            components = []
            connections = []
            
            # Look for text elements that might represent components
            for text in root.iter():
                if text.tag.endswith('text') and text.text:
                    components.append({
                        'name': text.text.strip(),
                        'type': 'component',
                        'position': {
                            'x': text.get('x', '0'),
                            'y': text.get('y', '0')
                        }
                    })
            
            # Look for lines/paths that might represent connections
            for element in root.iter():
                if element.tag.endswith(('line', 'path', 'polyline')):
                    connections.append({
                        'type': 'connection',
                        'element': element.tag.split('}')[-1] if '}' in element.tag else element.tag,
                        'attributes': dict(element.attrib)
                    })
            
            return {
                'format': 'svg',
                'components': components,
                'connections': connections,
                'data_flows': self._infer_data_flows(components, connections),
                'security_boundaries': self._identify_security_boundaries(root)
            }
        
        except Exception as e:
            self.logger.error(f"SVG parsing error: {e}")
            # Return basic structure if parsing fails
            return {
                'format': 'svg',
                'components': [],
                'connections': [],
                'data_flows': [],
                'security_boundaries': []
            }
    
    def _parse_image(self, filepath: str) -> Dict[str, Any]:
        """Parse image diagram (basic analysis)"""
        try:
            with Image.open(filepath) as img:
                width, height = img.size
                format_type = img.format.lower()
                
                # Basic image analysis
                return {
                    'format': format_type,
                    'dimensions': {'width': width, 'height': height},
                    'components': [],  # Image analysis would require OCR/ML
                    'connections': [],
                    'data_flows': [],
                    'security_boundaries': [],
                    'analysis_note': 'Image-based diagrams require manual component identification'
                }
        
        except Exception as e:
            self.logger.error(f"Image parsing error: {e}")
            raise
    
    def _infer_data_flows(self, components: List[Dict], connections: List[Dict]) -> List[Dict]:
        """Infer data flows from components and connections"""
        data_flows = []
        
        # Simple heuristic: assume connections represent data flows
        for i, connection in enumerate(connections):
            data_flows.append({
                'id': f'flow_{i}',
                'source': 'unknown',
                'destination': 'unknown',
                'data_type': 'unknown',
                'encryption': 'unknown',
                'connection_info': connection
            })
        
        return data_flows
    
    def _identify_security_boundaries(self, root) -> List[Dict]:
        """Identify potential security boundaries in the diagram"""
        boundaries = []
        
        # Look for rectangles or groups that might represent security zones
        for element in root.iter():
            if element.tag.endswith(('rect', 'g')):
                if 'security' in str(element.attrib).lower() or 'zone' in str(element.attrib).lower():
                    boundaries.append({
                        'type': 'security_boundary',
                        'element': element.tag.split('}')[-1] if '}' in element.tag else element.tag,
                        'attributes': dict(element.attrib)
                    })
        
        return boundaries


class CrossMapParser:
    """Parser for cross-mapping data files (JSON)"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse cross-mapping data for MITRE framework mappings"""
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                data = json.load(file)
            
            return self._normalize_crossmap_data(data)
        
        except Exception as e:
            self.logger.error(f"Failed to parse cross-mapping data: {e}")
            raise
    
    def _normalize_crossmap_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize cross-mapping data to standard format"""
        normalized = {
            'attack_mappings': {},
            'engage_mappings': {},
            'threat_to_technique': {},
            'technique_to_mitigation': {}
        }
        
        # Extract MITRE ATT&CK mappings
        if 'mitre_attack' in data:
            normalized['attack_mappings'] = data['mitre_attack']
        elif 'attack_mappings' in data:
            normalized['attack_mappings'] = data['attack_mappings']
        
        # Extract MITRE ENGAGE mappings
        if 'mitre_engage' in data:
            normalized['engage_mappings'] = data['mitre_engage']
        elif 'engage_mappings' in data:
            normalized['engage_mappings'] = data['engage_mappings']
        
        # Extract threat-to-technique mappings
        if 'threat_mappings' in data:
            normalized['threat_to_technique'] = data['threat_mappings']
        elif 'mappings' in data:
            normalized['threat_to_technique'] = data['mappings']
        
        # Extract technique-to-mitigation mappings
        if 'mitigation_mappings' in data:
            normalized['technique_to_mitigation'] = data['mitigation_mappings']
        
        return normalized
