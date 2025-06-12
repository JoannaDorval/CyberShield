import json
import yaml
import os
import logging
from PIL import Image
import xml.etree.ElementTree as ET
import pandas as pd
import zipfile
from typing import Dict, List, Any, Optional

class ThreatModelParser:
    """Parser for threat model files (JSON/YAML)"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse threat model file and extract relevant data"""
        try:
            # Handle different file formats
            if filepath.lower().endswith('.tm7'):
                data = self._parse_tm7_file(filepath)
            elif filepath.lower().endswith('.json'):
                with open(filepath, 'r', encoding='utf-8') as file:
                    data = json.load(file)
            elif filepath.lower().endswith(('.yaml', '.yml')):
                with open(filepath, 'r', encoding='utf-8') as file:
                    data = yaml.safe_load(file)
            else:
                raise ValueError("Unsupported file format")
            
            # Extract and normalize threat model data
            return self._normalize_threat_model(data)
        
        except Exception as e:
            self.logger.error(f"Failed to parse threat model: {e}")
            raise

    def _parse_tm7_file(self, filepath: str) -> Dict[str, Any]:
        """Parse Microsoft Threat Modeling Tool .tm7 file"""
        try:
            # .tm7 files are ZIP archives containing XML data
            with zipfile.ZipFile(filepath, 'r') as zip_file:
                # Read the main model file
                model_xml = None
                for filename in zip_file.namelist():
                    if filename.endswith('.xml') and 'model' in filename.lower():
                        model_xml = zip_file.read(filename).decode('utf-8')
                        break
                
                if not model_xml:
                    # Fallback to any XML file
                    for filename in zip_file.namelist():
                        if filename.endswith('.xml'):
                            model_xml = zip_file.read(filename).decode('utf-8')
                            break
                
                if not model_xml:
                    raise ValueError("No XML model found in .tm7 file")
                
                # Parse XML to extract threat model data
                return self._parse_tm7_xml(model_xml)
        
        except Exception as e:
            self.logger.error(f"Failed to parse .tm7 file: {e}")
            # Try to parse as regular JSON/XML if ZIP parsing fails
            try:
                with open(filepath, 'r', encoding='utf-8') as file:
                    content = file.read()
                    if content.strip().startswith('<'):
                        return self._parse_tm7_xml(content)
                    else:
                        return json.loads(content)
            except:
                raise e

    def _parse_tm7_xml(self, xml_content: str) -> Dict[str, Any]:
        """Parse XML content from .tm7 file"""
        root = ET.fromstring(xml_content)
        
        # Extract threats, assets, and other elements
        data = {
            'threats': [],
            'assets': [],
            'data_flows': [],
            'trust_boundaries': [],
            'metadata': {}
        }
        
        # Parse threats
        for threat in root.findall('.//Threat'):
            threat_data = {
                'id': threat.get('Id', ''),
                'title': threat.get('Title', ''),
                'description': threat.get('Description', ''),
                'category': threat.get('Category', ''),
                'interaction': threat.get('Interaction', ''),
                'priority': threat.get('Priority', 'Medium'),
                'state': threat.get('State', 'Not Started')
            }
            data['threats'].append(threat_data)
        
        # Parse elements (assets)
        for element in root.findall('.//Element'):
            element_data = {
                'id': element.get('Id', ''),
                'name': element.get('Name', ''),
                'type': element.get('Type', ''),
                'description': element.get('Description', ''),
                'properties': {}
            }
            
            # Extract properties
            for prop in element.findall('.//Property'):
                prop_name = prop.get('Name', '')
                prop_value = prop.get('Value', '')
                element_data['properties'][prop_name] = prop_value
            
            data['assets'].append(element_data)
        
        # Parse data flows
        for flow in root.findall('.//DataFlow'):
            flow_data = {
                'id': flow.get('Id', ''),
                'name': flow.get('Name', ''),
                'source': flow.get('SourceElement', ''),
                'target': flow.get('TargetElement', ''),
                'protocol': flow.get('Protocol', ''),
                'is_encrypted': flow.get('IsEncrypted', 'false').lower() == 'true'
            }
            data['data_flows'].append(flow_data)
        
        return data

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
                format_type = img.format.lower() if img.format else 'unknown'
                
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


class AssetListParser:
    """Parser for Excel asset list files"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse(self, filepath: str) -> Dict[str, Any]:
        """Parse Excel asset list file and extract asset data"""
        try:
            # Read Excel file
            df = pd.read_excel(filepath, sheet_name=0)  # Read first sheet
            
            # Normalize column names (handle common variations)
            df.columns = df.columns.str.strip().str.lower()
            
            # Extract asset data
            assets = []
            for _, row in df.iterrows():
                asset_data = self._extract_asset_from_row(row)
                if asset_data:
                    assets.append(asset_data)
            
            # Generate threats and data flows from assets
            threats = self._generate_threats_from_assets(assets)
            data_flows = self._infer_data_flows_from_assets(assets)
            
            return {
                'assets': assets,
                'threats': threats,
                'data_flows': data_flows,
                'risks': [],
                'mitigations': [],
                'metadata': {
                    'source': 'excel_asset_list',
                    'asset_count': len(assets)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to parse asset list: {e}")
            raise
    
    def _extract_asset_from_row(self, row) -> Optional[Dict[str, Any]]:
        """Extract asset information from Excel row"""
        # Common column mappings
        column_mappings = {
            'name': ['name', 'asset_name', 'asset', 'component'],
            'type': ['type', 'asset_type', 'category', 'classification'],
            'description': ['description', 'desc', 'details'],
            'criticality': ['criticality', 'priority', 'importance', 'risk_level'],
            'location': ['location', 'zone', 'network_zone'],
            'owner': ['owner', 'responsible', 'team'],
            'value': ['value', 'business_value', 'asset_value'],
            'confidentiality': ['confidentiality', 'conf', 'c'],
            'integrity': ['integrity', 'int', 'i'],
            'availability': ['availability', 'avail', 'a']
        }
        
        asset = {}
        
        # Map columns to standard asset properties
        for prop, possible_cols in column_mappings.items():
            for col in possible_cols:
                if col in row.index and pd.notna(row[col]):
                    asset[prop] = str(row[col]).strip()
                    break
        
        # Must have at least a name
        if 'name' not in asset or not asset['name']:
            return None
        
        # Set defaults
        asset.setdefault('type', 'Unknown')
        asset.setdefault('criticality', 'Medium')
        asset.setdefault('description', '')
        
        # Add CIA triad ratings if present
        cia_ratings = {}
        for cia in ['confidentiality', 'integrity', 'availability']:
            if cia in asset:
                cia_ratings[cia] = asset[cia]
        
        if cia_ratings:
            asset['cia_ratings'] = cia_ratings
        
        return asset
    
    def _generate_threats_from_assets(self, assets: List[Dict]) -> List[Dict]:
        """Generate common threats based on asset types"""
        threats = []
        threat_id = 1
        
        for asset in assets:
            asset_type = asset.get('type', '').lower()
            asset_name = asset.get('name', '')
            
            # Generate threats based on asset type
            if 'database' in asset_type or 'data' in asset_type:
                threats.extend([
                    {
                        'id': f'T{threat_id:03d}',
                        'title': f'Data Breach - {asset_name}',
                        'description': f'Unauthorized access to sensitive data stored in {asset_name}',
                        'category': 'Information Disclosure',
                        'severity': 'High',
                        'affected_assets': [asset_name]
                    },
                    {
                        'id': f'T{threat_id+1:03d}',
                        'title': f'Data Corruption - {asset_name}',
                        'description': f'Malicious modification or corruption of data in {asset_name}',
                        'category': 'Tampering',
                        'severity': 'High',
                        'affected_assets': [asset_name]
                    }
                ])
                threat_id += 2
            
            elif 'server' in asset_type or 'system' in asset_type:
                threats.extend([
                    {
                        'id': f'T{threat_id:03d}',
                        'title': f'System Compromise - {asset_name}',
                        'description': f'Unauthorized access and control of {asset_name}',
                        'category': 'Elevation of Privilege',
                        'severity': 'Critical',
                        'affected_assets': [asset_name]
                    },
                    {
                        'id': f'T{threat_id+1:03d}',
                        'title': f'Service Disruption - {asset_name}',
                        'description': f'Denial of service attack targeting {asset_name}',
                        'category': 'Denial of Service',
                        'severity': 'Medium',
                        'affected_assets': [asset_name]
                    }
                ])
                threat_id += 2
            
            elif 'network' in asset_type or 'router' in asset_type or 'switch' in asset_type:
                threats.append({
                    'id': f'T{threat_id:03d}',
                    'title': f'Network Interception - {asset_name}',
                    'description': f'Man-in-the-middle attack on network traffic through {asset_name}',
                    'category': 'Information Disclosure',
                    'severity': 'High',
                    'affected_assets': [asset_name]
                })
                threat_id += 1
            
            elif 'application' in asset_type or 'app' in asset_type:
                threats.extend([
                    {
                        'id': f'T{threat_id:03d}',
                        'title': f'Application Vulnerability - {asset_name}',
                        'description': f'Exploitation of security vulnerabilities in {asset_name}',
                        'category': 'Elevation of Privilege',
                        'severity': 'High',
                        'affected_assets': [asset_name]
                    },
                    {
                        'id': f'T{threat_id+1:03d}',
                        'title': f'Input Validation Attack - {asset_name}',
                        'description': f'Injection attacks targeting input validation in {asset_name}',
                        'category': 'Tampering',
                        'severity': 'Medium',
                        'affected_assets': [asset_name]
                    }
                ])
                threat_id += 2
        
        return threats
    
    def _infer_data_flows_from_assets(self, assets: List[Dict]) -> List[Dict]:
        """Infer data flows between assets"""
        data_flows = []
        flow_id = 1
        
        # Group assets by type for flow inference
        databases = [a for a in assets if 'database' in a.get('type', '').lower()]
        applications = [a for a in assets if 'application' in a.get('type', '').lower()]
        servers = [a for a in assets if 'server' in a.get('type', '').lower()]
        
        # Application to Database flows
        for app in applications:
            for db in databases:
                data_flows.append({
                    'id': f'DF{flow_id:03d}',
                    'name': f'{app["name"]} to {db["name"]}',
                    'source': app['name'],
                    'target': db['name'],
                    'description': f'Data exchange between {app["name"]} and {db["name"]}',
                    'protocol': 'HTTPS/SQL',
                    'data_type': 'Sensitive Data'
                })
                flow_id += 1
        
        # Server to Application flows
        for server in servers:
            for app in applications:
                data_flows.append({
                    'id': f'DF{flow_id:03d}',
                    'name': f'{server["name"]} to {app["name"]}',
                    'source': server['name'],
                    'target': app['name'],
                    'description': f'Service communication between {server["name"]} and {app["name"]}',
                    'protocol': 'HTTPS',
                    'data_type': 'Application Data'
                })
                flow_id += 1
        
        return data_flows
