import requests
import json
import logging
from typing import Dict, List, Any, Optional
import os

class MitreIntegrator:
    """Integration with MITRE ATT&CK and ENGAGE frameworks"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.attack_base_url = "https://raw.githubusercontent.com/mitre/cti/master"
        self.techniques_cache = {}
        self.mitigations_cache = {}
    
    def map_threats_to_mitre(self, threats: List[Dict], crossmap_data: Dict) -> Dict[str, Any]:
        """Map identified threats to MITRE ATT&CK techniques"""
        mappings = {
            'technique_mappings': [],
            'tactic_coverage': {},
            'unmapped_threats': []
        }
        
        try:
            # Load MITRE ATT&CK data
            techniques = self._get_mitre_techniques()
            
            for threat in threats:
                threat_id = threat.get('id', '')
                threat_name = threat.get('name', '')
                
                # Check crossmap data for explicit mappings
                mapped_techniques = self._find_mapped_techniques(threat, crossmap_data)
                
                if mapped_techniques:
                    for technique_id in mapped_techniques:
                        technique_info = techniques.get(technique_id, {})
                        mapping = {
                            'threat_id': threat_id,
                            'threat_name': threat_name,
                            'technique_id': technique_id,
                            'technique_name': technique_info.get('name', ''),
                            'tactic': technique_info.get('tactic', ''),
                            'description': technique_info.get('description', ''),
                            'mapping_confidence': 'high'
                        }
                        mappings['technique_mappings'].append(mapping)
                        
                        # Update tactic coverage
                        tactic = technique_info.get('tactic', 'Unknown')
                        mappings['tactic_coverage'][tactic] = mappings['tactic_coverage'].get(tactic, 0) + 1
                else:
                    # Try heuristic mapping based on threat description
                    heuristic_mappings = self._heuristic_mapping(threat, techniques)
                    if heuristic_mappings:
                        mappings['technique_mappings'].extend(heuristic_mappings)
                    else:
                        mappings['unmapped_threats'].append({
                            'threat_id': threat_id,
                            'threat_name': threat_name,
                            'reason': 'No matching MITRE technique found'
                        })
            
            return mappings
        
        except Exception as e:
            self.logger.error(f"MITRE mapping error: {e}")
            return {
                'technique_mappings': [],
                'tactic_coverage': {},
                'unmapped_threats': [],
                'error': str(e)
            }
    
    def _get_mitre_techniques(self) -> Dict[str, Dict]:
        """Retrieve MITRE ATT&CK techniques data"""
        if self.techniques_cache:
            return self.techniques_cache
        
        try:
            # Use a simplified local technique database for demonstration
            # In production, this would fetch from MITRE CTI repository
            techniques = {
                'T1566': {
                    'name': 'Phishing',
                    'tactic': 'Initial Access',
                    'description': 'Adversaries may send phishing messages to gain access to victim systems.'
                },
                'T1190': {
                    'name': 'Exploit Public-Facing Application',
                    'tactic': 'Initial Access',
                    'description': 'Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.'
                },
                'T1078': {
                    'name': 'Valid Accounts',
                    'tactic': 'Defense Evasion',
                    'description': 'Adversaries may obtain and abuse credentials of existing accounts.'
                },
                'T1055': {
                    'name': 'Process Injection',
                    'tactic': 'Defense Evasion',
                    'description': 'Adversaries may inject code into processes in order to evade process-based defenses.'
                },
                'T1204': {
                    'name': 'User Execution',
                    'tactic': 'Execution',
                    'description': 'An adversary may rely upon specific actions by a user in order to gain execution.'
                },
                'T1574': {
                    'name': 'Hijack Execution Flow',
                    'tactic': 'Persistence',
                    'description': 'Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs.'
                },
                'T1083': {
                    'name': 'File and Directory Discovery',
                    'tactic': 'Discovery',
                    'description': 'Adversaries may enumerate files and directories or may search in specific locations of a host or network share.'
                },
                'T1005': {
                    'name': 'Data from Local System',
                    'tactic': 'Collection',
                    'description': 'Adversaries may search local system sources, such as file systems or local databases.'
                },
                'T1041': {
                    'name': 'Exfiltration Over C2 Channel',
                    'tactic': 'Exfiltration',
                    'description': 'Adversaries may steal data by exfiltrating it over an existing command and control channel.'
                },
                'T1486': {
                    'name': 'Data Encrypted for Impact',
                    'tactic': 'Impact',
                    'description': 'Adversaries may encrypt data on target systems or on large numbers of systems in a network.'
                }
            }
            
            self.techniques_cache = techniques
            return techniques
        
        except Exception as e:
            self.logger.error(f"Failed to load MITRE techniques: {e}")
            return {}
    
    def _find_mapped_techniques(self, threat: Dict, crossmap_data: Dict) -> List[str]:
        """Find explicitly mapped techniques for a threat"""
        threat_id = threat.get('id', '')
        threat_name = threat.get('name', '').lower()
        
        # Check direct mappings
        mappings = crossmap_data.get('threat_to_technique', {})
        
        if threat_id in mappings:
            return mappings[threat_id] if isinstance(mappings[threat_id], list) else [mappings[threat_id]]
        
        # Check name-based mappings
        for key, techniques in mappings.items():
            if key.lower() in threat_name or threat_name in key.lower():
                return techniques if isinstance(techniques, list) else [techniques]
        
        return []
    
    def _heuristic_mapping(self, threat: Dict, techniques: Dict) -> List[Dict]:
        """Perform heuristic mapping based on threat characteristics"""
        mappings = []
        threat_name = threat.get('name', '').lower()
        threat_desc = threat.get('description', '').lower()
        threat_text = f"{threat_name} {threat_desc}"
        
        # Simple keyword-based matching
        keyword_mappings = {
            'phishing': ['T1566'],
            'email': ['T1566'],
            'malware': ['T1204', 'T1055'],
            'injection': ['T1055'],
            'account': ['T1078'],
            'credential': ['T1078'],
            'exploit': ['T1190'],
            'vulnerability': ['T1190'],
            'execution': ['T1204'],
            'discovery': ['T1083'],
            'file': ['T1083', 'T1005'],
            'data': ['T1005', 'T1041'],
            'exfiltration': ['T1041'],
            'encryption': ['T1486'],
            'ransomware': ['T1486']
        }
        
        for keyword, technique_ids in keyword_mappings.items():
            if keyword in threat_text:
                for technique_id in technique_ids:
                    if technique_id in techniques:
                        technique_info = techniques[technique_id]
                        mapping = {
                            'threat_id': threat.get('id', ''),
                            'threat_name': threat.get('name', ''),
                            'technique_id': technique_id,
                            'technique_name': technique_info.get('name', ''),
                            'tactic': technique_info.get('tactic', ''),
                            'description': technique_info.get('description', ''),
                            'mapping_confidence': 'medium'
                        }
                        mappings.append(mapping)
        
        return mappings
    
    def generate_recommendations(self, threats: List[Dict], mitre_mappings: Dict, existing_mitigations: List[Dict]) -> List[Dict]:
        """Generate security recommendations based on threat analysis"""
        recommendations = []
        
        try:
            # Get technique mappings
            technique_mappings = mitre_mappings.get('technique_mappings', [])
            
            # Generate recommendations for each mapped technique
            for mapping in technique_mappings:
                technique_id = mapping.get('technique_id', '')
                technique_name = mapping.get('technique_name', '')
                tactic = mapping.get('tactic', '')
                
                # Get suggested mitigations for the technique
                suggested_mitigations = self._get_mitigations_for_technique(technique_id)
                
                for mitigation in suggested_mitigations:
                    recommendation = {
                        'id': f"REC_{technique_id}_{len(recommendations)}",
                        'title': f"Mitigate {technique_name}",
                        'description': mitigation.get('description', ''),
                        'priority': self._calculate_priority(mapping, threats),
                        'category': tactic,
                        'implementation_effort': mitigation.get('effort', 'Medium'),
                        'effectiveness': mitigation.get('effectiveness', 'High'),
                        'related_threats': [mapping.get('threat_id', '')],
                        'mitre_technique': technique_id,
                        'mitigation_type': mitigation.get('type', 'Technical')
                    }
                    recommendations.append(recommendation)
            
            # Add general security recommendations
            general_recommendations = self._generate_general_recommendations(threats, technique_mappings)
            recommendations.extend(general_recommendations)
            
            # Sort by priority
            recommendations.sort(key=lambda x: self._priority_score(x.get('priority', 'Low')), reverse=True)
            
            return recommendations
        
        except Exception as e:
            self.logger.error(f"Recommendation generation error: {e}")
            return []
    
    def _get_mitigations_for_technique(self, technique_id: str) -> List[Dict]:
        """Get suggested mitigations for a MITRE technique"""
        # Simplified mitigation database
        mitigation_db = {
            'T1566': [
                {
                    'description': 'Implement email security solutions with advanced threat protection',
                    'type': 'Technical',
                    'effort': 'Medium',
                    'effectiveness': 'High'
                },
                {
                    'description': 'Conduct regular phishing awareness training for employees',
                    'type': 'Administrative',
                    'effort': 'Low',
                    'effectiveness': 'Medium'
                }
            ],
            'T1190': [
                {
                    'description': 'Implement regular vulnerability scanning and patch management',
                    'type': 'Technical',
                    'effort': 'Medium',
                    'effectiveness': 'High'
                },
                {
                    'description': 'Deploy Web Application Firewall (WAF) for public-facing applications',
                    'type': 'Technical',
                    'effort': 'Medium',
                    'effectiveness': 'High'
                }
            ],
            'T1078': [
                {
                    'description': 'Implement multi-factor authentication for all user accounts',
                    'type': 'Technical',
                    'effort': 'Medium',
                    'effectiveness': 'High'
                },
                {
                    'description': 'Deploy privileged access management (PAM) solution',
                    'type': 'Technical',
                    'effort': 'High',
                    'effectiveness': 'High'
                }
            ]
        }
        
        return mitigation_db.get(technique_id, [
            {
                'description': f'Implement appropriate controls to mitigate technique {technique_id}',
                'type': 'Technical',
                'effort': 'Medium',
                'effectiveness': 'Medium'
            }
        ])
    
    def _calculate_priority(self, mapping: Dict, threats: List[Dict]) -> str:
        """Calculate recommendation priority based on threat severity and technique impact"""
        threat_id = mapping.get('threat_id', '')
        
        # Find the corresponding threat
        threat = next((t for t in threats if t.get('id') == threat_id), {})
        severity = threat.get('severity', 'Medium').lower()
        likelihood = threat.get('likelihood', 'Medium').lower()
        
        # Simple priority calculation
        if severity in ['critical', 'high'] and likelihood in ['high', 'very high']:
            return 'Critical'
        elif severity in ['high', 'medium'] and likelihood in ['medium', 'high']:
            return 'High'
        elif severity in ['medium', 'low'] or likelihood in ['low', 'very low']:
            return 'Medium'
        else:
            return 'Low'
    
    def _generate_general_recommendations(self, threats: List[Dict], technique_mappings: List[Dict]) -> List[Dict]:
        """Generate general security recommendations"""
        general_recs = [
            {
                'id': 'GEN_001',
                'title': 'Implement Security Monitoring and Logging',
                'description': 'Deploy comprehensive security monitoring and logging solutions to detect and respond to threats',
                'priority': 'High',
                'category': 'General Security',
                'implementation_effort': 'Medium',
                'effectiveness': 'High',
                'related_threats': [t.get('id', '') for t in threats],
                'mitigation_type': 'Technical'
            },
            {
                'id': 'GEN_002',
                'title': 'Regular Security Assessments',
                'description': 'Conduct regular penetration testing and vulnerability assessments',
                'priority': 'Medium',
                'category': 'General Security',
                'implementation_effort': 'Medium',
                'effectiveness': 'High',
                'related_threats': [t.get('id', '') for t in threats],
                'mitigation_type': 'Administrative'
            },
            {
                'id': 'GEN_003',
                'title': 'Incident Response Plan',
                'description': 'Develop and maintain an comprehensive incident response plan',
                'priority': 'High',
                'category': 'General Security',
                'implementation_effort': 'High',
                'effectiveness': 'High',
                'related_threats': [t.get('id', '') for t in threats],
                'mitigation_type': 'Administrative'
            }
        ]
        
        return general_recs
    
    def _priority_score(self, priority: str) -> int:
        """Convert priority to numeric score for sorting"""
        priority_scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1
        }
        return priority_scores.get(priority.lower(), 0)
    
    def map_embed_to_attack(self, embed_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Map MITRE EMBED assessment to MITRE ATT&CK techniques"""
        mappings = {
            'technique_mappings': [],
            'tactic_coverage': {},
            'embed_controls': embed_assessment.get('recommended_controls', [])
        }
        
        # Extract properties and threat vectors from EMBED assessment
        selected_properties = embed_assessment.get('selected_properties', [])
        threat_vectors = embed_assessment.get('threat_vectors', [])
        
        # Map common IoT/embedded threat patterns to MITRE ATT&CK
        property_to_attack_mapping = {
            # Hardware properties to ATT&CK techniques
            'PID-19': ['T1200'],  # Physical interfaces -> Hardware Additions
            'PID-110': ['T1557', 'T1040'],  # Wireless hardware -> Adversary-in-the-Middle
            
            # System software properties  
            'PID-22': ['T1611'],  # Debugging capabilities -> Escape to Host
            'PID-28': ['T1195.002'],  # Update mechanisms -> Supply Chain Compromise
            
            # Application software properties
            'PID-311': ['T1190'],  # Web applications -> Exploit Public-Facing Application
            'PID-319': ['T1190'],  # API interfaces -> Exploit Public-Facing Application
            
            # Network properties
            'PID-41': ['T1190', 'T1133'],  # Remote services -> External Remote Services
            'PID-412': ['T1557'],  # Wireless networking -> Adversary-in-the-Middle
            'PID-418': ['T1199']   # Cloud connectivity -> Trusted Relationship
        }
        
        # Map selected properties to ATT&CK techniques
        for prop in selected_properties:
            if prop in property_to_attack_mapping:
                for technique_id in property_to_attack_mapping[prop]:
                    technique_info = self._get_technique_info(technique_id)
                    if technique_info:
                        mapping = {
                            'embed_property': prop,
                            'technique_id': technique_id,
                            'technique_name': technique_info.get('name', ''),
                            'tactic': technique_info.get('tactic', ''),
                            'description': technique_info.get('description', ''),
                            'mapping_confidence': 'high'
                        }
                        mappings['technique_mappings'].append(mapping)
                        
                        # Update tactic coverage
                        tactic = technique_info.get('tactic', 'Unknown')
                        mappings['tactic_coverage'][tactic] = mappings['tactic_coverage'].get(tactic, 0) + 1
        
        return mappings
    
    def _get_technique_info(self, technique_id: str) -> Optional[Dict[str, str]]:
        """Get basic technique information"""
        # Simplified technique database for common IoT/embedded techniques
        technique_db = {
            'T1200': {
                'name': 'Hardware Additions',
                'tactic': 'Initial Access',
                'description': 'Hardware additions introduce computer accessories, computers, or networking hardware'
            },
            'T1557': {
                'name': 'Adversary-in-the-Middle',
                'tactic': 'Credential Access',
                'description': 'Position between two or more networked devices to intercept communications'
            },
            'T1190': {
                'name': 'Exploit Public-Facing Application',
                'tactic': 'Initial Access',
                'description': 'Take advantage of a weakness in an Internet-facing computer or program'
            },
            'T1133': {
                'name': 'External Remote Services',
                'tactic': 'Persistence',
                'description': 'Leverage legitimate external remote services to access internal resources'
            }
        }
        
        return technique_db.get(technique_id)
