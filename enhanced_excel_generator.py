"""
Enhanced Excel Report Generator for TARA Analysis
"""

import pandas as pd
import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

class EnhancedTaraExcelGenerator:
    """Generate comprehensive TARA Excel reports with multiple worksheets"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate_excel_report(self, analysis_data: Dict[str, Any], 
                            input_type: str, 
                            cross_ref_source: str,
                            embed_assessment: Optional[Dict] = None) -> str:
        """Generate complete Excel report with all analysis data"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"TARA_Excel_Report_{timestamp}.xlsx"
            
            # Create uploads directory if it doesn't exist
            output_dir = 'uploads'
            os.makedirs(output_dir, exist_ok=True)
            
            filepath = os.path.join(output_dir, filename)
            
            # Create writer object
            with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                # Create single consolidated worksheet
                self._create_consolidated_sheet(writer, analysis_data, input_type, cross_ref_source, embed_assessment)
            
            self.logger.info(f"Excel report generated: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to generate Excel report: {e}")
            raise
    
    def _create_consolidated_sheet(self, writer, analysis_data: Dict, input_type: str, cross_ref_source: str, embed_assessment: Optional[Dict]):
        from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
        #Create Work sheets
        general_info = writer.book.create_sheet('General Information')
        writer.book.active = ws
        colors = 
        # Create the main worksheet
        ws = writer.book.create_sheet('TARA Analysis Report')
        writer.book.active = ws
        
        # Define color schemes for each section
        colors = {
            'assets': 'E7E6E6',
            'damage_scenario': 'E2EFDA', 
            'impact_analysis': 'FFF2CC',
            'cybersecurity_controls': 'F2F2F2',
            'threat_scenarios': 'DEEAF6',
            'attack_path': 'FCE4D6',
            'attack_feasibility': 'EDEDED',
            'cybersecurity_goals': 'E1D5E7'
        }
        
        # Define section headers and their columns
        sections = {
            'Assets': ['Asset ID', 'Asset Name', 'Security Property Loss'],
            'Damage Scenario': ['Stakeholder', 'Damage Scenario Description'],
            'Impact Analysis': ['Impact Category', 'Impact Level', 'Impact Description'],
            'Cybersecurity Controls': ['Control ID', 'Control Name', 'Control Description'],
            'Threat Scenarios': ['Threat ID', 'Threat Name', 'STRIDE Category'],
            'Attack Path': ['Attack Vector', 'Attack Steps', 'Prerequisites'],
            'Attack Feasibility Assessment': ['Feasibility Factor', 'Rating', 'Justification'],
            'Cybersecurity Goals and Claims': ['Goal ID', 'Security Goal', 'Claim Statement']
        }
        
        # Start position
        current_col = 1
        
        # Create each section
        for section_name, columns in sections.items():
            color_key = section_name.lower().replace(' ', '_').replace('_and_', '_')
            if color_key not in colors:
                color_key = 'assets'  # Default color
            
            fill_color = colors[color_key]
            
            # Create section header
            self._create_section_header(ws, section_name, current_col, len(columns), fill_color)
            
            # Create column headers
            for i, col_name in enumerate(columns):
                cell = ws.cell(row=2, column=current_col + i)
                cell.value = col_name
                cell.fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type='solid')
                cell.font = Font(bold=True, size=10)
                cell.alignment = Alignment(horizontal='center', vertical='center')
                cell.border = Border(
                    left=Side(style='thin'),
                    right=Side(style='thin'),
                    top=Side(style='thin'),
                    bottom=Side(style='thin')
                )
            
            # Fill section data
            self._fill_section_data(ws, section_name, analysis_data, current_col, fill_color, embed_assessment)
            
            # Move to next section
            current_col += len(columns) + 1  # Add gap between sections
        
        # Auto-fit column widths
        from openpyxl.utils import get_column_letter
        from openpyxl.cell.cell import MergedCell
        
        for col_idx in range(1, ws.max_column + 1):
            max_length = 0
            column_letter = get_column_letter(col_idx)
            
            for row_idx in range(1, ws.max_row + 1):
                cell = ws.cell(row=row_idx, column=col_idx)
                try:
                    # Skip merged cells and check for actual content
                    if not isinstance(cell, MergedCell) and cell.value is not None:
                        cell_length = len(str(cell.value))
                        if cell_length > max_length:
                            max_length = cell_length
                except:
                    pass
            
            adjusted_width = min(max(max_length + 2, 12), 50)  # Min 12, max 50
            ws.column_dimensions[column_letter].width = adjusted_width
    
    def _create_section_header(self, ws, section_name, start_col, num_cols, fill_color):
        """Create merged header for section"""
        from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
        
        # Merge cells for header
        if num_cols > 1:
            ws.merge_cells(start_row=1, start_column=start_col, end_row=1, end_column=start_col + num_cols - 1)
        
        # Style the header
        header_cell = ws.cell(row=1, column=start_col)
        header_cell.value = section_name
        header_cell.fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type='solid')
        header_cell.font = Font(bold=True, size=12)
        header_cell.alignment = Alignment(horizontal='center', vertical='center')
        header_cell.border = Border(
            left=Side(style='thick'),
            right=Side(style='thick'),
            top=Side(style='thick'),
            bottom=Side(style='thick')
        )
    
    def _fill_section_data(self, ws, section_name, analysis_data, start_col, fill_color, embed_assessment):
        """Fill data for each section"""
        from openpyxl.styles import PatternFill, Alignment, Border, Side
        
        fill = PatternFill(start_color=fill_color, end_color=fill_color, fill_type='solid')
        border = Border(
            left=Side(style='thin'),
            right=Side(style='thin'),
            top=Side(style='thin'),
            bottom=Side(style='thin')
        )
        
        row = 3  # Start data from row 3
        
        if section_name == 'Assets':
            assets = analysis_data.get('assets', [])
            for i, asset in enumerate(assets):
                ws.cell(row=row + i, column=start_col).value = f"A{i+1:03d}"
                ws.cell(row=row + i, column=start_col + 1).value = asset.get('name', 'Unknown')
                ws.cell(row=row + i, column=start_col + 2).value = asset.get('criticality', 'Medium')
                
                for col in range(3):
                    cell = ws.cell(row=row + i, column=start_col + col)
                    cell.fill = fill
                    cell.border = border
                    cell.alignment = Alignment(vertical='center')
        
        elif section_name == 'Damage Scenario':
            threats = analysis_data.get('threats', [])
            stakeholders = ['Users', 'Organization', 'Partners', 'Regulators']
            
            scenario_row = row
            for threat in threats[:10]:  # Limit to first 10 threats
                for stakeholder in stakeholders:
                    if scenario_row - row < 20:  # Limit total scenarios
                        ws.cell(row=scenario_row, column=start_col).value = stakeholder
                        scenario_desc = self._generate_damage_scenario(threat, stakeholder)
                        ws.cell(row=scenario_row, column=start_col + 1).value = scenario_desc
                        
                        for col in range(2):
                            cell = ws.cell(row=scenario_row, column=start_col + col)
                            cell.fill = fill
                            cell.border = border
                            cell.alignment = Alignment(vertical='center', wrap_text=True)
                        
                        scenario_row += 1
        
        elif section_name == 'Impact Analysis':
            threats = analysis_data.get('threats', [])
            for i, threat in enumerate(threats[:15]):  # Limit to 15 threats
                impact = self._calculate_impact_analysis(threat)
                ws.cell(row=row + i, column=start_col).value = impact.get('category', 'Operational')
                ws.cell(row=row + i, column=start_col + 1).value = impact.get('level', 'Medium')
                ws.cell(row=row + i, column=start_col + 2).value = impact.get('description', 'Standard impact assessment')
                
                for col in range(3):
                    cell = ws.cell(row=row + i, column=start_col + col)
                    cell.fill = fill
                    cell.border = border
                    cell.alignment = Alignment(vertical='center', wrap_text=True)
        
        elif section_name == 'Cybersecurity Controls':
            controls = analysis_data.get('mitigations', [])
            if embed_assessment:
                controls.extend(embed_assessment.get('controls', []))
            
            for i, control in enumerate(controls[:20]):  # Limit to 20 controls
                ws.cell(row=row + i, column=start_col).value = f"C{i+1:03d}"
                ws.cell(row=row + i, column=start_col + 1).value = control.get('name', control.get('title', 'Security Control'))
                ws.cell(row=row + i, column=start_col + 2).value = control.get('description', 'Standard security control')
                
                for col in range(3):
                    cell = ws.cell(row=row + i, column=start_col + col)
                    cell.fill = fill
                    cell.border = border
                    cell.alignment = Alignment(vertical='center', wrap_text=True)
        
        elif section_name == 'Threat Scenarios':
            threats = analysis_data.get('threats', [])
            for i, threat in enumerate(threats[:15]):
                stride = self._analyze_stride_threat(threat)
                ws.cell(row=row + i, column=start_col).value = f"T{i+1:03d}"
                ws.cell(row=row + i, column=start_col + 1).value = threat.get('name', threat.get('title', 'Security Threat'))
                ws.cell(row=row + i, column=start_col + 2).value = stride.get('primary_category', 'Information Disclosure')
                
                for col in range(3):
                    cell = ws.cell(row=row + i, column=start_col + col)
                    cell.fill = fill
                    cell.border = border
                    cell.alignment = Alignment(vertical='center', wrap_text=True)
        
        elif section_name == 'Attack Path':
            threats = analysis_data.get('threats', [])
            for i, threat in enumerate(threats[:12]):
                attack_path = self._generate_attack_path(threat)
                ws.cell(row=row + i, column=start_col).value = attack_path.get('vector', 'Network')
                ws.cell(row=row + i, column=start_col + 1).value = attack_path.get('steps', 'Multi-step attack sequence')
                ws.cell(row=row + i, column=start_col + 2).value = attack_path.get('prerequisites', 'Network access required')
                
                for col in range(3):
                    cell = ws.cell(row=row + i, column=start_col + col)
                    cell.fill = fill
                    cell.border = border
                    cell.alignment = Alignment(vertical='center', wrap_text=True)
        
        elif section_name == 'Attack Feasibility Assessment':
            threats = analysis_data.get('threats', [])
            feasibility_factors = ['Technical Skill', 'Resources Required', 'Detection Likelihood']
            
            factor_row = row
            for threat in threats[:8]:  # Limit threats
                for factor in feasibility_factors:
                    if factor_row - row < 24:  # Limit total assessments
                        feasibility = self._assess_attack_feasibility(threat)
                        ws.cell(row=factor_row, column=start_col).value = factor
                        ws.cell(row=factor_row, column=start_col + 1).value = feasibility.get('rating', 'Medium')
                        ws.cell(row=factor_row, column=start_col + 2).value = feasibility.get('justification', 'Standard assessment')
                        
                        for col in range(3):
                            cell = ws.cell(row=factor_row, column=start_col + col)
                            cell.fill = fill
                            cell.border = border
                            cell.alignment = Alignment(vertical='center', wrap_text=True)
                        
                        factor_row += 1
        
        elif section_name == 'Cybersecurity Goals and Claims':
            threats = analysis_data.get('threats', [])
            mitigations = analysis_data.get('mitigations', [])
            
            for i, threat in enumerate(threats[:12]):
                goal = self._generate_cybersecurity_goal(threat, mitigations)
                ws.cell(row=row + i, column=start_col).value = f"G{i+1:03d}"
                ws.cell(row=row + i, column=start_col + 1).value = goal.get('goal', 'Ensure system security')
                ws.cell(row=row + i, column=start_col + 2).value = goal.get('claim', 'Security controls effectively mitigate threats')
                
                for col in range(3):
                    cell = ws.cell(row=row + i, column=start_col + col)
                    cell.fill = fill
                    cell.border = border
                    cell.alignment = Alignment(vertical='center', wrap_text=True)
    
    def _create_executive_summary(self, writer, analysis_data: Dict, input_type: str, cross_ref_source: str):
        """Create executive summary worksheet"""
        summary_data = {
            'Analysis Details': [
                'Analysis Date',
                'Input Type',
                'Cross-Reference Source',
                'Total Threats',
                'Total Assets',
                'Total Mitigations'
            ],
            'Values': [
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                input_type.replace('_', ' ').title(),
                cross_ref_source.replace('_', ' ').title(),
                len(analysis_data.get('threats', [])),
                len(analysis_data.get('assets', [])),
                len(analysis_data.get('mitigations', []))
            ]
        }
        
        df_summary = pd.DataFrame(summary_data)
        df_summary.to_excel(writer, sheet_name='Executive Summary', index=False)
    
    def _create_assets_sheet(self, writer, analysis_data: Dict):
        """Create Assets worksheet"""
        assets = analysis_data.get('assets', [])
        
        assets_data = []
        for i, asset in enumerate(assets, 1):
            assets_data.append({
                'Asset ID': f"A{i:03d}",
                'Asset': asset.get('name', 'Unknown Asset'),
                'Security Property Loss': 'Confidentiality, Integrity, Availability'
            })
        
        df_assets = pd.DataFrame(assets_data)
        df_assets.to_excel(writer, sheet_name='Assets', index=False)
    
    def _create_damage_scenarios_sheet(self, writer, analysis_data: Dict):
        """Create Damage Scenarios worksheet"""
        threats = analysis_data.get('threats', [])
        stakeholders = ['End Users', 'Organization', 'Third Parties', 'Regulators']
        
        scenarios_data = []
        for threat in threats:
            for stakeholder in stakeholders:
                scenario = self._generate_damage_scenario(threat, stakeholder)
                scenarios_data.append({
                    'Stakeholder': stakeholder,
                    'Damage Scenario Description': scenario
                })
        
        df_scenarios = pd.DataFrame(scenarios_data)
        df_scenarios.to_excel(writer, sheet_name='Damage Scenarios', index=False)
    
    def _create_impact_analysis_sheet(self, writer, analysis_data: Dict):
        """Create Impact Analysis worksheet"""
        threats = analysis_data.get('threats', [])
        
        impact_data = []
        for threat in threats:
            impact = self._calculate_impact_analysis(threat)
            impact_data.append({
                'Threat ID': threat.get('id', 'T-XXX'),
                'Safety': impact['safety'],
                'Financial': impact['financial'],
                'Operational': impact['operational'],
                'Privacy': impact['privacy'],
                'Impact Level': impact['overall_level'],
                'Justification': impact['justification']
            })
        
        df_impact = pd.DataFrame(impact_data)
        df_impact.to_excel(writer, sheet_name='Impact Analysis', index=False)
    
    def _create_cybersecurity_controls_sheet(self, writer, analysis_data: Dict, embed_assessment: Optional[Dict]):
        """Create Cybersecurity Controls worksheet"""
        controls_data = []
        
        # Add existing mitigations
        mitigations = analysis_data.get('mitigations', [])
        for mitigation in mitigations:
            controls_data.append({
                'ID': mitigation.get('id', 'C-XXX'),
                'Cybersecurity Control': mitigation.get('description', mitigation.get('name', 'Unknown Control'))
            })
        
        # Add EMBED controls if available
        if embed_assessment and 'recommended_controls' in embed_assessment:
            for control in embed_assessment['recommended_controls']:
                controls_data.append({
                    'ID': control.get('id', 'EMBED-XXX'),
                    'Cybersecurity Control': control.get('control', control.get('description', 'EMBED Control'))
                })
        
        df_controls = pd.DataFrame(controls_data)
        df_controls.to_excel(writer, sheet_name='Cybersecurity Controls', index=False)
    
    def _create_threat_scenarios_sheet(self, writer, analysis_data: Dict):
        """Create Threat Scenarios worksheet (STRIDE)"""
        threats = analysis_data.get('threats', [])
        
        stride_data = []
        for threat in threats:
            stride = self._analyze_stride_threat(threat)
            stride_data.append({
                'Threat ID': threat.get('id', 'T-XXX'),
                'Spoofing': stride['spoofing'],
                'Tampering': stride['tampering'],
                'Repudiation': stride['repudiation'],
                'Information Disclosure': stride['information_disclosure'],
                'Denial of Service': stride['denial_of_service'],
                'Elevation of Privileges': stride['elevation_of_privileges']
            })
        
        df_stride = pd.DataFrame(stride_data)
        df_stride.to_excel(writer, sheet_name='Threat Scenarios', index=False)
    
    def _create_attack_paths_sheet(self, writer, analysis_data: Dict):
        """Create Attack Paths worksheet"""
        threats = analysis_data.get('threats', [])
        
        attack_paths_data = []
        for threat in threats:
            attack_path = self._generate_attack_path(threat)
            attack_paths_data.append({
                'Threat ID': threat.get('id', 'T-XXX'),
                'Attack Path': attack_path['path_name'],
                'Entry Point': attack_path['entry_point'],
                'Target Asset': attack_path['target'],
                'Attack Steps': attack_path['steps']
            })
        
        df_paths = pd.DataFrame(attack_paths_data)
        df_paths.to_excel(writer, sheet_name='Attack Paths', index=False)
    
    def _create_attack_feasibility_sheet(self, writer, analysis_data: Dict):
        """Create Attack Feasibility Assessment worksheet"""
        threats = analysis_data.get('threats', [])
        
        feasibility_data = []
        for threat in threats:
            feasibility = self._assess_attack_feasibility(threat)
            feasibility_data.append({
                'Threat ID': threat.get('id', 'T-XXX'),
                'Elapsed Time': feasibility['elapsed_time'],
                'Specialist Expertise': feasibility['specialist_expertise'],
                'Knowledge of Item': feasibility['knowledge_of_item'],
                'Window of Opportunity': feasibility['window_of_opportunity'],
                'Equipment': feasibility['equipment'],
                'Attack Vector': feasibility['attack_vector'],
                'Summary Attack Feasibility': feasibility['summary_feasibility'],
                'Risk Determination': feasibility['risk_determination']
            })
        
        df_feasibility = pd.DataFrame(feasibility_data)
        df_feasibility.to_excel(writer, sheet_name='Attack Feasibility', index=False)
    
    def _create_risk_evaluation_sheet(self, writer, analysis_data: Dict):
        """Create Risk Evaluation worksheet"""
        threats = analysis_data.get('threats', [])
        
        risk_data = []
        for threat in threats:
            risk = self._evaluate_risk(threat)
            risk_data.append({
                'Threat ID': threat.get('id', 'T-XXX'),
                'Likelihood': risk['likelihood'],
                'Impact': risk['impact'],
                'Risk Level': risk['risk_level'],
                'Risk Score': risk['risk_score'],
                'Risk Category': risk['risk_category'],
                'Treatment Required': risk['treatment_required']
            })
        
        df_risk = pd.DataFrame(risk_data)
        df_risk.to_excel(writer, sheet_name='Risk Evaluation', index=False)
    
    def _create_cybersecurity_goals_sheet(self, writer, analysis_data: Dict):
        """Create Cybersecurity Goals and Claims worksheet"""
        threats = analysis_data.get('threats', [])
        mitigations = analysis_data.get('mitigations', [])
        
        goals_data = []
        for i, threat in enumerate(threats, 1):
            goal = self._generate_cybersecurity_goal(threat, mitigations)
            goals_data.append({
                'Risk Threshold Level': goal['risk_threshold'],
                'Risk Treatment Option': goal['treatment_option'],
                'ID': f"CG-{i:03d}",
                'Cybersecurity Goal': goal['goal'],
                'Cybersecurity Claim': goal['claim'],
                'CAL': goal['cal'],
                'Expected Functionality': goal['expected_functionality']
            })
        
        df_goals = pd.DataFrame(goals_data)
        df_goals.to_excel(writer, sheet_name='Cybersecurity Goals', index=False)
    
    # Helper methods for data analysis
    
    def _generate_damage_scenario(self, threat: Dict, stakeholder: str) -> str:
        """Generate damage scenario description"""
        threat_name = threat.get('name', 'Unknown Threat')
        
        scenarios = {
            'End Users': f"Personal data exposure or service disruption due to {threat_name}",
            'Organization': f"Business impact and reputation damage from {threat_name}",
            'Third Parties': f"Supply chain or partner relationship impact from {threat_name}",
            'Regulators': f"Compliance violations and regulatory penalties due to {threat_name}"
        }
        
        return scenarios.get(stakeholder, f"Impact from {threat_name}")
    
    def _calculate_impact_analysis(self, threat: Dict) -> Dict[str, str]:
        """Calculate impact analysis for a threat"""
        severity = threat.get('severity', 'Medium').lower()
        
        impact_mapping = {
            'critical': {'safety': 'High', 'financial': 'High', 'operational': 'High', 'privacy': 'High'},
            'high': {'safety': 'Medium', 'financial': 'High', 'operational': 'Medium', 'privacy': 'High'},
            'medium': {'safety': 'Low', 'financial': 'Medium', 'operational': 'Medium', 'privacy': 'Medium'},
            'low': {'safety': 'Low', 'financial': 'Low', 'operational': 'Low', 'privacy': 'Low'}
        }
        
        impacts = impact_mapping.get(severity, impact_mapping['medium'])
        
        return {
            **impacts,
            'overall_level': severity.title(),
            'justification': f"Based on threat severity: {severity} and potential impact scope"
        }
    
    def _analyze_stride_threat(self, threat: Dict) -> Dict[str, str]:
        """Analyze threat against STRIDE categories"""
        threat_desc = threat.get('description', '').lower()
        
        stride = {
            'spoofing': 'Not Applicable',
            'tampering': 'Not Applicable',
            'repudiation': 'Not Applicable',
            'information_disclosure': 'Not Applicable',
            'denial_of_service': 'Not Applicable',
            'elevation_of_privileges': 'Not Applicable'
        }
        
        if any(word in threat_desc for word in ['identity', 'authentication', 'imperson']):
            stride['spoofing'] = 'High Risk'
        
        if any(word in threat_desc for word in ['modify', 'alter', 'tamper', 'change']):
            stride['tampering'] = 'High Risk'
        
        if any(word in threat_desc for word in ['deny', 'log', 'audit', 'trace']):
            stride['repudiation'] = 'Medium Risk'
        
        if any(word in threat_desc for word in ['data', 'information', 'leak', 'exposure']):
            stride['information_disclosure'] = 'High Risk'
        
        if any(word in threat_desc for word in ['dos', 'denial', 'availability', 'service']):
            stride['denial_of_service'] = 'High Risk'
        
        if any(word in threat_desc for word in ['privilege', 'escalation', 'admin', 'root']):
            stride['elevation_of_privileges'] = 'High Risk'
        
        return stride
    
    def _generate_attack_path(self, threat: Dict) -> Dict[str, str]:
        """Generate attack path information"""
        return {
            'path_name': f"Attack Path for {threat.get('name', 'Unknown')}",
            'entry_point': 'External Network Interface',
            'target': threat.get('target', 'System Assets'),
            'steps': '1. Initial Access → 2. Persistence → 3. Privilege Escalation → 4. Impact'
        }
    
    def _assess_attack_feasibility(self, threat: Dict) -> Dict[str, str]:
        """Assess attack feasibility parameters"""
        severity = threat.get('severity', 'Medium').lower()
        
        feasibility_mapping = {
            'critical': {
                'elapsed_time': '< 1 day',
                'specialist_expertise': 'Layman',
                'knowledge_of_item': 'Public',
                'window_of_opportunity': 'Unlimited',
                'equipment': 'Standard',
                'attack_vector': 'Remote'
            },
            'high': {
                'elapsed_time': '< 1 week',
                'specialist_expertise': 'Proficient',
                'knowledge_of_item': 'Restricted',
                'window_of_opportunity': 'Moderate',
                'equipment': 'Specialized',
                'attack_vector': 'Adjacent Network'
            },
            'medium': {
                'elapsed_time': '< 1 month',
                'specialist_expertise': 'Expert',
                'knowledge_of_item': 'Confidential',
                'window_of_opportunity': 'Difficult',
                'equipment': 'Bespoke',
                'attack_vector': 'Local Network'
            },
            'low': {
                'elapsed_time': '> 6 months',
                'specialist_expertise': 'Multiple Expert',
                'knowledge_of_item': 'Strictly Confidential',
                'window_of_opportunity': 'Very Difficult',
                'equipment': 'Multiple Bespoke',
                'attack_vector': 'Physical'
            }
        }
        
        feasibility = feasibility_mapping.get(severity, feasibility_mapping['medium'])
        feasibility['summary_feasibility'] = f"{severity.title()} Feasibility"
        feasibility['risk_determination'] = f"{severity.title()} Risk"
        
        return feasibility
    
    def _evaluate_risk(self, threat: Dict) -> Dict[str, str]:
        """Evaluate risk parameters"""
        severity = threat.get('severity', 'Medium')
        
        risk_mapping = {
            'Critical': {'likelihood': 'Very High', 'impact': 'Critical', 'risk_score': '25'},
            'High': {'likelihood': 'High', 'impact': 'High', 'risk_score': '16'},
            'Medium': {'likelihood': 'Medium', 'impact': 'Medium', 'risk_score': '9'},
            'Low': {'likelihood': 'Low', 'impact': 'Low', 'risk_score': '4'}
        }
        
        risk_data = risk_mapping.get(severity, risk_mapping['Medium'])
        risk_data['risk_level'] = severity
        risk_data['risk_category'] = 'Cybersecurity Risk'
        risk_data['treatment_required'] = 'Yes' if severity in ['Critical', 'High'] else 'Optional'
        
        return risk_data
    
    def _generate_cybersecurity_goal(self, threat: Dict, mitigations: List[Dict]) -> Dict[str, str]:
        """Generate cybersecurity goal and claim"""
        severity = threat.get('severity', 'Medium')
        
        return {
            'risk_threshold': 'Medium' if severity in ['Critical', 'High'] else 'Low',
            'treatment_option': 'Mitigate',
            'goal': f"Prevent or mitigate {threat.get('name', 'security threat')}",
            'claim': f"System implements controls to address {threat.get('name', 'identified threat')}",
            'cal': 'CAL-2' if severity in ['Critical', 'High'] else 'CAL-1',
            'expected_functionality': 'Security controls operate as designed without impacting system functionality'
        }