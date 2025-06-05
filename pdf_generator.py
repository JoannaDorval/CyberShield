import os
import tempfile
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
import logging

class TaraReportGenerator:
    """Generate TARA (Threat Assessment and Remediation Analysis) reports as PDF"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom styles for the report"""
        # Custom title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#2c3e50'),
            alignment=TA_CENTER
        ))
        
        # Custom heading styles
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceBefore=20,
            spaceAfter=12,
            textColor=HexColor('#34495e'),
            leftIndent=0
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=16,
            spaceAfter=8,
            textColor=HexColor('#34495e'),
            leftIndent=0
        ))
        
        # Custom body text
        self.styles.add(ParagraphStyle(
            name='CustomBody',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceBefore=6,
            spaceAfter=6,
            alignment=TA_JUSTIFY,
            leftIndent=0,
            rightIndent=0
        ))
        
        # High priority recommendation style
        self.styles.add(ParagraphStyle(
            name='HighPriority',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceBefore=6,
            spaceAfter=6,
            textColor=HexColor('#e74c3c'),
            leftIndent=12
        ))
        
        # Medium priority recommendation style
        self.styles.add(ParagraphStyle(
            name='MediumPriority',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceBefore=6,
            spaceAfter=6,
            textColor=HexColor('#f39c12'),
            leftIndent=12
        ))
    
    def generate_report(self, analysis) -> str:
        """Generate complete TARA report and return file path"""
        try:
            # Create temporary file for the PDF
            temp_dir = tempfile.gettempdir()
            filename = f"tara_report_{analysis.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = os.path.join(temp_dir, filename)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            story = []
            
            # Title page
            story.extend(self._create_title_page(analysis))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(analysis))
            story.append(PageBreak())
            
            # Threat analysis section
            story.extend(self._create_threat_analysis(analysis))
            story.append(PageBreak())
            
            # MITRE mappings section
            story.extend(self._create_mitre_mappings(analysis))
            story.append(PageBreak())
            
            # Recommendations section
            story.extend(self._create_recommendations(analysis))
            story.append(PageBreak())
            
            # Appendices
            story.extend(self._create_appendices(analysis))
            
            # Build PDF
            doc.build(story)
            
            self.logger.info(f"TARA report generated: {filepath}")
            return filepath
        
        except Exception as e:
            self.logger.error(f"Failed to generate TARA report: {e}")
            raise
    
    def _create_title_page(self, analysis) -> list:
        """Create title page elements"""
        elements = []
        
        # Main title
        elements.append(Paragraph("TARA Report", self.styles['CustomTitle']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Subtitle
        elements.append(Paragraph(
            "Threat Assessment and Remediation Analysis",
            self.styles['CustomHeading1']
        ))
        elements.append(Spacer(1, 0.5*inch))
        
        # Report metadata
        metadata = [
            ['Report ID:', str(analysis.id)],
            ['Generated:', analysis.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ['Status:', analysis.status.title()],
            ['Threat Model:', analysis.threat_model_filename or 'N/A'],
            ['Block Diagram:', analysis.block_diagram_filename or 'N/A'],
            ['Cross-mapping Data:', analysis.crossmap_filename or 'N/A']
        ]
        
        metadata_table = Table(metadata, colWidths=[2*inch, 4*inch])
        metadata_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        
        elements.append(metadata_table)
        elements.append(Spacer(1, 1*inch))
        
        # Disclaimer
        disclaimer = """
        <b>CONFIDENTIAL</b><br/><br/>
        This document contains sensitive security information and is intended for internal use only. 
        Distribution of this document should be limited to authorized personnel with a legitimate 
        need to know. The information contained herein should be used to improve the organization's 
        security posture and should not be disclosed to unauthorized parties.
        """
        elements.append(Paragraph(disclaimer, self.styles['CustomBody']))
        
        return elements
    
    def _create_executive_summary(self, analysis) -> list:
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['CustomHeading1']))
        
        # Summary statistics
        threats = analysis.threats or []
        risks = analysis.risks or []
        mitigations = analysis.mitigations or []
        recommendations = analysis.recommendations or []
        mitre_mappings = analysis.mitre_mappings or {}
        
        summary_text = f"""
        This Threat Assessment and Remediation Analysis (TARA) report provides a comprehensive 
        security assessment based on the provided threat model, system architecture, and 
        cross-mapping data. The analysis identified <b>{len(threats)} threats</b>, 
        <b>{len(risks)} risks</b>, and generated <b>{len(recommendations)} actionable recommendations</b>.
        <br/><br/>
        The assessment mapped threats to <b>{len(mitre_mappings.get('technique_mappings', []))} MITRE ATT&CK techniques</b> 
        across multiple attack tactics. Priority recommendations focus on addressing the most critical 
        security gaps identified in the analysis.
        """
        
        elements.append(Paragraph(summary_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Key findings
        elements.append(Paragraph("Key Findings", self.styles['CustomHeading2']))
        
        # Calculate summary statistics
        high_priority_recs = len([r for r in recommendations if r.get('priority', '').lower() in ['critical', 'high']])
        critical_threats = len([t for t in threats if t.get('severity', '').lower() == 'critical'])
        
        findings = [
            f"• {critical_threats} critical severity threats identified",
            f"• {high_priority_recs} high/critical priority recommendations",
            f"• {len(mitre_mappings.get('tactic_coverage', {}))} MITRE ATT&CK tactics covered",
            f"• {len(mitre_mappings.get('unmapped_threats', []))} threats require additional analysis"
        ]
        
        for finding in findings:
            elements.append(Paragraph(finding, self.styles['CustomBody']))
        
        return elements
    
    def _create_threat_analysis(self, analysis) -> list:
        """Create threat analysis section"""
        elements = []
        
        elements.append(Paragraph("Threat Analysis", self.styles['CustomHeading1']))
        
        threats = analysis.threats or []
        assets = analysis.assets or []
        risks = analysis.risks or []
        
        if not threats:
            elements.append(Paragraph("No threats were identified in the provided threat model.", self.styles['CustomBody']))
            return elements
        
        # Threats overview
        elements.append(Paragraph("Identified Threats", self.styles['CustomHeading2']))
        
        # Create threats table
        threat_data = [['ID', 'Name', 'Severity', 'Category', 'Affected Assets']]
        
        for threat in threats:
            threat_data.append([
                threat.get('id', 'N/A'),
                threat.get('name', 'N/A'),
                threat.get('severity', 'Unknown'),
                threat.get('category', 'Unknown'),
                ', '.join(threat.get('affected_assets', [])) or 'N/A'
            ])
        
        threats_table = Table(threat_data, colWidths=[0.8*inch, 2.5*inch, 1*inch, 1.2*inch, 1.5*inch])
        threats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))
        
        elements.append(threats_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Assets overview
        if assets:
            elements.append(Paragraph("Critical Assets", self.styles['CustomHeading2']))
            
            asset_data = [['Name', 'Type', 'Criticality', 'Description']]
            for asset in assets[:10]:  # Limit to top 10 assets
                asset_data.append([
                    asset.get('name', 'N/A'),
                    asset.get('type', 'Unknown'),
                    asset.get('criticality', 'Medium'),
                    asset.get('description', 'N/A')[:50] + '...' if len(asset.get('description', '')) > 50 else asset.get('description', 'N/A')
                ])
            
            assets_table = Table(asset_data, colWidths=[1.5*inch, 1.2*inch, 1*inch, 3.3*inch])
            assets_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, black)
            ]))
            
            elements.append(assets_table)
        
        return elements
    
    def _create_mitre_mappings(self, analysis) -> list:
        """Create MITRE mappings section"""
        elements = []
        
        elements.append(Paragraph("MITRE ATT&CK Mappings", self.styles['CustomHeading1']))
        
        mitre_mappings = analysis.mitre_mappings or {}
        technique_mappings = mitre_mappings.get('technique_mappings', [])
        tactic_coverage = mitre_mappings.get('tactic_coverage', {})
        
        if not technique_mappings:
            elements.append(Paragraph("No MITRE ATT&CK technique mappings were generated.", self.styles['CustomBody']))
            return elements
        
        # Tactic coverage overview
        elements.append(Paragraph("Tactic Coverage Overview", self.styles['CustomHeading2']))
        
        if tactic_coverage:
            coverage_text = "The following MITRE ATT&CK tactics are represented in the threat analysis:<br/><br/>"
            for tactic, count in tactic_coverage.items():
                coverage_text += f"• <b>{tactic}</b>: {count} technique(s)<br/>"
            
            elements.append(Paragraph(coverage_text, self.styles['CustomBody']))
        
        elements.append(Spacer(1, 0.2*inch))
        
        # Technique mappings table
        elements.append(Paragraph("Technique Mappings", self.styles['CustomHeading2']))
        
        mapping_data = [['Threat', 'MITRE Technique', 'Tactic', 'Confidence']]
        
        for mapping in technique_mappings:
            mapping_data.append([
                mapping.get('threat_name', 'N/A')[:30] + '...' if len(mapping.get('threat_name', '')) > 30 else mapping.get('threat_name', 'N/A'),
                f"{mapping.get('technique_id', 'N/A')}: {mapping.get('technique_name', 'N/A')}"[:40] + '...' if len(f"{mapping.get('technique_id', 'N/A')}: {mapping.get('technique_name', 'N/A')}") > 40 else f"{mapping.get('technique_id', 'N/A')}: {mapping.get('technique_name', 'N/A')}",
                mapping.get('tactic', 'Unknown'),
                mapping.get('mapping_confidence', 'Unknown').title()
            ])
        
        mappings_table = Table(mapping_data, colWidths=[2*inch, 2.5*inch, 1.5*inch, 1*inch])
        mappings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        
        elements.append(mappings_table)
        
        return elements
    
    def _create_recommendations(self, analysis) -> list:
        """Create recommendations section"""
        elements = []
        
        elements.append(Paragraph("Security Recommendations", self.styles['CustomHeading1']))
        
        recommendations = analysis.recommendations or []
        
        if not recommendations:
            elements.append(Paragraph("No recommendations were generated.", self.styles['CustomBody']))
            return elements
        
        # Group recommendations by priority
        priority_groups = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': []
        }
        
        for rec in recommendations:
            priority = rec.get('priority', 'Medium')
            if priority not in priority_groups:
                priority_groups['Medium'].append(rec)
            else:
                priority_groups[priority].append(rec)
        
        # Generate recommendations by priority
        for priority in ['Critical', 'High', 'Medium', 'Low']:
            recs = priority_groups[priority]
            if not recs:
                continue
            
            elements.append(Paragraph(f"{priority} Priority Recommendations", self.styles['CustomHeading2']))
            
            for i, rec in enumerate(recs, 1):
                # Recommendation title
                title_style = self.styles['HighPriority'] if priority in ['Critical', 'High'] else self.styles['MediumPriority']
                elements.append(Paragraph(f"{i}. {rec.get('title', 'Untitled Recommendation')}", title_style))
                
                # Recommendation details
                details = f"""
                <b>Description:</b> {rec.get('description', 'No description provided')}<br/>
                <b>Category:</b> {rec.get('category', 'Unknown')}<br/>
                <b>Implementation Effort:</b> {rec.get('implementation_effort', 'Unknown')}<br/>
                <b>Effectiveness:</b> {rec.get('effectiveness', 'Unknown')}<br/>
                """
                
                if rec.get('mitre_technique'):
                    details += f"<b>MITRE Technique:</b> {rec.get('mitre_technique')}<br/>"
                
                elements.append(Paragraph(details, self.styles['CustomBody']))
                elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _create_appendices(self, analysis) -> list:
        """Create appendices section"""
        elements = []
        
        elements.append(Paragraph("Appendices", self.styles['CustomHeading1']))
        
        # Appendix A: Methodology
        elements.append(Paragraph("Appendix A: Analysis Methodology", self.styles['CustomHeading2']))
        
        methodology_text = """
        This TARA report was generated using an automated threat analysis system that processes 
        threat models, system architecture diagrams, and cross-mapping data to produce comprehensive 
        security assessments. The methodology includes:
        <br/><br/>
        1. <b>Threat Model Parsing:</b> Extraction of threats, assets, risks, and mitigations from 
           structured threat model files (JSON/YAML format)
        <br/><br/>
        2. <b>Architecture Analysis:</b> Basic analysis of system block diagrams to identify 
           components and data flows
        <br/><br/>
        3. <b>MITRE Framework Integration:</b> Mapping of identified threats to MITRE ATT&CK 
           techniques using both explicit cross-mapping data and heuristic analysis
        <br/><br/>
        4. <b>Recommendation Generation:</b> Production of prioritized security recommendations 
           based on threat severity, MITRE technique mappings, and best practices
        <br/><br/>
        5. <b>Report Generation:</b> Compilation of analysis results into this structured TARA document
        """
        
        elements.append(Paragraph(methodology_text, self.styles['CustomBody']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Appendix B: Data Sources
        elements.append(Paragraph("Appendix B: Data Sources", self.styles['CustomHeading2']))
        
        sources_data = [
            ['Source Type', 'Filename', 'Status'],
            ['Threat Model', analysis.threat_model_filename or 'Not provided', 'Processed' if analysis.threats else 'Failed'],
            ['Block Diagram', analysis.block_diagram_filename or 'Not provided', 'Processed'],
            ['Cross-mapping Data', analysis.crossmap_filename or 'Not provided', 'Processed' if analysis.mitre_mappings else 'Failed']
        ]
        
        sources_table = Table(sources_data, colWidths=[2*inch, 3*inch, 2*inch])
        sources_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#ecf0f1')),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, black)
        ]))
        
        elements.append(sources_table)
        
        return elements
