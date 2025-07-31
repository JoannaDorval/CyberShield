import os
import uuid
import json
from flask import render_template, request, jsonify, send_file, flash, redirect, url_for, session
from werkzeug.utils import secure_filename
from app import app, db
from models import Analysis, AuditLog
from parsers import ThreatModelParser, BlockDiagramParser, CrossMapParser
from mitre_integration import MitreIntegrator
from mitre_embed import MitreEmbedIntegrator
from pdf_generator import TaraReportGenerator
from enhanced_excel_generator_fixed import EnhancedTaraExcelGenerator
import logging

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    'threat_model': {'json', 'yaml', 'yml'},
    'block_diagram': {'svg', 'png', 'jpg', 'jpeg'},
    'crossmap': {'json'}
}

def allowed_file(filename, file_type):
    """Check if file extension is allowed for the given file type"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

def log_action(action, details=None):
    """Log security audit information"""
    try:
        audit_log = AuditLog(
            session_id=session.get('session_id', 'unknown'),
            action=action,
            details=details,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Failed to log audit action: {e}")

@app.route('/')
def index():
    """Main landing page"""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    
    log_action('page_visit', 'Accessed main page')
    return render_template('index.html')

@app.route('/mitre_embed')
def mitre_embed_page():
    """MITRE EMBED analysis page"""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    
    log_action('page_visit', 'Accessed MITRE EMBED analysis page')
    return render_template('mitre_embed.html')

@app.route('/analyze_embed', methods=['POST'])
def analyze_embed():
    """Handle MITRE EMBED analysis requests"""
    session_id = session.get('session_id', str(uuid.uuid4()))
    session['session_id'] = session_id
    
    try:
        # Check if file upload or properties were provided
        embed_file = request.files.get('embed_file')
        embed_properties = request.form.getlist('properties')
        
        embed_assessment = None
        embed_data = {}
        
        if embed_file and embed_file.filename != '':
            # Handle JSON file upload
            if not embed_file.filename or not embed_file.filename.endswith('.json'):
                flash('Please upload a valid JSON file', 'error')
                return redirect(url_for('mitre_embed_page'))
            
            try:
                embed_data = json.load(embed_file)
                log_action('file_upload', f'MITRE EMBED JSON file: {embed_file.filename}')
            except json.JSONDecodeError as e:
                flash(f'Invalid JSON file: {str(e)}', 'error')
                return redirect(url_for('mitre_embed_page'))
                
        elif embed_properties:
            # Handle properties from quiz
            embed_data = {'selected_properties': embed_properties}
            log_action('properties_selection', f'Selected {len(embed_properties)} MITRE EMBED properties')
        else:
            flash('Please either upload a MITRE EMBED JSON file or complete the properties quiz', 'error')
            return redirect(url_for('mitre_embed_page'))
        
        # Process EMBED assessment
        embed_integrator = MitreEmbedIntegrator()
        if 'selected_properties' in embed_data:
            embed_assessment = embed_integrator.assess_device_properties(embed_data['selected_properties'])
        else:
            embed_assessment = embed_integrator.process_embed_json(embed_data)
        
        # Create analysis record for MITRE EMBED
        analysis = Analysis()
        analysis.session_id = session_id
        analysis.status = 'processing'
        analysis.embed_properties_filename = secure_filename(embed_file.filename) if embed_file and embed_file.filename else 'properties_quiz'
        db.session.add(analysis)
        db.session.commit()
        
        log_action('analysis_started', f'Analysis ID: {analysis.id}')
        
        # Store the EMBED assessment results
        analysis.embed_assessment = embed_assessment
        analysis.embed_properties = embed_data
        
        # Process with MITRE ATT&CK integration
        mitre_integrator = MitreIntegrator()
        
        # Generate fake assets for EMBED analysis if none provided
        assets = embed_assessment.get('assets', [])
        if not assets:
            assets = [{
                'id': 'device_001',
                'name': 'IoT Device',
                'type': 'Embedded Device',
                'description': 'Device being assessed with MITRE EMBED framework',
                'properties': embed_data.get('selected_properties', [])
            }]
        
        # Map EMBED controls to MITRE ATT&CK
        mitre_mappings = mitre_integrator.map_embed_to_attack(embed_assessment)
        
        # Store final results
        analysis.assets = assets
        analysis.mitre_mappings = mitre_mappings
        analysis.status = 'completed'
        
        db.session.commit()
        
        # Generate reports
        try:
            # Generate Excel report
            excel_generator = EnhancedTaraExcelGenerator()
            excel_path = excel_generator.generate_excel_report(
                analysis_data={'assets': assets, 'threats': [], 'mitre_mappings': mitre_mappings},
                input_type='mitre_embed',
                cross_ref_source='embed_assessment',
                embed_assessment=embed_assessment
            )
            
            # Generate PDF report
            pdf_generator = TaraReportGenerator()
            pdf_path = pdf_generator.generate_report(
                analysis=analysis
            )
            
            log_action('reports_generated', f'Excel: {excel_path}, PDF: {pdf_path}')
            
        except Exception as e:
            analysis.error_message = str(e)
            analysis.status = 'failed'
            db.session.commit()
            app.logger.error(f"Report generation failed: {e}")
            flash(f'Analysis completed but report generation failed: {str(e)}', 'error')
            return redirect(url_for('mitre_embed_page'))
        
        # Redirect to results page
        return redirect(url_for('results', analysis_id=analysis.id))
        
    except Exception as e:
        app.logger.error(f"Analysis failed: {e}")
        flash(f'Analysis failed: {str(e)}', 'error')
        return redirect(url_for('mitre_embed_page'))

@app.route('/results/<int:analysis_id>')
def results(analysis_id):
    """Display analysis results"""
    analysis = Analysis.query.get_or_404(analysis_id)
    
    # Verify session ownership
    if analysis.session_id != session.get('session_id'):
        log_action('unauthorized_access_attempt', f'Analysis ID: {analysis_id}')
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    log_action('results_viewed', f'Analysis ID: {analysis_id}')
    return render_template('results.html', analysis=analysis)

@app.route('/download_report/<int:analysis_id>')
def download_report(analysis_id):
    """Generate and download TARA report as PDF"""
    analysis = Analysis.query.get_or_404(analysis_id)
    
    # Verify session ownership
    if analysis.session_id != session.get('session_id'):
        log_action('unauthorized_download_attempt', f'Analysis ID: {analysis_id}')
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    try:
        # Generate PDF report
        report_generator = TaraReportGenerator()
        pdf_path = report_generator.generate_report(analysis)
        
        log_action('report_downloaded', f'Analysis ID: {analysis_id}')
        
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f'TARA_Report_{analysis_id}_{analysis.timestamp.strftime("%Y%m%d_%H%M%S")}.pdf',
            mimetype='application/pdf'
        )
    
    except Exception as e:
        app.logger.error(f"Report generation error: {e}")
        log_action('report_generation_failed', f'Analysis ID: {analysis_id}, Error: {str(e)}')
        flash(f'Failed to generate report: {str(e)}', 'error')
        return redirect(url_for('results', analysis_id=analysis_id))

@app.route('/download_excel/<int:analysis_id>')
def download_excel_report(analysis_id):
    """Generate and download enhanced TARA report as Excel"""
    analysis = Analysis.query.get_or_404(analysis_id)
    
    # Verify session ownership
    if analysis.session_id != session.get('session_id'):
        log_action('unauthorized_excel_download_attempt', f'Analysis ID: {analysis_id}')
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    try:
        # Prepare analysis data for Excel generation
        analysis_data = {
            'threats': analysis.threats or [],
            'assets': analysis.assets or [],
            'risks': analysis.risks or [],
            'mitigations': analysis.mitigations or [],
            'mitre_mappings': analysis.mitre_mappings or {},
            'recommendations': analysis.recommendations or []
        }
        
        # Get metadata if available (use default values if not)
        input_type = 'both'
        cross_ref_source = 'mitre_attack'
        embed_assessment = None
        
        # Generate Excel report
        excel_generator = EnhancedTaraExcelGenerator()
        excel_path = excel_generator.generate_excel_report(
            analysis_data, 
            input_type, 
            cross_ref_source,
            embed_assessment
        )
        
        log_action('excel_download_completed', f'Analysis ID: {analysis_id}')
        return send_file(
            excel_path,
            as_attachment=True,
            download_name=f'TARA_Excel_Report_{analysis_id}_{analysis.timestamp.strftime("%Y%m%d_%H%M%S")}.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        app.logger.error(f"Excel report generation error: {e}")
        log_action('excel_download_error', f'Analysis ID: {analysis_id}, Error: {str(e)}')
        flash(f'Excel report generation failed: {str(e)}', 'error')
        return redirect(url_for('results', analysis_id=analysis_id))

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    log_action('file_too_large', 'File exceeded maximum size limit')
    flash('File too large. Maximum size is 50MB.', 'error')
    return redirect(url_for('mitre_embed_page'))

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    log_action('page_not_found', f'Path: {request.path}')
    return render_template('base.html'), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    log_action('internal_error', f'Error: {str(e)}')
    return render_template('base.html'), 500
