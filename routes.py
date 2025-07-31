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
from enhanced_excel_generator import EnhancedTaraExcelGenerator
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

@app.route('/upload')
def upload_page():
    """File upload page"""
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())
    
    log_action('page_visit', 'Accessed upload page')
    return render_template('upload.html')

@app.route('/upload_files', methods=['POST'])
def upload_files():
    """Handle enhanced file uploads and process analysis"""
    session_id = session.get('session_id', str(uuid.uuid4()))
    session['session_id'] = session_id
    
    try:
        # Get configuration from form
        input_type = request.form.get('selected_input_type', 'threat_model')
        cross_ref_source = request.form.get('selected_cross_ref_source', 'mitre_attack')
        embed_properties = request.form.get('embed_properties', '{}')
        
        # Parse EMBED properties if provided
        embed_assessment = None
        if embed_properties and embed_properties != '{}':
            try:
                selected_properties = json.loads(embed_properties)
                embed_integrator = MitreEmbedIntegrator()
                embed_assessment = embed_integrator.assess_device_properties(selected_properties)
            except Exception as e:
                app.logger.error(f"EMBED assessment error: {e}")
        
        # Determine required files based on input type
        required_files = ['crossmap']  # Always required
        if input_type == 'threat_model' or input_type == 'both':
            required_files.append('threat_model')
        if input_type == 'block_diagram' or input_type == 'both':
            required_files.append('block_diagram')
        
        # Check if required files are present
        files = {}
        for file_type in required_files:
            if file_type not in request.files:
                flash(f'{file_type.replace("_", " ").title()} file is required for selected analysis type', 'error')
                return redirect(url_for('upload_page'))
            
            file = request.files[file_type]
            if file.filename == '':
                flash(f'{file_type.replace("_", " ").title()} file is required', 'error')
                return redirect(url_for('upload_page'))
            
            if not allowed_file(file.filename, file_type):
                flash(f'Invalid file type for {file_type.replace("_", " ").title()}', 'error')
                return redirect(url_for('upload_page'))
            
            files[file_type] = file
        
        # Create analysis record with dynamic filenames
        analysis = Analysis(
            session_id=session_id,
            threat_model_filename=secure_filename(files['threat_model'].filename) if 'threat_model' in files else None,
            block_diagram_filename=secure_filename(files['block_diagram'].filename) if 'block_diagram' in files else None,
            crossmap_filename=secure_filename(files['crossmap'].filename) if 'crossmap' in files else None,
            status='processing'
        )
        db.session.add(analysis)
        db.session.commit()
        
        # Save files temporarily
        saved_files = {}
        for file_type, file in files.items():
            filename = f"{session_id}_{file_type}_{secure_filename(file.filename)}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            saved_files[file_type] = filepath
        
        log_action('files_uploaded', f'Analysis ID: {analysis.id}')
        
        # Process the files based on input type
        try:
            threat_data = {'threats': [], 'assets': [], 'risks': [], 'mitigations': []}
            diagram_data = {'components': [], 'connections': [], 'data_flows': []}
            crossmap_data = {}
            
            # Parse files based on input type selection
            if 'threat_model' in saved_files:
                threat_parser = ThreatModelParser()
                threat_data = threat_parser.parse(saved_files['threat_model'])
            
            if 'block_diagram' in saved_files:
                diagram_parser = BlockDiagramParser()
                diagram_data = diagram_parser.parse(saved_files['block_diagram'])
            
            if 'crossmap' in saved_files:
                crossmap_parser = CrossMapParser()
                crossmap_data = crossmap_parser.parse(saved_files['crossmap'])
            
            # Choose integration approach based on cross-reference source
            mitre_mappings = {}
            recommendations = []
            
            if cross_ref_source == 'mitre_attack' or cross_ref_source == 'both':
                mitre_integrator = MitreIntegrator()
                mitre_mappings = mitre_integrator.map_threats_to_mitre(
                    threat_data.get('threats', []),
                    crossmap_data
                )
                
                recommendations.extend(mitre_integrator.generate_recommendations(
                    threat_data.get('threats', []),
                    mitre_mappings,
                    threat_data.get('mitigations', [])
                ))
            
            # Add EMBED recommendations if selected
            if embed_assessment and (cross_ref_source == 'mitre_embed' or cross_ref_source == 'both'):
                recommendations.extend(embed_assessment.get('recommended_controls', []))
            
            # Store configuration and assessment data
            analysis_metadata = {
                'input_type': input_type,
                'cross_ref_source': cross_ref_source,
                'embed_assessment': embed_assessment,
                'diagram_data': diagram_data
            }
            
            # Update analysis with results
            analysis.threats = threat_data.get('threats', [])
            analysis.assets = threat_data.get('assets', [])
            analysis.risks = threat_data.get('risks', [])
            analysis.mitigations = threat_data.get('mitigations', [])
            analysis.mitre_mappings = mitre_mappings
            analysis.recommendations = recommendations
            analysis.status = 'completed'
            
            # Store metadata as JSON in a new column (you may need to add this to the model)
            if hasattr(analysis, 'metadata'):
                analysis.metadata = analysis_metadata
            
            db.session.commit()
            
            log_action('analysis_completed', f'Analysis ID: {analysis.id}')
            
            flash('Enhanced TARA analysis completed successfully!', 'success')
            return redirect(url_for('results', analysis_id=analysis.id))
            
        except Exception as e:
            app.logger.error(f"Processing error: {e}")
            analysis.status = 'failed'
            analysis.error_message = str(e)
            db.session.commit()
            
            log_action('analysis_failed', f'Analysis ID: {analysis.id}, Error: {str(e)}')
            flash(f'Analysis failed: {str(e)}', 'error')
            return redirect(url_for('upload_page'))
        
        finally:
            # Clean up temporary files
            for filepath in saved_files.values():
                try:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                except Exception as e:
                    app.logger.error(f"Failed to remove file {filepath}: {e}")
    
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        log_action('upload_error', f'Error: {str(e)}')
        flash(f'Upload failed: {str(e)}', 'error')
        return redirect(url_for('upload_page'))

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
    return redirect(url_for('upload_page'))

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
