import os
import uuid
import json
from flask import render_template, request, jsonify, send_file, flash, redirect, url_for, session
from werkzeug.utils import secure_filename
from app import app, db
from models import Analysis, AuditLog
from parsers import Embed3dCsvParser
from mitre_integration import MitreIntegrator
from mitre_embed import MitreEmbedIntegrator
from enhanced_excel_generator import EnhancedTaraExcelGenerator
import logging

# Allowed file extensions - EMB3D focused only
ALLOWED_EXTENSIONS = {
    'embed3d_csv': {'csv'}
}

def allowed_file(filename, file_type):
    """Check if file extension is allowed for the given file type"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

def log_action(action, details=None):
    """Log security audit information"""
    try:
        audit_log = AuditLog()
        audit_log.session_id = session.get('session_id', 'unknown')
        audit_log.action = action
        audit_log.details = details
        audit_log.ip_address = request.remote_addr
        audit_log.user_agent = request.headers.get('User-Agent', '')
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
    """Handle EMB3D CSV heatmap uploads and questionnaire processing"""
    session_id = session.get('session_id', str(uuid.uuid4()))
    session['session_id'] = session_id
    
    try:
        # Get configuration from form - EMB3D focused only
        input_type = request.form.get('selected_input_type', 'embed3d_questionnaire')
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
        
        # Handle EMB3D-only file uploads
        files = {}
        if 'embed3d_csv' in request.files:
            file = request.files['embed3d_csv']
            if file.filename != '' and allowed_file(file.filename, 'embed3d_csv'):
                files['embed3d_csv'] = file
                app.logger.info(f"CSV file uploaded: {file.filename}")
            elif file.filename != '':
                flash('Please upload a valid CSV file from MITRE EMB3D website', 'error')
                return redirect(url_for('upload_page'))
        
        # Create analysis record for EMB3D
        analysis = Analysis()
        analysis.session_id = session_id
        analysis.status = 'processing'
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
            
            # Parse EMB3D CSV heatmap if provided
            if 'embed3d_csv' in saved_files:
                csv_parser = Embed3dCsvParser()
                csv_data = csv_parser.parse(saved_files['embed3d_csv'])
                
                # Extract device properties and generate assessment
                embed_integrator = MitreEmbedIntegrator()
                device_properties = csv_data.get('device_properties', {})
                embed_assessment = embed_integrator.assess_device_properties(device_properties)
                
                app.logger.info(f"CSV processed: {len(device_properties)} property categories found")
                app.logger.info(f"Device properties: {device_properties}")
                
                # Generate threat and asset data
                threat_data['threats'] = embed_assessment.get('threat_vectors', [])
                threat_data['mitigations'] = embed_assessment.get('recommended_controls', [])
            
            # EMB3D-focused threat mapping and recommendations
            mitre_mappings = {}
            recommendations = []
            
            # Always use MITRE EMBED for EMB3D-focused analysis
            if embed_assessment:
                recommendations.extend(embed_assessment.get('recommended_controls', []))
            elif 'embed3d_csv' in saved_files:
                # If CSV was uploaded but assessment failed, log it
                app.logger.error("CSV file was uploaded but embed_assessment is None")
            
            # Optional MITRE ATT&CK mapping for additional context
            if threat_data.get('threats'):
                mitre_integrator = MitreIntegrator()
                mitre_mappings = mitre_integrator.map_threats_to_mitre(
                    threat_data.get('threats', []),
                    {}  # No crossmap data needed for EMB3D
                )
            
            # Store configuration and assessment data
            analysis_metadata = {
                'input_type': input_type,
                'embed_assessment': embed_assessment
            }
            
            # Update analysis with results
            analysis.threats = threat_data.get('threats', [])
            analysis.assets = threat_data.get('assets', [])
            analysis.risks = threat_data.get('risks', [])
            analysis.mitigations = threat_data.get('mitigations', [])
            analysis.mitre_mappings = mitre_mappings
            analysis.recommendations = recommendations
            analysis.status = 'completed'
            
            # Store metadata as JSON string for compatibility
            if hasattr(analysis, 'metadata'):
                import json as json_lib
                analysis.metadata = json_lib.dumps(analysis_metadata)
            
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
        # PDF generation removed - redirect to Excel download instead
        flash('PDF reports have been replaced with enhanced Excel reports', 'info')
        return redirect(url_for('download_excel_report', analysis_id=analysis_id))
    
    except Exception as e:
        app.logger.error(f"Report generation error: {e}")
        log_action('report_generation_failed', f'Analysis ID: {analysis_id}, Error: {str(e)}')
        flash(f'Failed to generate report: {str(e)}', 'error')
        return redirect(url_for('results', analysis_id=analysis_id))

@app.route('/demo')
def demo():
    """Load demo data for easy testing"""
    session_id = session.get('session_id', str(uuid.uuid4()))
    session['session_id'] = session_id
    
    # Create demo analysis with sample EMB3D data
    analysis = Analysis()
    analysis.session_id = session_id
    analysis.status = 'completed'
    analysis.threats = [
        {"id": "T1", "name": "Hardware Debug Access", "severity": "High"},
        {"id": "T2", "name": "Firmware Tampering", "severity": "Medium"},
        {"id": "T3", "name": "Communication Interception", "severity": "High"}
    ]
    analysis.assets = [
        {"id": "A1", "name": "IoT Device", "type": "Hardware"},
        {"id": "A2", "name": "Firmware", "type": "Software"},
        {"id": "A3", "name": "Communication Channel", "type": "Network"}
    ]
    analysis.mitigations = [
        {"id": "M1", "name": "Disable Debug Interfaces", "category": "Hardware"},
        {"id": "M2", "name": "Code Signing", "category": "Software"},
        {"id": "M3", "name": "Encryption", "category": "Communication"}
    ]
    
    db.session.add(analysis)
    db.session.commit()
    
    flash('Demo analysis created successfully!', 'success')
    return redirect(url_for('results', analysis_id=analysis.id))

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
