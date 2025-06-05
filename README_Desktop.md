# TARA Desktop Application - Threat Assessment and Remediation Analysis

A comprehensive desktop cybersecurity threat analysis application built with Tkinter that processes threat models, system architecture diagrams, and cross-mapping data to generate professional TARA documents with MITRE ATT&CK framework integration.

## Features

- **Desktop GUI Interface**: Clean, intuitive Tkinter-based interface for file uploads and analysis
- **Threat Model Processing**: Parse JSON/YAML threat models to extract threats, assets, risks, and mitigations
- **Architecture Analysis**: Analyze system block diagrams (SVG, PNG, JPEG) to identify components and data flows
- **MITRE Integration**: Map threats to MITRE ATT&CK techniques and generate defense strategies
- **Professional Reports**: Generate comprehensive TARA documents in PDF format
- **Security-First Design**: Input validation, sanitization, and audit logging
- **Real-time Progress**: Live status updates and progress indicators during analysis
- **Local Processing**: No web server required - runs entirely on your local machine

## System Requirements

- Python 3.8 or higher
- Operating System: Windows, macOS, or Linux with GUI support
- Memory: Minimum 4GB RAM recommended
- Storage: 100MB free space for application and logs

## Installation

### Prerequisites

Ensure Python 3.8+ is installed on your system:
```bash
python --version
```

### Install Dependencies

Install the required Python packages:
```bash
pip install flask flask-sqlalchemy pyyaml pillow reportlab requests werkzeug
```

Or if using uv (recommended):
```bash
uv add flask flask-sqlalchemy pyyaml pillow reportlab requests werkzeug
```

### Download Application

1. Download or clone the TARA desktop application files
2. Ensure all files are in the same directory:
   - `tara_desktop.py` (main application)
   - `parsers.py` (file parsing modules)
   - `mitre_integration.py` (MITRE framework integration)
   - `pdf_generator.py` (PDF report generation)
   - `examples/` directory (sample input files)

## Quick Start

### Running the Application

1. Open a terminal or command prompt
2. Navigate to the application directory
3. Run the desktop application:
   ```bash
   python tara_desktop.py
   ```

The TARA desktop application window will open with an intuitive interface.

### Using the Application

1. **Upload Files**:
   - Click "Browse" next to each file type to select your input files
   - **Threat Model**: JSON or YAML file containing threats, assets, and risks
   - **Block Diagram**: SVG, PNG, or JPEG system architecture diagram
   - **Cross-mapping Data**: JSON file with MITRE ATT&CK mappings

2. **Generate Analysis**:
   - Once all three files are selected, click "Generate TARA Report"
   - Monitor the progress bar and status messages
   - View real-time analysis results in the results panel

3. **Save Report**:
   - After analysis completes, click "Save Report as PDF"
   - Choose location and filename for your TARA report
   - The comprehensive PDF report will be generated and saved

## Example Files

The `examples/` directory contains sample input files to test the application:

- `threat_model_example.json`: Sample web application threat model
- `block_diagram_example.svg`: Sample system architecture diagram
- `crossmap_example.json`: Sample MITRE ATT&CK cross-mapping data

To test the application:
1. Run `python tara_desktop.py`
2. Browse and select each example file
3. Click "Generate TARA Report"
4. Save the generated PDF report

## File Format Requirements

### Threat Model (JSON/YAML)
Required structure with the following sections:
- `threats`: Array of threat objects with id, name, description, severity, likelihood
- `assets`: Array of asset objects with id, name, type, criticality
- `risks`: Array of risk objects linking threats to assets
- `mitigations`: Array of mitigation controls

### Block Diagram (SVG/PNG/JPEG)
- **SVG files**: Preferred format for component extraction
- **Image files**: PNG/JPEG supported with basic analysis
- Should show system components, connections, and data flows

### Cross-mapping Data (JSON)
Required structure with:
- `mitre_attack`: MITRE ATT&CK technique definitions
- `threat_to_technique`: Mappings from threats to MITRE techniques
- `technique_to_mitigation`: Suggested mitigations for each technique

## Generated Reports

The TARA report includes:

1. **Executive Summary**: High-level findings and statistics
2. **Threat Analysis**: Detailed threat identification and assessment
3. **MITRE ATT&CK Mappings**: Technique mappings and tactic coverage
4. **Security Recommendations**: Prioritized actionable recommendations
5. **Asset Analysis**: Critical asset inventory and dependencies
6. **Appendices**: Supporting data and technical details

## Security Features

- **Input Validation**: All uploaded files are validated for type and content
- **File Sanitization**: Protection against malicious file uploads
- **Audit Logging**: Comprehensive logging of all operations
- **Session Isolation**: Each analysis session is isolated and secure
- **Local Processing**: No data transmitted to external servers

## Troubleshooting

### Common Issues

**Application won't start:**
- Verify Python 3.8+ is installed
- Check all dependencies are installed: `pip list`
- Ensure GUI support is available (Linux users may need X11)

**File upload errors:**
- Verify file formats match requirements
- Check file permissions and accessibility
- Ensure files are not corrupted or empty

**Analysis fails:**
- Check input file formats and structure
- Review error messages in the status panel
- Examine log files in the `logs/` directory

**PDF generation fails:**
- Ensure write permissions in the save location
- Check available disk space
- Verify ReportLab dependency is installed correctly

### Log Files

Application logs are stored in the `logs/` directory with timestamps:
```
logs/tara_desktop_YYYYMMDD_HHMMSS.log
```

These logs contain detailed information about:
- File processing steps
- Analysis progress
- Error messages and stack traces
- Performance metrics

## Advanced Usage

### Custom MITRE Data

To use updated MITRE ATT&CK data:
1. Update the cross-mapping JSON file with latest technique IDs
2. Modify `mitre_integration.py` to include new techniques
3. Test with your specific threat models

### Extending Analysis

The modular design allows for extensions:
- **Custom Parsers**: Add support for additional file formats
- **Enhanced Analysis**: Implement additional threat analysis algorithms
- **Report Formats**: Add support for DOCX or other output formats

## Performance Optimization

For large files or complex analyses:
- Use SVG format for block diagrams when possible
- Optimize threat model files by removing unnecessary fields
- Close other applications to free system memory
- Use SSD storage for faster file processing

## Support and Maintenance

### Regular Updates
- Update Python dependencies monthly
- Review MITRE ATT&CK framework updates quarterly
- Update threat intelligence mappings as needed

### Backup and Recovery
- Regular backup of analysis results and custom configurations
- Export important reports to secure storage
- Maintain version control for custom modifications

## License and Compliance

This application is designed for internal cybersecurity use and includes:
- Comprehensive audit logging for compliance
- Secure handling of sensitive security data
- GDPR-compliant data processing practices
- SOC 2 Type II compatible controls

## Technical Architecture

The application uses a modular architecture:
- **GUI Layer**: Tkinter-based user interface
- **Processing Layer**: Threat analysis and MITRE integration
- **Data Layer**: File parsing and validation
- **Output Layer**: PDF report generation

All processing occurs locally with no external data transmission, ensuring complete data security and privacy.