# TARA - Threat Assessment and Remediation Analysis

## Overview

TARA is a comprehensive cybersecurity threat analysis application that processes threat models, system architecture diagrams, and cross-mapping data to generate professional TARA documents with MITRE ATT&CK framework integration. The application is designed as both a web-based Flask application and a desktop Tkinter application, providing flexibility for different deployment scenarios.

## System Architecture

### Frontend Architecture
- **Web Interface**: Flask-based web application with Bootstrap-themed UI
- **Desktop Interface**: Tkinter-based desktop application for local processing
- **File Upload System**: Supports multiple file types including JSON, YAML, SVG, PNG, JPEG, and Excel files
- **Real-time Progress Tracking**: Live status updates during analysis processing

### Backend Architecture
- **Flask Web Framework**: RESTful API endpoints for file processing and analysis
- **SQLAlchemy ORM**: Database abstraction layer with SQLite as primary database
- **Modular Parser System**: Separate parsers for different file types (threat models, block diagrams, cross-mapping data)
- **MITRE Framework Integration**: Dedicated modules for MITRE ATT&CK and MITRE EMBED frameworks
- **Report Generation**: PDF and Excel report generators using ReportLab and openpyxl

## Key Components

### Core Processing Modules
1. **parsers.py**: Multi-format file parsing (JSON, YAML, TM7, SVG, PNG, Excel)
2. **mitre_integration.py**: MITRE ATT&CK framework integration and threat mapping
3. **mitre_embed.py**: MITRE EMBED framework for IoT/embedded device security assessment
4. **pdf_generator.py**: Professional PDF report generation using ReportLab
5. **enhanced_excel_generator.py**: Comprehensive Excel report generation with formatting

### Data Models
- **Analysis Model**: Stores analysis results, metadata, and processing status
- **AuditLog Model**: Security audit logging for all user actions and system events
- **Session Management**: UUID-based session tracking for security and audit purposes

### File Processing Pipeline
1. **Input Validation**: Secure file type validation and sanitization
2. **Multi-format Parsing**: Support for threat models (.tm7, .json, .yaml), diagrams (SVG, PNG), and asset lists (Excel)
3. **MITRE Framework Mapping**: Automatic cross-referencing with ATT&CK techniques and EMBED controls
4. **Report Generation**: Professional PDF and Excel output with customizable formatting

## Data Flow

1. **File Upload**: Users upload threat models, block diagrams, and/or cross-mapping data
2. **Validation & Parsing**: Files are validated for security and parsed into normalized data structures
3. **MITRE Integration**: Threats and assets are mapped to MITRE ATT&CK techniques and EMBED controls
4. **Analysis Processing**: Risk assessment, impact analysis, and mitigation recommendations
5. **Report Generation**: Professional TARA documents in PDF and Excel formats
6. **Audit Logging**: All actions logged for security compliance and traceability

## External Dependencies

### Core Dependencies
- **Flask**: Web framework for HTTP handling and routing
- **SQLAlchemy**: Database ORM and query management
- **Werkzeug**: WSGI utilities and security features
- **Gunicorn**: WSGI HTTP server for production deployment

### File Processing
- **PyYAML**: YAML file parsing and processing
- **Pillow**: Image processing for block diagrams
- **openpyxl**: Excel file reading and writing
- **pandas**: Data manipulation and analysis

### Report Generation
- **ReportLab**: PDF generation with professional formatting
- **requests**: HTTP client for MITRE framework data fetching

### Security & Validation
- **email-validator**: Input validation for security
- **psycopg2-binary**: PostgreSQL database adapter (optional)

## Deployment Strategy

### Development Environment
- **Local Flask Server**: Development server with debug mode enabled
- **SQLite Database**: Lightweight database for development and testing
- **File-based Storage**: Local uploads directory for temporary file storage

### Production Environment
- **Gunicorn WSGI Server**: Production-grade HTTP server
- **PostgreSQL Database**: Scalable relational database (configurable)
- **Autoscale Deployment**: Configured for automatic scaling based on demand
- **Security Hardening**: ProxyFix middleware, secure session management, and audit logging

### Desktop Deployment
- **Standalone Tkinter Application**: No web server required
- **Local File Processing**: All analysis performed locally without network dependencies
- **Cross-platform Compatibility**: Windows, macOS, and Linux support

## Changelog

### June 17, 2025 - Major Application Restructuring
- **Two-Path Toggle Implementation**: Replaced complex multi-file input system with streamlined approach
  - Option 1: Upload threat model files (.tm7/.tb7)
  - Option 2: Complete MITRE EMB3D questionnaire
- **Enhanced Excel Template Generation**: Added always-available template generation with proper formatting
- **Universal MITRE Integration**: All assets now evaluated against both ATT&CK and EMBED frameworks regardless of input method
- **Streamlined UI**: Removed analysis framework selection, consolidated file upload sections
- **Clear All Functionality**: Added comprehensive field clearing for questionnaire responses
- **Single Consolidated Excel Output**: Replaced multi-sheet format with horizontal color-coded sections

### Previous Updates
- June 17, 2025. Initial setup

## User Preferences

Preferred communication style: Simple, everyday language.