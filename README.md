# TARA - Threat Assessment and Remediation Analysis

A comprehensive cybersecurity threat analysis application that processes threat models, system architecture diagrams, and cross-mapping data to generate professional TARA documents with MITRE ATT&CK framework integration.

## Features

- **Threat Model Processing**: Parse JSON/YAML threat models to extract threats, assets, risks, and mitigations
- **Architecture Analysis**: Analyze system block diagrams (SVG, PNG, JPEG) to identify components and data flows
- **MITRE Integration**: Map threats to MITRE ATT&CK techniques and generate defense strategies
- **Professional Reports**: Generate comprehensive TARA documents in PDF format
- **Security-First Design**: Input validation, sanitization, and audit logging
- **Web Interface**: Clean, responsive interface for file uploads and results viewing

## Quick Start

### Prerequisites

- Python 3.8+
- Flask and dependencies (automatically installed)

### Installation

1. Clone or download the application files
2. Install dependencies:
   ```bash
   pip install flask flask-sqlalchemy pyyaml pillow reportlab requests werkzeug
   