#!/usr/bin/env python3
"""
TARA Desktop Application
Threat Assessment and Remediation Analysis - Desktop Version

A comprehensive cybersecurity threat analysis application that processes threat models, 
system architecture diagrams, and cross-mapping data to generate professional TARA documents 
with MITRE ATT&CK framework integration.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import json
import logging
from datetime import datetime
from pathlib import Path
import sys
from typing import Dict, List, Any

# Import the existing processing modules
from parsers import ThreatModelParser, BlockDiagramParser, CrossMapParser, AssetListParser
from mitre_integration import MitreIntegrator
from mitre_embed import MitreEmbedIntegrator
from pdf_generator import TaraReportGenerator
from enhanced_excel_generator import EnhancedTaraExcelGenerator


class TaraDesktopApp:
    """Main desktop application class for TARA"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("TARA - Threat Assessment and Remediation Analysis")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        
        # Configure window to handle scrolling
        self.root.minsize(800, 600)
        
        # Set up logging
        self.setup_logging()
        
        # Initialize variables
        self.threat_model_file = tk.StringVar()
        self.block_diagram_file = tk.StringVar()
        self.crossmap_file = tk.StringVar()
        self.asset_list_file = tk.StringVar()  # New: Excel asset list
        self.analysis_data = None
        
        # Enhanced configuration variables with new input types
        self.input_type = tk.StringVar(value="threat_model")
        self.cross_ref_source = tk.StringVar(value="mitre_attack")
        self.workflow_mode = tk.StringVar(value="file_input")  # file_input or questionnaire
        self.embed_properties = {
            'hardware': [],
            'system_software': [],
            'application_software': [],
            'networking': []
        }
        
        # Initialize processors first (needed for widget creation)
        self.threat_parser = ThreatModelParser()
        self.diagram_parser = BlockDiagramParser()
        self.crossmap_parser = CrossMapParser()
        self.asset_parser = AssetListParser()
        self.mitre_integrator = MitreIntegrator()
        self.embed_integrator = MitreEmbedIntegrator()
        self.report_generator = TaraReportGenerator()
        self.excel_generator = EnhancedTaraExcelGenerator()
        
        # Create GUI
        self.create_widgets()
        
        self.logger.info("TARA Desktop Application initialized")
    
    def _on_mousewheel(self, event):
        """Handle mouse wheel scrolling"""
        self.main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
    
    def _on_canvas_configure(self, event):
        """Handle canvas resize to adjust scrollable frame width"""
        canvas_width = event.width
        self.main_canvas.itemconfig(self.canvas_window, width=canvas_width)
    
    def setup_logging(self):
        """Set up logging for the application"""
        # Create logs directory if it doesn't exist
        logs_dir = Path("logs")
        logs_dir.mkdir(exist_ok=True)
        
        # Configure logging
        log_filename = logs_dir / f"tara_desktop_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def create_widgets(self):
        """Create and arrange GUI widgets with scrollable interface"""
        # Configure root window
        self.root.configure(bg='#f0f0f0')
        
        # Create main canvas and scrollbar for scrollable interface
        self.main_canvas = tk.Canvas(self.root, bg='#f0f0f0')
        self.scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=self.main_canvas.yview)
        self.scrollable_frame = ttk.Frame(self.main_canvas)
        
        # Configure scrollable frame
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))
        )
        
        # Create window in canvas
        self.canvas_window = self.main_canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Configure canvas scrolling
        self.main_canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack canvas and scrollbar
        self.main_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to canvas
        self.main_canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.scrollable_frame.bind("<MouseWheel>", self._on_mousewheel)
        
        # Main content frame
        main_frame = ttk.Frame(self.scrollable_frame, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.scrollable_frame.columnconfigure(0, weight=1)
        self.scrollable_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Bind canvas resize
        self.main_canvas.bind('<Configure>', self._on_canvas_configure)
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="TARA - Threat Assessment and Remediation Analysis",
            font=('Arial', 16, 'bold')
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Configuration section
        self.create_configuration_section(main_frame)
        
        # File upload section
        self.create_file_upload_section(main_frame)
        
        # MITRE EMBED properties section
        self.create_embed_properties_section(main_frame)
        
        # Progress and status section
        self.create_progress_section(main_frame)
        
        # Results section
        self.create_results_section(main_frame)
        
        # Buttons section
        self.create_buttons_section(main_frame)
    
    def create_configuration_section(self, parent):
        """Create enhanced configuration options section"""
        config_frame = ttk.LabelFrame(parent, text="Analysis Configuration", padding="10")
        config_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        config_frame.columnconfigure(1, weight=1)
        
        # Workflow mode selection
        ttk.Label(config_frame, text="Analysis Workflow:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        workflow_frame = ttk.Frame(config_frame)
        workflow_frame.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 15))
        
        ttk.Radiobutton(workflow_frame, text="File Input Analysis", variable=self.workflow_mode, value="file_input", command=self.on_workflow_change).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Radiobutton(workflow_frame, text="MITRE EMBED Questionnaire", variable=self.workflow_mode, value="questionnaire", command=self.on_workflow_change).grid(row=0, column=1, sticky=tk.W)
        
        # Input type selection (for file input mode)
        self.input_type_label = ttk.Label(config_frame, text="Input Document Type:", font=('Arial', 10, 'bold'))
        self.input_type_label.grid(row=2, column=0, sticky=tk.W, pady=(10, 5))
        
        self.input_frame = ttk.Frame(config_frame)
        self.input_frame.grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 15))
        
        ttk.Radiobutton(self.input_frame, text="Threat Model (.tm7/.json)", variable=self.input_type, value="threat_model").grid(row=0, column=0, sticky=tk.W, padx=(0, 15))
        ttk.Radiobutton(self.input_frame, text="Asset List (Excel)", variable=self.input_type, value="asset_list").grid(row=0, column=1, sticky=tk.W, padx=(0, 15))
        ttk.Radiobutton(self.input_frame, text="Block Diagram", variable=self.input_type, value="block_diagram").grid(row=0, column=2, sticky=tk.W, padx=(0, 15))
        ttk.Radiobutton(self.input_frame, text="Multiple Files", variable=self.input_type, value="multiple").grid(row=1, column=0, sticky=tk.W, pady=(5,0))
        
        # Cross-reference source selection
        ttk.Label(config_frame, text="Cross-Reference Framework:", font=('Arial', 10, 'bold')).grid(row=4, column=0, sticky=tk.W, pady=(10, 5))
        
        ref_frame = ttk.Frame(config_frame)
        ref_frame.grid(row=5, column=0, columnspan=2, sticky="w", pady=(0, 10))
        
        ttk.Radiobutton(ref_frame, text="MITRE ATT&CK", variable=self.cross_ref_source, value="mitre_attack", command=self.on_cross_ref_change).grid(row=0, column=0, sticky=tk.W, padx=(0, 20))
        ttk.Radiobutton(ref_frame, text="MITRE EMBED", variable=self.cross_ref_source, value="mitre_embed", command=self.on_cross_ref_change).grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        ttk.Radiobutton(ref_frame, text="Both Frameworks", variable=self.cross_ref_source, value="both", command=self.on_cross_ref_change).grid(row=0, column=2, sticky=tk.W)
    
    def create_embed_properties_section(self, parent):
        """Create MITRE EMBED device properties section"""
        self.embed_frame = ttk.LabelFrame(parent, text="MITRE EMBED Device Properties", padding="10")
        self.embed_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        self.embed_frame.columnconfigure(0, weight=1)
        
        # Initially hidden
        self.embed_frame.grid_remove()
        
        # Create notebook for categories
        self.embed_notebook = ttk.Notebook(self.embed_frame)
        self.embed_notebook.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Get device properties from MITRE EMBED integrator
        device_props = self.embed_integrator.get_device_properties_form()
        
        # Create tabs for each category
        self.embed_checkboxes = {}
        for category, properties in device_props.items():
            tab_frame = ttk.Frame(self.embed_notebook)
            self.embed_notebook.add(tab_frame, text=category.replace('_', ' ').title())
            
            # Create scrollable frame
            canvas = tk.Canvas(tab_frame, height=200)
            scrollbar = ttk.Scrollbar(tab_frame, orient="vertical", command=canvas.yview)
            scrollable_frame = ttk.Frame(canvas)
            
            scrollable_frame.bind(
                "<Configure>",
                lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
            )
            
            canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)
            
            canvas.grid(row=0, column=0, sticky="nsew")
            scrollbar.grid(row=0, column=1, sticky="ns")
            
            tab_frame.columnconfigure(0, weight=1)
            tab_frame.rowconfigure(0, weight=1)
            
            # Add checkboxes for properties
            self.embed_checkboxes[category] = {}
            row = 0
            for prop_id, description in properties.items():
                var = tk.BooleanVar()
                checkbox = ttk.Checkbutton(
                    scrollable_frame, 
                    text=f"{prop_id}: {description}",
                    variable=var
                )
                checkbox.grid(row=row, column=0, sticky="w", pady=2, padx=5)
                self.embed_checkboxes[category][prop_id] = var
                row += 1
    
    def on_cross_ref_change(self):
        """Handle cross-reference source change"""
        source = self.cross_ref_source.get()
        if source in ['mitre_embed', 'both']:
            self.embed_frame.grid()
        else:
            self.embed_frame.grid_remove()
    
    def on_workflow_change(self):
        """Handle workflow mode change"""
        mode = self.workflow_mode.get()
        if mode == "file_input":
            # Show file upload section and input type selection
            self.upload_frame.grid()
            self.input_type_label.grid()
            self.input_frame.grid()
        else:  # questionnaire mode
            # Hide file upload section and input type selection
            self.upload_frame.grid_remove()
            self.input_type_label.grid_remove()
            self.input_frame.grid_remove()
            # Force MITRE EMBED for questionnaire mode
            self.cross_ref_source.set("mitre_embed")
            self.on_cross_ref_change()
    
    def create_file_upload_section(self, parent):
        """Create enhanced file upload widgets with support for new input types"""
        # File upload frame
        self.upload_frame = ttk.LabelFrame(parent, text="File Upload", padding="10")
        self.upload_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        self.upload_frame.columnconfigure(1, weight=1)
        
        # Threat Model file (.tm7, .json, .yaml)
        self.tm_label = ttk.Label(self.upload_frame, text="Threat Model (.tm7/.json/.yaml):")
        self.tm_label.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.tm_entry = ttk.Entry(self.upload_frame, textvariable=self.threat_model_file, width=50)
        self.tm_entry.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        self.tm_button = ttk.Button(self.upload_frame, text="Browse", command=self.browse_threat_model)
        self.tm_button.grid(row=0, column=2)
        
        # Asset List file (Excel)
        self.asset_label = ttk.Label(self.upload_frame, text="Asset List (Excel .xlsx/.xls):")
        self.asset_label.grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.asset_entry = ttk.Entry(self.upload_frame, textvariable=self.asset_list_file, width=50)
        self.asset_entry.grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(10, 0))
        self.asset_button = ttk.Button(self.upload_frame, text="Browse", command=self.browse_asset_list)
        self.asset_button.grid(row=1, column=2, pady=(10, 0))
        
        # Block Diagram file
        self.bd_label = ttk.Label(self.upload_frame, text="Block Diagram (SVG/PNG/JPEG):")
        self.bd_label.grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.bd_entry = ttk.Entry(self.upload_frame, textvariable=self.block_diagram_file, width=50)
        self.bd_entry.grid(row=2, column=1, sticky="ew", padx=(0, 10), pady=(10, 0))
        self.bd_button = ttk.Button(self.upload_frame, text="Browse", command=self.browse_block_diagram)
        self.bd_button.grid(row=2, column=2, pady=(10, 0))
        
        # Cross-mapping data file
        self.cm_label = ttk.Label(self.upload_frame, text="Cross-mapping Data (JSON):")
        self.cm_label.grid(row=3, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        self.cm_entry = ttk.Entry(self.upload_frame, textvariable=self.crossmap_file, width=50)
        self.cm_entry.grid(row=3, column=1, sticky="ew", padx=(0, 10), pady=(10, 0))
        self.cm_button = ttk.Button(self.upload_frame, text="Browse", command=self.browse_crossmap)
        self.cm_button.grid(row=3, column=2, pady=(10, 0))
    
    def create_progress_section(self, parent):
        """Create progress and status widgets"""
        # Progress frame
        progress_frame = ttk.LabelFrame(parent, text="Status", padding="10")
        progress_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        progress_frame.columnconfigure(0, weight=1)
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Status label
        self.status_label = ttk.Label(progress_frame, text="Ready to process files...")
        self.status_label.grid(row=1, column=0, sticky=tk.W)
    
    def create_results_section(self, parent):
        """Create results display widgets"""
        # Results frame
        results_frame = ttk.LabelFrame(parent, text="Analysis Results", padding="10")
        results_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=(0, 20))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Results text area with scrollbar
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            height=15, 
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=('Consolas', 10)
        )
        self.results_text.grid(row=0, column=0, sticky="nsew")
    
    def create_buttons_section(self, parent):
        """Create action buttons"""
        # Buttons frame
        buttons_frame = ttk.Frame(parent)
        buttons_frame.grid(row=6, column=0, columnspan=2, pady=(0, 10))
        
        # Analyze button
        self.analyze_button = ttk.Button(
            buttons_frame, 
            text="Generate TARA Report", 
            command=self.start_analysis,
            style='Accent.TButton'
        )
        self.analyze_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Save PDF report button
        self.save_pdf_button = ttk.Button(
            buttons_frame, 
            text="Save PDF Report", 
            command=self.save_pdf_report,
            state=tk.DISABLED
        )
        self.save_pdf_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Save Excel report button
        self.save_excel_button = ttk.Button(
            buttons_frame, 
            text="Save Excel Report", 
            command=self.save_excel_report,
            state=tk.DISABLED
        )
        self.save_excel_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear button
        self.clear_button = ttk.Button(
            buttons_frame, 
            text="Clear All", 
            command=self.clear_all
        )
        self.clear_button.pack(side=tk.LEFT)
    
    def browse_threat_model(self):
        """Open file dialog for threat model file"""
        filename = filedialog.askopenfilename(
            title="Select Threat Model File",
            filetypes=[
                ("Threat Model files", "*.tm7 *.json *.yaml *.yml"),
                ("TM7 files", "*.tm7"),
                ("JSON files", "*.json"),
                ("YAML files", "*.yaml *.yml"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.threat_model_file.set(filename)
            self.log_message(f"Threat model file selected: {Path(filename).name}")
    
    def browse_asset_list(self):
        """Open file dialog for asset list Excel file"""
        filename = filedialog.askopenfilename(
            title="Select Asset List Excel File",
            filetypes=[
                ("Excel files", "*.xlsx *.xls"),
                ("XLSX files", "*.xlsx"),
                ("XLS files", "*.xls"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.asset_list_file.set(filename)
            self.log_message(f"Asset list file selected: {Path(filename).name}")
    
    def browse_block_diagram(self):
        """Open file dialog for block diagram file"""
        filename = filedialog.askopenfilename(
            title="Select Block Diagram File",
            filetypes=[
                ("Image files", "*.png *.jpg *.jpeg *.svg"),
                ("SVG files", "*.svg"),
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg *.jpeg"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.block_diagram_file.set(filename)
            self.log_message(f"Block diagram file selected: {Path(filename).name}")
    
    def browse_crossmap(self):
        """Open file dialog for cross-mapping data file"""
        filename = filedialog.askopenfilename(
            title="Select Cross-mapping Data File",
            filetypes=[
                ("JSON files", "*.json"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.crossmap_file.set(filename)
            self.log_message(f"Cross-mapping data file selected: {Path(filename).name}")
    
    def validate_files(self):
        """Validate that required files are selected based on input type"""
        errors = []
        input_type = self.input_type.get()
        
        # Check threat model file if required
        if input_type in ['threat_model', 'both']:
            if not self.threat_model_file.get():
                errors.append("Threat model file is required for selected analysis type")
            elif not os.path.exists(self.threat_model_file.get()):
                errors.append("Threat model file does not exist")
            elif not self.threat_model_file.get().lower().endswith(('.json', '.yaml', '.yml')):
                errors.append("Threat model file must be JSON or YAML format")
        
        # Check block diagram file if required
        if input_type in ['block_diagram', 'both']:
            if not self.block_diagram_file.get():
                errors.append("Block diagram file is required for selected analysis type")
            elif not os.path.exists(self.block_diagram_file.get()):
                errors.append("Block diagram file does not exist")
            elif not self.block_diagram_file.get().lower().endswith(('.svg', '.png', '.jpg', '.jpeg')):
                errors.append("Block diagram file must be SVG, PNG, or JPEG format")
        
        # Cross-mapping file is always required
        if not self.crossmap_file.get():
            errors.append("Cross-mapping data file is required")
        elif not os.path.exists(self.crossmap_file.get()):
            errors.append("Cross-mapping data file does not exist")
        elif not self.crossmap_file.get().lower().endswith('.json'):
            errors.append("Cross-mapping data file must be JSON format")
        
        return errors
    
    def start_analysis(self):
        """Start the analysis process in a separate thread"""
        # Validate files first
        errors = self.validate_files()
        if errors:
            messagebox.showerror("Validation Error", "\n".join(errors))
            return
        
        # Disable buttons and start progress
        self.analyze_button.config(state=tk.DISABLED)
        self.save_pdf_button.config(state=tk.DISABLED)
        self.save_excel_button.config(state=tk.DISABLED)
        self.progress_bar.start()
        
        # Clear previous results
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        
        # Start analysis in separate thread
        analysis_thread = threading.Thread(target=self.perform_analysis)
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def perform_analysis(self):
        """Perform enhanced threat analysis with support for multiple input types"""
        try:
            self.update_status("Starting enhanced TARA analysis...")
            self.log_message("=== Starting Enhanced TARA Analysis ===")
            
            # Determine workflow mode and input type
            workflow_mode = self.workflow_mode.get()
            input_type = self.input_type.get()
            
            if workflow_mode == "questionnaire":
                # MITRE EMBED Questionnaire Mode
                analysis_data = self._process_questionnaire_mode()
            else:
                # File Input Mode
                analysis_data = self._process_file_input_mode(input_type)
            
            # Integrate with MITRE frameworks
            analysis_data = self._integrate_mitre_frameworks(analysis_data)
            
            # Generate comprehensive analysis
            self._finalize_analysis(analysis_data)
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            self.update_status("Analysis failed!")
            self.log_message(f"ERROR: {error_msg}")
            messagebox.showerror("Analysis Error", error_msg)
        finally:
            # Re-enable buttons and stop progress
            self.root.after(0, self._analysis_complete)
    
    def _process_questionnaire_mode(self) -> Dict[str, Any]:
        """Process MITRE EMBED questionnaire responses"""
        self.update_status("Processing MITRE EMBED questionnaire...")
        self.log_message("Processing device properties from questionnaire...")
        
        # Collect selected properties
        selected_properties = {}
        for category, checkboxes in self.embed_checkboxes.items():
            selected_properties[category] = [
                prop_id for prop_id, var in checkboxes.items() if var.get()
            ]
        
        # Generate assessment from properties
        embed_assessment = self.embed_integrator.assess_device_properties(selected_properties)
        
        # Extract generated threats and assets
        threats = embed_assessment.get('threat_vectors', [])
        assets = self._generate_assets_from_properties(selected_properties)
        
        analysis_data = {
            'threats': threats,
            'assets': assets,
            'data_flows': [],
            'risks': [],
            'mitigations': embed_assessment.get('recommended_controls', []),
            'embed_assessment': embed_assessment,
            'metadata': {
                'source': 'questionnaire',
                'input_type': 'mitre_embed_questionnaire',
                'properties_count': sum(len(props) for props in selected_properties.values())
            }
        }
        
        self.log_message(f"Generated {len(threats)} threats from {analysis_data['metadata']['properties_count']} device properties")
        return analysis_data
    
    def _process_file_input_mode(self, input_type: str) -> Dict[str, Any]:
        """Process file-based input analysis"""
        self.update_status(f"Processing {input_type} input...")
        
        analysis_data = {
            'threats': [],
            'assets': [],
            'data_flows': [],
            'risks': [],
            'mitigations': [],
            'metadata': {'source': 'file_input', 'input_type': input_type}
        }
        
        if input_type == "threat_model":
            self.log_message("Parsing threat model file...")
            threat_file = self.threat_model_file.get()
            if threat_file:
                threat_data = self.threat_parser.parse(threat_file)
                analysis_data.update(threat_data)
                self.log_message(f"Loaded {len(threat_data.get('threats', []))} threats, {len(threat_data.get('assets', []))} assets")
        
        elif input_type == "asset_list":
            self.log_message("Parsing Excel asset list...")
            asset_file = self.asset_list_file.get()
            if asset_file:
                asset_data = self.asset_parser.parse(asset_file)
                analysis_data.update(asset_data)
                self.log_message(f"Loaded {len(asset_data.get('assets', []))} assets, generated {len(asset_data.get('threats', []))} threats")
        
        elif input_type == "block_diagram":
            self.log_message("Analyzing block diagram...")
            diagram_file = self.block_diagram_file.get()
            if diagram_file:
                diagram_data = self.diagram_parser.parse(diagram_file)
                analysis_data['data_flows'] = diagram_data.get('data_flows', [])
                analysis_data['assets'].extend(diagram_data.get('components', []))
                self.log_message(f"Identified {len(diagram_data.get('components', []))} components")
        
        elif input_type == "multiple":
            self.log_message("Processing multiple input files...")
            
            # Process threat model if provided
            threat_file = self.threat_model_file.get()
            if threat_file:
                threat_data = self.threat_parser.parse(threat_file)
                analysis_data['threats'].extend(threat_data.get('threats', []))
                analysis_data['assets'].extend(threat_data.get('assets', []))
                analysis_data['mitigations'].extend(threat_data.get('mitigations', []))
            
            # Process asset list if provided
            asset_file = self.asset_list_file.get()
            if asset_file:
                asset_data = self.asset_parser.parse(asset_file)
                analysis_data['assets'].extend(asset_data.get('assets', []))
                analysis_data['threats'].extend(asset_data.get('threats', []))
                analysis_data['data_flows'].extend(asset_data.get('data_flows', []))
            
            # Process block diagram if provided
            diagram_file = self.block_diagram_file.get()
            if diagram_file:
                diagram_data = self.diagram_parser.parse(diagram_file)
                analysis_data['data_flows'].extend(diagram_data.get('data_flows', []))
                analysis_data['assets'].extend(diagram_data.get('components', []))
            
            self.log_message(f"Combined analysis: {len(analysis_data['threats'])} threats, {len(analysis_data['assets'])} assets")
        
        return analysis_data
    
    def _integrate_mitre_frameworks(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Integrate analysis with MITRE frameworks"""
        cross_ref_source = self.cross_ref_source.get()
        
        if cross_ref_source in ['mitre_attack', 'both']:
            self.update_status("Mapping to MITRE ATT&CK...")
            self.log_message("Integrating with MITRE ATT&CK framework...")
            
            # Load cross-mapping data if available
            crossmap_data = {}
            crossmap_file = self.crossmap_file.get()
            if crossmap_file:
                crossmap_data = self.crossmap_parser.parse(crossmap_file)
            
            # Perform MITRE integration
            mitre_mappings = self.mitre_integrator.map_threats_to_mitre(
                analysis_data.get('threats', []),
                crossmap_data
            )
            analysis_data['mitre_mappings'] = mitre_mappings
            
            # Generate recommendations
            recommendations = self.mitre_integrator.generate_recommendations(
                analysis_data.get('threats', []),
                mitre_mappings,
                analysis_data.get('mitigations', [])
            )
            analysis_data['recommendations'] = recommendations
            
            self.log_message(f"Mapped {len(mitre_mappings.get('technique_mappings', []))} MITRE techniques")
        
        if cross_ref_source in ['mitre_embed', 'both']:
            self.update_status("Processing MITRE EMBED assessment...")
            
            # Collect EMBED properties if not already done
            if 'embed_assessment' not in analysis_data:
                selected_properties = {}
                for category, checkboxes in self.embed_checkboxes.items():
                    selected_properties[category] = [
                        prop_id for prop_id, var in checkboxes.items() if var.get()
                    ]
                
                if any(selected_properties.values()):
                    embed_assessment = self.embed_integrator.assess_device_properties(selected_properties)
                    analysis_data['embed_assessment'] = embed_assessment
                    
                    # Add EMBED controls to mitigations
                    embed_controls = embed_assessment.get('recommended_controls', [])
                    analysis_data['mitigations'].extend(embed_controls)
                    
                    self.log_message(f"Added {len(embed_controls)} MITRE EMBED controls")
        
        return analysis_data
    
    def _finalize_analysis(self, analysis_data: Dict[str, Any]):
        """Finalize analysis and prepare results"""
        self.update_status("Finalizing analysis...")
        self.log_message("Generating final analysis report...")
        
        # Store analysis data
        self.analysis_data = analysis_data
        
        # Generate analysis summary
        summary = self._generate_analysis_summary(analysis_data)
        
        # Display results
        self.root.after(0, lambda: self._display_results(summary))
        
        self.update_status("Analysis complete!")
        self.log_message("=== TARA Analysis Complete ===")
    
    def _generate_assets_from_properties(self, selected_properties: Dict[str, List[str]]) -> List[Dict[str, Any]]:
        """Generate asset list from selected device properties"""
        assets = []
        
        # Create assets based on property categories
        for category, properties in selected_properties.items():
            if properties:
                asset = {
                    'name': f'{category.replace("_", " ").title()} Component',
                    'type': category,
                    'description': f'Device component representing {category} properties',
                    'properties': properties,
                    'criticality': 'Medium'
                }
                assets.append(asset)
        
        return assets
    
    def _generate_analysis_summary(self, analysis_data: Dict[str, Any]) -> str:
        """Generate comprehensive analysis summary"""
        summary_lines = [
            "TARA ANALYSIS SUMMARY",
            "=" * 50,
            "",
            f"Analysis Type: {analysis_data.get('metadata', {}).get('input_type', 'Unknown')}",
            f"Source: {analysis_data.get('metadata', {}).get('source', 'Unknown')}",
            "",
            "RESULTS OVERVIEW:",
            f"• Threats Identified: {len(analysis_data.get('threats', []))}",
            f"• Assets Analyzed: {len(analysis_data.get('assets', []))}",
            f"• Data Flows: {len(analysis_data.get('data_flows', []))}",
            f"• Mitigations: {len(analysis_data.get('mitigations', []))}",
            ""
        ]
        
        # Add MITRE mappings info
        if 'mitre_mappings' in analysis_data:
            mappings = analysis_data['mitre_mappings']
            summary_lines.extend([
                "MITRE ATT&CK INTEGRATION:",
                f"• Technique Mappings: {len(mappings.get('technique_mappings', []))}",
                f"• Recommendations: {len(analysis_data.get('recommendations', []))}",
                ""
            ])
        
        # Add EMBED assessment info
        if 'embed_assessment' in analysis_data:
            embed = analysis_data['embed_assessment']
            summary_lines.extend([
                "MITRE EMBED ASSESSMENT:",
                f"• Device Properties: {len(embed.get('security_implications', {}))}",
                f"• Threat Vectors: {len(embed.get('threat_vectors', []))}",
                f"• Controls: {len(embed.get('recommended_controls', []))}",
                ""
            ])
        
        # Add threat breakdown
        threats = analysis_data.get('threats', [])
        if threats:
            threat_categories = {}
            for threat in threats:
                category = threat.get('category', 'Unknown')
                threat_categories[category] = threat_categories.get(category, 0) + 1
            
            summary_lines.extend([
                "THREAT CATEGORIES:",
                *[f"• {category}: {count}" for category, count in threat_categories.items()],
                ""
            ])
        
        summary_lines.extend([
            "Analysis completed successfully.",
            "Use 'Save PDF Report' or 'Save Excel Report' to export results."
        ])
        
        return "\n".join(summary_lines)
    
    def _display_results(self, summary: str):
        """Display analysis results in the text widget"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, summary)
        self.results_text.config(state=tk.DISABLED)
        
        # Scroll to top
        self.results_text.see(1.0)
    
    def _analysis_complete(self):
        """Re-enable UI elements after analysis completion"""
        self.progress_bar.stop()
        self.analyze_button.config(state=tk.NORMAL)
        self.save_pdf_button.config(state=tk.NORMAL)
        self.save_excel_button.config(state=tk.NORMAL)
    
    def save_pdf_report(self):
        """Save the TARA report as PDF"""
        if not self.analysis_data:
            messagebox.showerror("Error", "No analysis data available to save")
            return
        
        # Get save location
        filename = filedialog.asksaveasfilename(
            title="Save TARA Report",
            defaultextension=".pdf",
            filetypes=[
                ("PDF files", "*.pdf"),
                ("All files", "*.*")
            ],
            initialfile=f"TARA_Report_{self.analysis_data['id']}.pdf"
        )
        
        if not filename:
            return
        
        try:
            self.update_status("Generating PDF report...")
            self.log_message("Generating PDF report...")
            
            # Create a mock analysis object for the report generator
            class MockAnalysis:
                def __init__(self, data):
                    for key, value in data.items():
                        setattr(self, key, value)
            
            analysis_obj = MockAnalysis(self.analysis_data)
            
            # Generate PDF
            temp_pdf_path = self.report_generator.generate_report(analysis_obj)
            
            # Copy to desired location
            import shutil
            shutil.copy2(temp_pdf_path, filename)
            
            # Clean up temporary file
            if os.path.exists(temp_pdf_path):
                os.remove(temp_pdf_path)
            
            self.update_status("Report saved successfully!")
            self.log_message(f"Report saved to: {filename}")
            messagebox.showinfo("Success", f"TARA report saved successfully to:\n{filename}")
            
        except Exception as e:
            error_msg = f"Failed to save report: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            self.update_status("Failed to save report!")
            messagebox.showerror("Save Error", error_msg)
    
    def save_excel_report(self):
        """Save the TARA report as Excel"""
        if not self.analysis_data:
            messagebox.showerror("Error", "No analysis data available to save")
            return
        
        # Get save location
        filename = filedialog.asksaveasfilename(
            title="Save TARA Excel Report",
            defaultextension=".xlsx",
            filetypes=[
                ("Excel files", "*.xlsx"),
                ("All files", "*.*")
            ],
            initialfile=f"TARA_Excel_Report_{self.analysis_data['id']}.xlsx"
        )
        
        if not filename:
            return
        
        try:
            self.update_status("Generating Excel report...")
            self.log_message("Generating Excel report...")
            
            # Collect EMBED properties if selected
            embed_assessment = None
            if self.cross_ref_source.get() in ['mitre_embed', 'both']:
                selected_properties = {}
                for category, checkboxes in self.embed_checkboxes.items():
                    selected_properties[category] = [
                        prop_id for prop_id, var in checkboxes.items() if var.get()
                    ]
                
                if any(selected_properties.values()):
                    embed_assessment = self.embed_integrator.assess_device_properties(selected_properties)
            
            # Generate Excel report
            excel_path = self.excel_generator.generate_excel_report(
                self.analysis_data,
                self.input_type.get(),
                self.cross_ref_source.get(),
                embed_assessment
            )
            
            # Copy to desired location
            import shutil
            shutil.copy2(excel_path, filename)
            
            # Clean up temporary file
            if os.path.exists(excel_path):
                os.remove(excel_path)
            
            self.update_status("Excel report saved successfully!")
            self.log_message(f"Excel report saved to: {filename}")
            messagebox.showinfo("Success", f"TARA Excel report saved successfully to:\n{filename}")
            
        except Exception as e:
            error_msg = f"Failed to save Excel report: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            self.update_status("Failed to save Excel report!")
            messagebox.showerror("Save Error", error_msg)
    
    def clear_all(self):
        """Clear all inputs and results"""
        self.threat_model_file.set("")
        self.block_diagram_file.set("")
        self.crossmap_file.set("")
        self.analysis_data = None
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        
        self.save_pdf_button.config(state=tk.DISABLED)
        self.save_excel_button.config(state=tk.DISABLED)
        self.update_status("Ready to process files...")
        self.log_message("All fields cleared")
    
    def update_status(self, message):
        """Update status label (thread-safe)"""
        self.root.after(0, lambda: self.status_label.config(text=message))
    
    def log_message(self, message):
        """Log message to both logger and results area"""
        self.logger.info(message)
        # Also display in results if it's available
        if hasattr(self, 'results_text'):
            self.root.after(0, lambda: self._append_to_results(f"[{datetime.now().strftime('%H:%M:%S')}] {message}"))
    
    def _append_to_results(self, message):
        """Append message to results text area (main thread only)"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, message + "\n")
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)


def main():
    """Main function to run the application"""
    # Create the main window
    root = tk.Tk()
    
    # Set up the application style
    style = ttk.Style()
    try:
        # Try to use a modern theme if available
        style.theme_use('clam')
    except:
        # Fall back to default theme
        pass
    
    # Create and run the application
    app = TaraDesktopApp(root)
    
    # Center the window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")
    
    # Start the GUI event loop
    root.mainloop()


if __name__ == "__main__":
    main()