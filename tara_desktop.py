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

# Import the existing processing modules
from parsers import ThreatModelParser, BlockDiagramParser, CrossMapParser
from mitre_integration import MitreIntegrator
from pdf_generator import TaraReportGenerator


class TaraDesktopApp:
    """Main desktop application class for TARA"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("TARA - Threat Assessment and Remediation Analysis")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Set up logging
        self.setup_logging()
        
        # Initialize variables
        self.threat_model_file = tk.StringVar()
        self.block_diagram_file = tk.StringVar()
        self.crossmap_file = tk.StringVar()
        self.analysis_data = None
        
        # Create GUI
        self.create_widgets()
        
        # Initialize processors
        self.threat_parser = ThreatModelParser()
        self.diagram_parser = BlockDiagramParser()
        self.crossmap_parser = CrossMapParser()
        self.mitre_integrator = MitreIntegrator()
        self.report_generator = TaraReportGenerator()
        
        self.logger.info("TARA Desktop Application initialized")
    
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
        """Create and arrange GUI widgets"""
        # Configure root window
        self.root.configure(bg='#f0f0f0')
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="TARA - Threat Assessment and Remediation Analysis",
            font=('Arial', 16, 'bold')
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # File upload section
        self.create_file_upload_section(main_frame)
        
        # Progress and status section
        self.create_progress_section(main_frame)
        
        # Results section
        self.create_results_section(main_frame)
        
        # Buttons section
        self.create_buttons_section(main_frame)
    
    def create_file_upload_section(self, parent):
        """Create file upload widgets"""
        # File upload frame
        upload_frame = ttk.LabelFrame(parent, text="File Upload", padding="10")
        upload_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 20))
        upload_frame.columnconfigure(1, weight=1)
        
        # Threat Model file
        ttk.Label(upload_frame, text="Threat Model (JSON/YAML):").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        ttk.Entry(upload_frame, textvariable=self.threat_model_file, width=50).grid(row=0, column=1, sticky="ew", padx=(0, 10))
        ttk.Button(upload_frame, text="Browse", command=self.browse_threat_model).grid(row=0, column=2)
        
        # Block Diagram file
        ttk.Label(upload_frame, text="Block Diagram (SVG/PNG/JPEG):").grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        ttk.Entry(upload_frame, textvariable=self.block_diagram_file, width=50).grid(row=1, column=1, sticky="ew", padx=(0, 10), pady=(10, 0))
        ttk.Button(upload_frame, text="Browse", command=self.browse_block_diagram).grid(row=1, column=2, pady=(10, 0))
        
        # Cross-mapping data file
        ttk.Label(upload_frame, text="Cross-mapping Data (JSON):").grid(row=2, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        ttk.Entry(upload_frame, textvariable=self.crossmap_file, width=50).grid(row=2, column=1, sticky="ew", padx=(0, 10), pady=(10, 0))
        ttk.Button(upload_frame, text="Browse", command=self.browse_crossmap).grid(row=2, column=2, pady=(10, 0))
    
    def create_progress_section(self, parent):
        """Create progress and status widgets"""
        # Progress frame
        progress_frame = ttk.LabelFrame(parent, text="Status", padding="10")
        progress_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 20))
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
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 20))
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
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    
    def create_buttons_section(self, parent):
        """Create action buttons"""
        # Buttons frame
        buttons_frame = ttk.Frame(parent)
        buttons_frame.grid(row=4, column=0, columnspan=2, pady=(0, 10))
        
        # Analyze button
        self.analyze_button = ttk.Button(
            buttons_frame, 
            text="Generate TARA Report", 
            command=self.start_analysis,
            style='Accent.TButton'
        )
        self.analyze_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # Save report button
        self.save_button = ttk.Button(
            buttons_frame, 
            text="Save Report as PDF", 
            command=self.save_report,
            state=tk.DISABLED
        )
        self.save_button.pack(side=tk.LEFT, padx=(0, 10))
        
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
                ("JSON files", "*.json"),
                ("YAML files", "*.yaml *.yml"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.threat_model_file.set(filename)
            self.log_message(f"Threat model file selected: {Path(filename).name}")
    
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
        """Validate that all required files are selected and exist"""
        errors = []
        
        # Check threat model file
        if not self.threat_model_file.get():
            errors.append("Threat model file is required")
        elif not os.path.exists(self.threat_model_file.get()):
            errors.append("Threat model file does not exist")
        elif not self.threat_model_file.get().lower().endswith(('.json', '.yaml', '.yml')):
            errors.append("Threat model file must be JSON or YAML format")
        
        # Check block diagram file
        if not self.block_diagram_file.get():
            errors.append("Block diagram file is required")
        elif not os.path.exists(self.block_diagram_file.get()):
            errors.append("Block diagram file does not exist")
        elif not self.block_diagram_file.get().lower().endswith(('.svg', '.png', '.jpg', '.jpeg')):
            errors.append("Block diagram file must be SVG, PNG, or JPEG format")
        
        # Check cross-mapping file
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
        self.save_button.config(state=tk.DISABLED)
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
        """Perform the threat analysis (runs in separate thread)"""
        try:
            self.update_status("Starting analysis...")
            self.log_message("=== Starting TARA Analysis ===")
            
            # Parse threat model
            self.update_status("Parsing threat model...")
            self.log_message("Parsing threat model...")
            threat_data = self.threat_parser.parse(self.threat_model_file.get())
            threats_count = len(threat_data.get('threats', []))
            assets_count = len(threat_data.get('assets', []))
            self.log_message(f"Found {threats_count} threats and {assets_count} assets")
            
            # Parse block diagram
            self.update_status("Analyzing block diagram...")
            self.log_message("Analyzing block diagram...")
            diagram_data = self.diagram_parser.parse(self.block_diagram_file.get())
            components_count = len(diagram_data.get('components', []))
            self.log_message(f"Identified {components_count} components in diagram")
            
            # Parse cross-mapping data
            self.update_status("Loading cross-mapping data...")
            self.log_message("Loading cross-mapping data...")
            crossmap_data = self.crossmap_parser.parse(self.crossmap_file.get())
            
            # Perform MITRE integration
            self.update_status("Mapping threats to MITRE ATT&CK...")
            self.log_message("Mapping threats to MITRE ATT&CK framework...")
            mitre_mappings = self.mitre_integrator.map_threats_to_mitre(
                threat_data.get('threats', []),
                crossmap_data
            )
            mappings_count = len(mitre_mappings.get('technique_mappings', []))
            self.log_message(f"Generated {mappings_count} MITRE technique mappings")
            
            # Generate recommendations
            self.update_status("Generating security recommendations...")
            self.log_message("Generating security recommendations...")
            recommendations = self.mitre_integrator.generate_recommendations(
                threat_data.get('threats', []),
                mitre_mappings,
                threat_data.get('mitigations', [])
            )
            recommendations_count = len(recommendations)
            self.log_message(f"Generated {recommendations_count} recommendations")
            
            # Store analysis data
            self.analysis_data = {
                'id': datetime.now().strftime('%Y%m%d_%H%M%S'),
                'timestamp': datetime.now(),
                'threat_model_filename': Path(self.threat_model_file.get()).name,
                'block_diagram_filename': Path(self.block_diagram_file.get()).name,
                'crossmap_filename': Path(self.crossmap_file.get()).name,
                'threats': threat_data.get('threats', []),
                'assets': threat_data.get('assets', []),
                'risks': threat_data.get('risks', []),
                'mitigations': threat_data.get('mitigations', []),
                'mitre_mappings': mitre_mappings,
                'recommendations': recommendations,
                'status': 'completed'
            }
            
            # Display results
            self.root.after(0, self.display_results)
            
            self.update_status("Analysis completed successfully!")
            self.log_message("=== Analysis Completed Successfully ===")
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            self.root.after(0, lambda: self.analysis_error(error_msg))
    
    def analysis_error(self, error_msg):
        """Handle analysis errors (runs on main thread)"""
        self.progress_bar.stop()
        self.analyze_button.config(state=tk.NORMAL)
        self.update_status("Analysis failed!")
        self.log_message(f"ERROR: {error_msg}")
        messagebox.showerror("Analysis Error", error_msg)
    
    def display_results(self):
        """Display analysis results in the text area"""
        self.progress_bar.stop()
        self.analyze_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.NORMAL)
        
        if not self.analysis_data:
            return
        
        # Build results summary
        results = []
        results.append("=== TARA ANALYSIS RESULTS ===\n")
        results.append(f"Analysis ID: {self.analysis_data['id']}")
        results.append(f"Generated: {self.analysis_data['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
        results.append(f"Status: {self.analysis_data['status'].title()}\n")
        
        # File information
        results.append("=== INPUT FILES ===")
        results.append(f"Threat Model: {self.analysis_data['threat_model_filename']}")
        results.append(f"Block Diagram: {self.analysis_data['block_diagram_filename']}")
        results.append(f"Cross-mapping Data: {self.analysis_data['crossmap_filename']}\n")
        
        # Summary statistics
        results.append("=== SUMMARY STATISTICS ===")
        results.append(f"Threats Identified: {len(self.analysis_data['threats'])}")
        results.append(f"Assets Analyzed: {len(self.analysis_data['assets'])}")
        results.append(f"MITRE Techniques Mapped: {len(self.analysis_data['mitre_mappings'].get('technique_mappings', []))}")
        results.append(f"Recommendations Generated: {len(self.analysis_data['recommendations'])}\n")
        
        # MITRE mappings summary
        if self.analysis_data['mitre_mappings'].get('tactic_coverage'):
            results.append("=== MITRE ATT&CK TACTIC COVERAGE ===")
            for tactic, count in self.analysis_data['mitre_mappings']['tactic_coverage'].items():
                results.append(f"• {tactic}: {count} technique(s)")
            results.append("")
        
        # Top threats
        if self.analysis_data['threats']:
            results.append("=== TOP IDENTIFIED THREATS ===")
            for i, threat in enumerate(self.analysis_data['threats'][:5], 1):
                results.append(f"{i}. {threat.get('name', 'Unnamed Threat')}")
                results.append(f"   Severity: {threat.get('severity', 'Unknown')}")
                results.append(f"   Category: {threat.get('category', 'Unknown')}")
                if threat.get('description'):
                    desc = threat['description'][:100] + "..." if len(threat['description']) > 100 else threat['description']
                    results.append(f"   Description: {desc}")
                results.append("")
        
        # Top recommendations
        if self.analysis_data['recommendations']:
            results.append("=== TOP PRIORITY RECOMMENDATIONS ===")
            # Sort by priority
            priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
            sorted_recs = sorted(
                self.analysis_data['recommendations'], 
                key=lambda x: priority_order.get(x.get('priority', 'Medium'), 2)
            )
            
            for i, rec in enumerate(sorted_recs[:5], 1):
                results.append(f"{i}. {rec.get('title', 'Untitled Recommendation')}")
                results.append(f"   Priority: {rec.get('priority', 'Medium')}")
                results.append(f"   Category: {rec.get('category', 'Unknown')}")
                if rec.get('description'):
                    desc = rec['description'][:100] + "..." if len(rec['description']) > 100 else rec['description']
                    results.append(f"   Description: {desc}")
                results.append("")
        
        # Display in text widget
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, "\n".join(results))
        self.results_text.config(state=tk.DISABLED)
        
        # Scroll to top
        self.results_text.see(1.0)
    
    def save_report(self):
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
            initialname=f"TARA_Report_{self.analysis_data['id']}.pdf"
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
    
    def clear_all(self):
        """Clear all inputs and results"""
        self.threat_model_file.set("")
        self.block_diagram_file.set("")
        self.crossmap_file.set("")
        self.analysis_data = None
        
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        
        self.save_button.config(state=tk.DISABLED)
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