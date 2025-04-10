#!/usr/bin/env python3
import asyncio
import json
import logging
from datetime import datetime
import customtkinter as ctk
from tkinter import scrolledtext, messagebox
import threading
import sys
import os

from netrecon import NetRecon, ScanTools

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='netrecon_gui.log'
)
logger = logging.getLogger('netrecon_gui')

class NetReconGUI:
    def __init__(self):
        self.app = ctk.CTk()
        self.app.title("NetRecon Pro")
        self.app.geometry("800x600")
        
        # Set theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Initialize scanner
        self.scanner = NetRecon()
        self.tools = ScanTools()
        
        self._create_widgets()
        
    def _create_widgets(self):
        # Target input frame
        input_frame = ctk.CTkFrame(self.app)
        input_frame.pack(pady=10, padx=10, fill="x")
        
        ctk.CTkLabel(input_frame, text="Target:").pack(side="left", padx=5)
        self.target_entry = ctk.CTkEntry(input_frame, width=300, placeholder_text="IP address or domain")
        self.target_entry.pack(side="left", padx=5)
        
        # Port input
        ctk.CTkLabel(input_frame, text="Ports:").pack(side="left", padx=5)
        self.ports_entry = ctk.CTkEntry(input_frame, width=150, placeholder_text="e.g., 80,443 or 1-1024")
        self.ports_entry.pack(side="left", padx=5)
        
        # Options frame
        options_frame = ctk.CTkFrame(self.app)
        options_frame.pack(pady=5, padx=10, fill="x")
        
        self.aggressive_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(options_frame, text="Aggressive Scan", variable=self.aggressive_var).pack(side="left", padx=5)
        
        # Save results
        self.save_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(options_frame, text="Save Results", variable=self.save_var).pack(side="left", padx=5)
        
        # Scan buttons frame
        buttons_frame = ctk.CTkFrame(self.app)
        buttons_frame.pack(pady=5, padx=10, fill="x")
        
        # Create scan buttons
        scans = [
            ("Comprehensive", self._run_comprehensive_scan),
            ("Ping", lambda: self._run_single_scan("ping")),
            ("Traceroute", lambda: self._run_single_scan("traceroute")),
            ("Nmap", lambda: self._run_single_scan("nmap")),
            ("Whois", lambda: self._run_single_scan("whois")),
            ("DNS", lambda: self._run_single_scan("dns")),
            ("SSL", lambda: self._run_single_scan("ssl"))
        ]
        
        for text, command in scans:
            ctk.CTkButton(
                buttons_frame,
                text=text,
                command=command,
                width=100
            ).pack(side="left", padx=5)
        
        # Clear button
        ctk.CTkButton(
            buttons_frame,
            text="Clear",
            command=self._clear_results,
            width=100,
            fg_color="dark red",
            hover_color="red"
        ).pack(side="right", padx=5)
        
        # Results text area with label
        results_frame = ctk.CTkFrame(self.app)
        results_frame.pack(pady=5, padx=10, fill="both", expand=True)
        
        ctk.CTkLabel(results_frame, text="Scan Results:").pack(anchor="w", padx=5, pady=2)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=20)
        self.results_text.pack(pady=5, padx=5, fill="both", expand=True)
        
    def _run_single_scan(self, scan_type):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            logger.error("No target entered for scan")
            return
            
        self._update_results(f"Starting {scan_type} scan for {target}...")
        logger.info(f"Starting {scan_type} scan for {target}")
        threading.Thread(
            target=self._async_scan,
            args=(target, scan_type),
            daemon=True
        ).start()
    
    def _run_comprehensive_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            logger.error("No target entered for comprehensive scan")
            return
            
        self._update_results(f"Starting comprehensive scan for {target}...")
        logger.info(f"Starting comprehensive scan for {target}")
        threading.Thread(
            target=self._async_scan,
            args=(target, "all"),
            daemon=True
        ).start()
    
    def _async_scan(self, target, scan_type):
        async def run():
            try:
                results = await self.scanner.comprehensive_scan(
                    target,
                    scan_type=scan_type,
                    ports=self.ports_entry.get().strip() or None,
                    aggressive=self.aggressive_var.get()
                )
                
                # Format the output
                output = json.dumps(results, indent=2)
                self._update_results(f"\nScan Results ({datetime.now().isoformat()}):\n{output}")
                logger.info(f"Scan results for {target}: {output}")
                
                # Save results if requested
                if self.save_var.get():
                    self.scanner.save_results(results)
                    self._update_results("\nResults saved to file.")
                    logger.info(f"Results saved for {target}")
                    
            except Exception as e:
                self._update_results(f"\nError during scan: {str(e)}")
                messagebox.showerror("Error", f"Scan failed: {str(e)}")
                logger.error(f"Error during scan for {target}: {str(e)}")
        
        asyncio.run(run())
    
    def _update_results(self, text):
        self.results_text.insert("end", f"{text}\n")
        self.results_text.see("end")
        
    def _clear_results(self):
        self.results_text.delete(1.0, "end")
        
    def run(self):
        self.app.mainloop()

def main():
    try:
        gui = NetReconGUI()
        gui.run()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start GUI: {str(e)}")
        logger.error(f"Failed to start GUI: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()