import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time


class AuditorDashboard:
    """
    Modern dashboard for Wi-Fi AI Auditor.
    
    Provides real-time visualization of the audit process with
    start/stop controls and immediate success notification.
    """
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Wi-Fi AI Auditor - Security Testing Dashboard")
        self.root.geometry("900x700")
        self.root.configure(bg='#1e1e1e')
        
        self._running = False
        self._setup_styles()
        self._create_widgets()
        
    def _setup_styles(self):
        """Configure ttk styles for dark theme."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Colors
        bg_color = '#1e1e1e'
        fg_color = '#ffffff'
        accent_color = '#007acc'
        
        style.configure('Dashboard.TFrame', background=bg_color)
        style.configure('Dashboard.TLabel', background=bg_color, 
                       foreground=fg_color, font=('Segoe UI', 10))
        style.configure('Dashboard.TButton', font=('Segoe UI', 10))
        style.configure('Header.TLabel', background=bg_color,
                       foreground=fg_color, font=('Segoe UI', 16, 'bold'))
        
    def _create_widgets(self):
        """Create dashboard widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, style='Dashboard.TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        header = ttk.Label(main_frame, text="Wi-Fi AI Auditor", 
                        style='Header.TLabel')
        header.pack(pady=(0, 20))
        
        # Configuration section
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", 
                                      padding=10)
        config_frame.pack(fill=tk.X, pady=10)
        
        # Capture file selection
        ttk.Label(config_frame, text="Capture File:").grid(row=0, column=0, 
                                                           sticky=tk.W)
        self.capture_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.capture_var, 
                 width=50).grid(row=0, column=1, padx=5)
        ttk.Button(config_frame, text="Browse", 
                  command=self._browse_capture).grid(row=0, column=2)
        
        # Strategy selection
        ttk.Label(config_frame, text="Strategy:").grid(row=1, column=0, 
                                                     sticky=tk.W, pady=5)
        self.strategy_var = tk.StringVar(value="alphanumeric")
        strategies = ["numeric", "lowercase", "uppercase", "alphanumeric", 
                       "ai-prioritized"]
        ttk.Combobox(config_frame, textvariable=self.strategy_var, 
                    values=strategies, state='readonly').grid(row=1, column=1, 
                                                            sticky=tk.W)
        
        # Length configuration
        ttk.Label(config_frame, text="Min Length:").grid(row=2, column=0, 
                                                         sticky=tk.W)
        self.min_len_var = tk.IntVar(value=8)
        ttk.Spinbox(config_frame, from_=1, to=64, 
                   textvariable=self.min_len_var, width=5).grid(row=2, column=1, 
                                                                sticky=tk.W)
        
        ttk.Label(config_frame, text="Max Length:").grid(row=2, column=1, 
                                                         sticky=tk.E, padx=(50, 0))
        self.max_len_var = tk.IntVar(value=8)
        ttk.Spinbox(config_frame, from_=1, to=64, 
                   textvariable=self.max_len_var, width=5).grid(row=2, column=2, 
                                                                sticky=tk.W)
        
        # Workers
        ttk.Label(config_frame, text="Workers:").grid(row=3, column=0, 
                                                      sticky=tk.W, pady=5)
        self.workers_var = tk.IntVar(value=4)
        ttk.Spinbox(config_frame, from_=1, to=32, 
                   textvariable=self.workers_var, width=5).grid(row=3, column=1, 
                                                                sticky=tk.W)
        
        # AI Options
        self.ai_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(config_frame, text="Enable AI Prioritization", 
                       variable=self.ai_var).grid(row=4, column=0, 
                                                  columnspan=2, sticky=tk.W)
        
        ttk.Label(config_frame, text="Organization:").grid(row=5, column=0, 
                                                           sticky=tk.W)
        self.org_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.org_var, 
                 width=30).grid(row=5, column=1, sticky=tk.W)
        
        # Status section
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding=10)
        status_frame.pack(fill=tk.X, pady=10)
        
        self.status_labels = {}
        status_items = [
            ('target', 'Target:'),
            ('mode', 'Mode:'),
            ('charset', 'Character Set:'),
            ('length', 'Password Length:'),
            ('rate', 'Testing Rate:'),
            ('tested', 'Candidates Tested:'),
            ('progress', 'Progress:'),
            ('workers', 'Worker Status:'),
            ('time', 'Elapsed Time:'),
        ]
        
        for i, (key, label) in enumerate(status_items):
            ttk.Label(status_frame, text=label).grid(row=i, column=0, 
                                                     sticky=tk.W)
            self.status_labels[key] = ttk.Label(status_frame, text="-")
            self.status_labels[key].grid(row=i, column=1, sticky=tk.W)
            
        # Progress bar
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var,
                                           maximum=100, length=400, mode='determinate')
        self.progress_bar.grid(row=len(status_items), column=0, columnspan=2, 
                              pady=10, sticky=tk.EW)
        
        # Control buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)
        
        self.start_btn = ttk.Button(btn_frame, text="Start Audit", 
                                   command=self._start_audit)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", 
                                  command=self._stop_audit, state='disabled')
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Log output
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_frame, height=10, bg='#2d2d2d', 
                               fg='#d4d4d4', font=('Consolas', 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text['yscrollcommand'] = scrollbar.set
        
    def _browse_capture(self):
        """Open file browser for capture file."""
        filename = filedialog.askopenfilename(
            title="Select Capture File",
            filetypes=[("Capture files", "*.cap *.pcap *.pcapng"),
                      ("All files", "*.*")]
        )
        if filename:
            self.capture_var.set(filename)
            
    def _log(self, message: str):
        """Add message to log."""
        self.log_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_text.see(tk.END)
        
    def _update_status(self, key: str, value: str):
        """Update status label."""
        if key in self.status_labels:
            self.status_labels[key].config(text=value)
            
    def _start_audit(self):
        """Start the audit process."""
        capture_path = self.capture_var.get()
        if not capture_path:
            messagebox.showerror("Error", "Please select a capture file")
            return
            
        # Authorization dialog
        if not messagebox.askyesno("Authorization Required",
            "Do you confirm that you own this network or have explicit "
            "permission to perform this security test?"):
            return
            
        self._running = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
        self._log("Starting audit...")
        self._update_status('target', capture_path)
        self._update_status('mode', 'AI-assisted' if self.ai_var.get() else 'Deterministic')
        
        # Start in thread
        self.audit_thread = threading.Thread(target=self._run_audit)
        self.audit_thread.daemon = True
        self.audit_thread.start()
        
    def _run_audit(self):
        """Run the audit (in thread)."""
        try:
            from config import AuditConfig, GenerationStrategy
            
            config = AuditConfig(
                capture_path=self.capture_var.get(),
                strategy=GenerationStrategy.ALPHANUMERIC,  # Simplified for GUI
                min_length=self.min_len_var.get(),
                max_length=self.max_len_var.get(),
                use_ai=self.ai_var.get(),
                organization=self.org_var.get() or None,
                max_workers=self.workers_var.get()
            )
            
            # Import here to avoid issues if modules not fully implemented
            from cli import run_audit
            
            result = run_audit(config, skip_auth=True)
            
            if result:
                self.root.after(0, lambda: self._show_success(result))
            else:
                self.root.after(0, lambda: self._log("Audit completed - password not found"))
                
        except Exception as e:
            self.root.after(0, lambda: self._log(f"Error: {str(e)}"))
        finally:
            self.root.after(0, self._audit_finished)
            
    def _show_success(self, password: str):
        """Show success dialog."""
        messagebox.showinfo("SUCCESS", 
            f"Password discovered!\n\nPassword: {password}\n\n"
            "Please handle this information securely.")
        self._log(f"SUCCESS - Password found")
        
    def _audit_finished(self):
        """Clean up after audit."""
        self._running = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
    def _stop_audit(self):
        """Stop the audit."""
        self._log("Stopping audit...")
        self._running = False
        # Signal cancellation to workers
        # (Implementation would need access to success_detector)
        
    def run(self):
        """Start the GUI."""
        self.root.mainloop()


def launch_gui():
    """Launch the GUI dashboard."""
    dashboard = AuditorDashboard()
    dashboard.run()
