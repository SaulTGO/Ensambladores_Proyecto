import tkinter as tk
from tkinter import ttk, filedialog
import math
import re
from Analyzer import AsmAnalyzer

class AsmAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Analizador de programa en lengaje ensamblador")

        # Get screen width and height
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        # Calculate window size (90% of screen size)
        window_width = int(screen_width * 0.9)
        window_height = int(screen_height * 0.9)

        # Center the window
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        # Set window size and position
        self.root.geometry(f'{window_width}x{window_height}+{x}+{y}')

        # Make window resizable
        self.root.resizable(True, True)

        self.analyzer = AsmAnalyzer()

        self.lines_per_page = 20

        self.current_page = {
            'source': 1,
            'symbol_table': 1,
            'instruction_verification': 1
        }

        self.verification_results = []
        self.source_code_with_details = []
        
        self.setup_gui()    

    def setup_gui(self):
        # Configure root grid
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(0, weight=3)  # Source and Symbol Table
        main_frame.grid_rowconfigure(1, weight=2)  # Instruction Verification
        main_frame.grid_rowconfigure(2, weight=0)  # File selection

        # Sección de Código Fuente
        source_frame = ttk.LabelFrame(main_frame, text="Código Fuente", padding="10")
        source_frame.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        source_frame.grid_columnconfigure(0, weight=1)
        source_frame.grid_rowconfigure(0, weight=1)

        self.source_text = tk.Text(source_frame, wrap=tk.NONE, font=('Consolas', 10))
        self.source_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        source_scrollbar_y = ttk.Scrollbar(source_frame, orient=tk.VERTICAL, command=self.source_text.yview)
        source_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        source_scrollbar_x = ttk.Scrollbar(source_frame, orient=tk.HORIZONTAL, command=self.source_text.xview)
        source_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))

        self.source_text.configure(yscrollcommand=source_scrollbar_y.set, xscrollcommand=source_scrollbar_x.set)

        # Sección de Tabla de Símbolos
        symbol_table_frame = ttk.LabelFrame(main_frame, text="Tabla de Símbolos", padding="10")
        symbol_table_frame.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        symbol_table_frame.grid_columnconfigure(0, weight=1)
        symbol_table_frame.grid_rowconfigure(0, weight=1)

        self.symbol_table_tree = ttk.Treeview(symbol_table_frame,
                                              columns=('Símbolo', 'Tipo', 'Valor', 'Tamaño', 'Dirección'),
                                              show='headings'
                                              )
        for col in ('Símbolo', 'Tipo', 'Valor', 'Tamaño', 'Dirección'):
            self.symbol_table_tree.heading(col, text=col)
            self.symbol_table_tree.column(col, width=100, minwidth=50, stretch=tk.YES)
        self.symbol_table_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        symbol_table_scrollbar = ttk.Scrollbar(symbol_table_frame, orient=tk.VERTICAL,
                                               command=self.symbol_table_tree.yview)
        symbol_table_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.symbol_table_tree.configure(yscrollcommand=symbol_table_scrollbar.set)

        # Sección de Verificación de Instrucciones
        verification_frame = ttk.LabelFrame(main_frame, text="Verificación de Instrucciones", padding="10")
        verification_frame.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        verification_frame.grid_columnconfigure(0, weight=1)
        verification_frame.grid_rowconfigure(0, weight=1)
        verification_frame.grid_rowconfigure(1, weight=0)  # For pagination controls

        self.verification_tree = ttk.Treeview(verification_frame,
                                              columns=('Línea', 'Validación'),
                                              show='headings'
                                              )
        self.verification_tree.heading('Línea', text='Línea')
        self.verification_tree.heading('Validación', text='Validación')
        self.verification_tree.column('Línea', width=500, minwidth=200, stretch=tk.YES)
        self.verification_tree.column('Validación', width=500, minwidth=200, stretch=tk.YES)
        self.verification_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        verification_scrollbar = ttk.Scrollbar(verification_frame, orient=tk.VERTICAL,
                                               command=self.verification_tree.yview)
        verification_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.verification_tree.configure(yscrollcommand=verification_scrollbar.set)

        # Pagination controls
        pagination_frame = ttk.Frame(verification_frame)
        pagination_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.page_label = ttk.Label(pagination_frame, text="Página 1/1")
        self.page_label.pack(side=tk.LEFT, padx=10)

        prev_button = ttk.Button(pagination_frame, text="Anterior",
                                 command=lambda: self.prev_page('instruction_verification'))
        prev_button.pack(side=tk.LEFT, padx=5)

        next_button = ttk.Button(pagination_frame, text="Siguiente",
                                 command=lambda: self.next_page('instruction_verification'))
        next_button.pack(side=tk.LEFT, padx=5)

        # Sección de Carga de Archivo
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))
        file_frame.grid_columnconfigure(1, weight=1)

        self.file_path_var = tk.StringVar()
        ttk.Button(file_frame, text="Seleccionar Archivo", command=self.load_file).grid(row=0, column=0, padx=5)
        ttk.Label(file_frame, textvariable=self.file_path_var, wraplength=600).grid(row=0, column=1,
                                                                                    sticky=(tk.W, tk.E))
    
        # Add pagination controls for source code
        source_pagination_frame = ttk.Frame(source_frame)
        source_pagination_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)

        self.source_page_label = ttk.Label(source_pagination_frame, text="Página 1/1")
        self.source_page_label.pack(side=tk.LEFT, padx=10)

        source_prev_button = ttk.Button(source_pagination_frame, text="Anterior",
                                        command=lambda: self.prev_page('source'))
        source_prev_button.pack(side=tk.LEFT, padx=5)

        source_next_button = ttk.Button(source_pagination_frame, text="Siguiente",
                                        command=lambda: self.next_page('source'))
        source_next_button.pack(side=tk.LEFT, padx=5)

    def load_file(self):
        file_path = self.analyzer.select_file()
        if file_path:
            self.file_path_var.set(file_path)
            self.analyzer.parse_file(file_path)
            
            # Reset source code pagination when loading a new file
            self.current_page['source'] = 1
            
            # Store source code with details
            self.source_code_with_details = self.analyzer.get_source_with_details()
            
            self.update_all_displays()

    def update_all_displays(self):
        # Reset verification results when loading a new file
        self.verification_results = []

        # Call update methods
        self.update_source_code()
        self.update_symbol_table()
        self.update_instruction_verification()

    def update_source_code(self):
        self.source_text.delete('1.0', tk.END)

        # Calculate total pages
        total_pages = math.ceil(len(self.source_code_with_details) / self.lines_per_page)
        
        # Ensure current page is within bounds
        current_page = min(self.current_page['source'], total_pages)
        self.current_page['source'] = current_page

        # Calculate page range
        start_idx = (current_page - 1) * self.lines_per_page
        end_idx = start_idx + self.lines_per_page

        # Define column widths
        address_width = 15
        source_width = 45
        machine_code_width = 20

        # Create table header
        header = f"{'CP':<{address_width}}| {'Instrucción':<{source_width}}| {'Codificacion':<{machine_code_width}}"
        separator = '-' * len(header)

        self.source_text.insert(tk.END, header + '\n')
        self.source_text.insert(tk.END, separator + '\n')

        # Insert paginated source code
        page_source_code = self.source_code_with_details[start_idx:end_idx]
        for line in page_source_code:
            # Split the line into its components
            parts = line.split(' | ')
            if len(parts) == 3:
                address, instruction, machine_code = parts
                formatted_line = f"{address:<{address_width}}| {instruction:<{source_width}}| {machine_code:<{machine_code_width}}"
            else:
                # Fallback for any unexpected line format
                formatted_line = f"{'----':<{address_width}}| {line:<{source_width}}| {'Sin procesamiento':<{machine_code_width}}"

            self.source_text.insert(tk.END, formatted_line + '\n')

        # Optional: Add some styling to make the header stand out
        self.source_text.tag_configure('header', foreground='blue', font=('Consolas', 10, 'bold'))
        self.source_text.tag_add('header', '1.0', '3.0')

        # Update page label
        self.source_page_label.config(text=f"Página {current_page}/{total_pages}")

    def update_symbol_table(self):
        for item in self.symbol_table_tree.get_children():
            self.symbol_table_tree.delete(item)

        symbol_table = self.analyzer.generate_symbol_table()

        for symbol, details in symbol_table.items():
            self.symbol_table_tree.insert('', 'end', values=(
                symbol,
                details.get('tipo', ''),
                details.get('valor', ''),
                details.get('tamaño', ''),
                details.get('dirección', '')
            ))

    def update_instruction_verification(self):
        # Limpiar entradas existentes
        for item in self.verification_tree.get_children():
            self.verification_tree.delete(item)

        # Obtener resultados de verificación
        if not self.verification_results:
            self.verification_results = self.analyzer.verify_instructions()

        # Calcular número total de páginas
        total_pages = math.ceil(len(self.verification_results) / self.lines_per_page)

        # Ajustar página actual si es mayor que el total de páginas
        current_page = min(self.current_page['instruction_verification'], total_pages)
        self.current_page['instruction_verification'] = current_page

        # Calcular índices para la página actual
        start_idx = (current_page - 1) * self.lines_per_page
        end_idx = start_idx + self.lines_per_page

        # Obtener resultados de la página actual
        page_results = self.verification_results[start_idx:end_idx]

        # Crear etiquetas de estilo para instrucciones correctas e incorrectas
        self.verification_tree.tag_configure('correct', foreground='green')
        self.verification_tree.tag_configure('incorrect', foreground='red')

        # Poblar la vista de árbol
        for original_line, verification_result in page_results:
            if verification_result == "Correcta":
                self.verification_tree.insert('', 'end', values=(original_line, verification_result), tags=('correct',))
            else:
                self.verification_tree.insert('', 'end', values=(original_line, verification_result),
                                              tags=('incorrect',))

        # Actualizar etiqueta de página
        self.page_label.config(text=f"Página {current_page}/{total_pages}")

    def prev_page(self, section_key):
        # For source code and instruction verification
        if section_key == 'source':
            total_pages = math.ceil(len(self.source_code_with_details) / self.lines_per_page)
        elif section_key == 'instruction_verification':
            total_pages = math.ceil(len(self.verification_results) / self.lines_per_page)
        else:
            return

        if self.current_page[section_key] > 1:
            # Retroceder una página
            self.current_page[section_key] -= 1
            
            # Call appropriate update method
            if section_key == 'source':
                self.update_source_code()
            elif section_key == 'instruction_verification':
                self.update_instruction_verification()

    def next_page(self, section_key):
        # For source code and instruction verification
        if section_key == 'source':
            total_pages = math.ceil(len(self.source_code_with_details) / self.lines_per_page)
        elif section_key == 'instruction_verification':
            total_pages = math.ceil(len(self.verification_results) / self.lines_per_page)
        else:
            return

        # Verificar si hay páginas siguientes
        if self.current_page[section_key] < total_pages:
            # Avanzar una página
            self.current_page[section_key] += 1
            
            # Call appropriate update method
            if section_key == 'source':
                self.update_source_code()
            elif section_key == 'instruction_verification':
                self.update_instruction_verification()

def main():
    root = tk.Tk()
    app = AsmAnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()