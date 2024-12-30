import tkinter as tk
from tkinter import ttk, filedialog
import math
import re
from dictionaries import Dictionary

class AsmAnalyzer:
    def __init__(self):
        self.code_section = []
        self.data_section = []
        self.stack_section = []
        self.current_section = None
        self.original_code = []
        self.lines_per_page = 20
        self.data_address_counter = 0x0250  # Initial address for data segment
        self.code_address_counter = 0x0250  # Initial address for code segment
        self.machine_code_map = {}
        self.variables_dict = {}

        #Set dictionaries from dictionaries.py
        dicc = Dictionary()

        self.data_dict = dicc.data_dict

        self.valid_instructions = dicc.valid_instructions

        self.machine_code_reference = dicc.machine_code_reference
        
        self.instructions = dicc.instructions

        self.registers_16bit = dicc.registers_16bit

        self.registers_8bit = dicc.registers_8bit

        self.pseudo_instructions = dicc.pseudo_instructions
        
        self.constant_patterns = dicc.constant_patterns

        self.symbol_table = {}
        self.label_table = set()

    def get_constant_type(self, token):
        for pattern, const_type in self.constant_patterns.items():
            if re.match(pattern, token):
                return const_type
        return None

    def get_element_type(self, token):
        token_upper = token.upper()

        if token_upper in self.instructions:
            return self.instructions[token_upper]
        elif token_upper in self.registers_16bit:
            return self.registers_16bit[token_upper]
        elif token_upper in self.registers_8bit:
            return self.registers_8bit[token_upper]
        elif token_upper in self.pseudo_instructions:
            return self.pseudo_instructions[token_upper]

        const_type = self.get_constant_type(token)
        if const_type:
            return const_type

        return 'Símbolo'

    def remove_comments(self, line):
        line = line.strip()
        if not line:
            return ""

        code_part = ""
        in_quotes = False
        for i, char in enumerate(line):
            if char == '"' or char == "'":
                in_quotes = not in_quotes
            elif (char == ';' or char == '#') and not in_quotes:
                code_part = line[:i]
                break
        else:
            code_part = line

        return code_part.strip()

    def select_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Archivos ENS", "*.ens")],
            title="Selecciona un archivo ENS"
        )
        return file_path

    def parse_file(self, file_path):
        if not file_path:
            return

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                self.original_code = []
                # Reset address counters
                self.data_address_counter = 0x0250
                self.code_address_counter = 0x0250
                self.data_section = []
                self.code_section = []
                self.current_section = None
                self.machine_code_map = {}

                for line in file:
                    clean_line = self.remove_comments(line)
                    if clean_line:
                        self.original_code.append(clean_line.strip())

                # Two-pass parsing for addressing
                self.parse_sections()

        except Exception as e:
            print(f"Error al procesar el archivo: {str(e)}")

    def parse_sections(self):
        # First pass: parse sections and update symbol table
        self.data_section = []
        self.code_section = []
        self.stack_section = []  # New attribute to store stack section content
        self.current_section = None

        for line in self.original_code:
            # Detect section changes
            if '.CODE' in line.upper():
                self.current_section = 'code'
                continue
            elif '.DATA' in line.upper():
                self.current_section = 'data'
                continue
            elif '.STACK' in line.upper():
                self.current_section = 'stack'
                continue

            # Process differently based on section
            if self.current_section == 'data':
                self.data_section.append(line)
                self.process_data_line(line)
            elif self.current_section == 'code':
                self.code_section.append(line)
            elif self.current_section == 'stack':
                self.stack_section.append(line)

        # Second pass: generate machine code
        self.generate_machine_code()

    def process_data_line(self, line):
        parts = line.split()
        if len(parts) >= 3:
            symbol = parts[0]
            directive = parts[1].upper()
            
            # Modificación para manejar cadenas completas
            value = ' '.join(parts[2:])  # Unir todos los elementos después de la directiva
            
            # Validation 1: Check if symbol starts with a number
            if symbol[0].isdigit():
                print(f"Error: Variable name '{symbol}' cannot start with a number")
                return

            # Validation 2: Check string initialization
            if directive in ['DB', 'DW', 'DD']:
                # Check for properly initialized strings with quotes
                if value.startswith('"') and value.endswith('"'):
                    # Mantener la cadena completa, incluyendo espacios
                    value = value.strip('"')
                elif not re.match(r'^[0-9A-Fa-f]+[Hh]$|^\d+$', value):
                    print(f"Error: Invalid initialization for '{symbol}'")
                    return

            size_map = {
                'DB': 1,  # Byte
                'DW': 2,  # Word
                'DD': 4  # Double Word
            }

            if directive in size_map:
                # Add symbol to symbol table with address and size
                self.symbol_table[symbol] = {
                    'tipo': f'{directive} ({size_map[directive]} bytes)',
                    'valor': value,
                    'tamaño': size_map[directive],
                    'dirección': f'{self.data_address_counter:04X}h'
                }

                # Increment data address counter
                self.data_address_counter += size_map[directive]

    def generate_machine_code(self):
        # Reset code address counter and maps
        self.code_address_counter = 0x0250
        self.machine_code_map = {}
        label_addresses = {}  # Dictionary to store label addresses

        # Generate variables dictionary at the start
        self.generate_variables_dict()

        # Expanded addressing mode dictionary
        addressing_modes = {
            '00': 'DIRECT/MEMORY',  # Direct addressing or memory operand
            '01': 'IMMEDIATE',  # Immediate data
            '10': 'INDIRECT',  # Indirect addressing
            '11': 'REGISTER'  # Register-to-register
        }

        # Comprehensive register encoding for 16-bit and 8-bit registers
        register_encoding = {
            '16BIT': {
                'AX': '000', 'CX': '001', 'DX': '010', 'BX': '011',
                'SP': '100', 'BP': '101', 'SI': '110', 'DI': '111'
            },
            '8BIT': {
                'AL': '000', 'CL': '001', 'DL': '010', 'BL': '011',
                'AH': '100', 'CH': '101', 'DH': '110', 'BH': '111'
            }
        }

        def process_operand(operand):
            """Processes an operand and determines if it's a register, variable or immediate value"""
            operand = operand.upper()
            if operand in register_encoding['16BIT'] or operand in register_encoding['8BIT']:
                return 'register', operand
            elif operand in self.variables_dict:
                return 'variable', operand
            elif any(pattern.match(operand) for pattern in [
                re.compile(r'^[0-9A-Fa-f]+[Hh]$'),
                re.compile(r'^\d+$'),
                re.compile(r'^[01]+[Bb]$')
            ]):
                return 'immediate', operand
            return 'unknown', operand

        def encode_cmp_with_variable(reg, var_name):
            """Generates machine code for CMP with variable"""
            if var_name in self.variables_dict:
                var_info = self.variables_dict[var_name]
                is_word = var_info['tipo'].startswith('DW')

                # Base format for CMP with memory
                machine_code = '001110'  # Base opcode for CMP
                machine_code += '1'  # Direction (reg to memory)
                machine_code += '1' if is_word else '0'  # Word/Byte
                machine_code += '00'  # Direct mode
                machine_code += register_encoding['16BIT'][reg] if is_word else register_encoding['8BIT'][reg]
                machine_code += '110'  # Direct memory mode

                # Add variable address (16 bits)
                var_addr = int(var_info['dirección'].rstrip('h'), 16)
                addr_binary = format(var_addr, '016b')
                machine_code += addr_binary

                return machine_code
            return None

        def group_and_convert_to_hex(binary_str):
            """Group binary string into groups of 4 bits and convert to hex."""
            # Pad the binary string to ensure it's divisible by 4
            binary_str = binary_str.zfill((len(binary_str) + 3) // 4 * 4)

            # Group into 4-bit chunks
            groups = [binary_str[i:i + 4] for i in range(0, len(binary_str), 4)]

            # Convert each 4-bit group to hex
            hex_groups = [hex(int(group, 2))[2:].upper() for group in groups]

            return ' '.join(hex_groups)

        # First pass: collect label addresses
        current_address = self.code_address_counter
        for line in self.code_section:
            parts = line.split()
            if parts and parts[0].endswith(':'):
                label = parts[0].rstrip(':')
                label_addresses[label] = current_address
            if not line.strip().endswith(':'):  # Only increment for non-label lines
                current_address += 2  # Assuming all instructions are 2 bytes

        # Second pass: generate machine code
        for line in self.code_section:
            parts = line.split()
            if not parts:
                continue

            instruction = parts[0].upper()
            if instruction.endswith(':'):  # Skip label definitions
                continue

            try:
                machine_code_binary = ''
                addressing_mode = ''

                # Handle jump instructions
                if instruction in ['JMP', 'JE', 'JNE', 'JL', 'JLE', 'JG', 'JGE', 'JA', 'JC']:
                    if len(parts) > 1:
                        target_label = parts[1].upper()
                        if target_label in label_addresses:
                            # Get base opcode for jump instruction
                            base_opcode = self.machine_code_reference.get(instruction)
                            if base_opcode:
                                target_address = label_addresses[target_label]
                                # Calculate relative offset (target - current - 2)
                                offset = target_address - (self.code_address_counter + 2)
                                # Convert offset to 8-bit signed value
                                if -128 <= offset <= 127:
                                    offset_binary = format(offset & 0xFF, '08b')
                                    machine_code_binary = base_opcode + offset_binary
                                    addressing_mode = addressing_modes['00']
                                else:
                                    machine_code_binary = f"Error: Jump offset too large"
                            else:
                                machine_code_binary = f"Error: Unknown jump instruction"
                        else:
                            machine_code_binary = f"Error: Undefined label {target_label}"
                    else:
                        machine_code_binary = f"Error: Missing target for jump instruction"

                # Handle PUSH/POP
                elif instruction in ['PUSH', 'POP']:
                    if len(parts) > 1:
                        reg = parts[1].upper()
                        if reg in register_encoding['16BIT']:
                            machine_code_binary = (
                                    ('01010' if instruction == 'PUSH' else '01011') +
                                    register_encoding['16BIT'][reg]
                            )
                            addressing_mode = addressing_modes['11']
                        else:
                            machine_code_binary = f"Error: Invalid register {reg}"
                    else:
                        machine_code_binary = f"Error: Missing register for {instruction}"

                # Handle CMP
                elif instruction == 'CMP' and len(parts) == 3:
                    op1, op2 = parts[1].upper(), parts[2].upper()
                    op1_type, op1_val = process_operand(op1)
                    op2_type, op2_val = process_operand(op2)

                    if op1_type == 'register' and op2_type == 'variable':
                        machine_code_binary = encode_cmp_with_variable(op1_val, op2_val)
                        if machine_code_binary:
                            addressing_mode = addressing_modes['00']  # Direct mode
                        else:
                            machine_code_binary = "Error: Invalid variable reference"
                    elif op1_type == 'register' and op2_type == 'register':
                        if (op1_val in register_encoding['16BIT'] and
                                op2_val in register_encoding['16BIT']):
                            machine_code_binary = (
                                    '001110' +  # CMP opcode
                                    '1' +  # Direction bit (dest <- src)
                                    '1' +  # Word operation
                                    '11' +  # Register-to-register mode
                                    register_encoding['16BIT'][op2_val] +  # Dest register
                                    register_encoding['16BIT'][op1_val]  # Src register
                            )
                            addressing_mode = addressing_modes['11']
                        else:
                            machine_code_binary = f"Error: Invalid registers"
                    else:
                        machine_code_binary = f"Error: Invalid operand types for CMP"

                # Handle MOV
                elif instruction == 'MOV':
                    if len(parts) == 3:
                        src, dest = parts[1].upper(), parts[2].upper()

                        # Register-to-register MOV (16-bit)
                        if src in register_encoding['16BIT'] and dest in register_encoding['16BIT']:
                            machine_code_binary = (
                                    '1000100' +  # MOV opcode
                                    '1' +  # Word operation
                                    '11' +  # Register-to-register mode
                                    register_encoding['16BIT'][dest] +  # Dest register
                                    register_encoding['16BIT'][src]  # Src register
                            )
                            addressing_mode = addressing_modes['11']

                        # Register-to-register MOV (8-bit)
                        elif src in register_encoding['8BIT'] and dest in register_encoding['8BIT']:
                            machine_code_binary = (
                                    '1000100' +  # MOV opcode
                                    '0' +  # Byte operation
                                    '11' +  # Register-to-register mode
                                    register_encoding['8BIT'][dest] +  # Dest register
                                    register_encoding['8BIT'][src]  # Src register
                            )
                            addressing_mode = addressing_modes['11']
                        else:
                            machine_code_binary = f"Error: Invalid registers"
                    else:
                        machine_code_binary = f"Error: Incorrect MOV arguments"

                else:
                    # Default machine code from reference
                    machine_code_binary = self.machine_code_reference.get(instruction,
                                                                          f"Not implemented: {instruction}")
                    addressing_mode = 'UNDEFINED'

                # Convert binary to grouped hex
                machine_code_hex = group_and_convert_to_hex(machine_code_binary) if not machine_code_binary.startswith(
                    'Error') else 'Error'

                # Store machine code with address and details
                self.machine_code_map[line] = {
                    'address': f'{self.code_address_counter:04X}h',
                    'machine_code_binary': machine_code_binary,
                    'machine_code_hex': machine_code_hex,
                    'addressing_mode': addressing_mode
                }

                # Increment address (2 bytes per instruction)
                if not line.strip().endswith(':'):  # Only increment for non-label lines
                    self.code_address_counter += 2

            except Exception as e:
                self.machine_code_map[line] = {
                    'address': f'{self.code_address_counter:04X}h',
                    'machine_code_binary': f"Encoding error: {str(e)}",
                    'machine_code_hex': 'Error',
                    'addressing_mode': 'ERROR'
                }
                if not line.strip().endswith(':'):
                    self.code_address_counter += 2

    def get_source_with_details(self):
        source_details = []

        # Regenerate symbol table to ensure updated information
        self.generate_symbol_table()

        # Initialize counters for different segments
        current_code_address = 0x0250
        current_data_address = 0x0250
        current_stack_address = 0x0250
        current_segment = None

        for line in self.original_code:
            clean_line = self.remove_comments(line)
            if not clean_line:
                continue

            # Segment change detection
            if '.CODE' in line.upper():
                current_segment = 'code'
                current_code_address = 0x0250
                source_details.append(f"0250h | {line} | {'Correcto'}")
                continue
            elif '.DATA' in line.upper():
                current_segment = 'data'
                current_data_address = 0x0250
                source_details.append(f"0250h | {line} | {'Correcto'}")
                continue
            elif '.STACK' in line.upper():
                current_segment = 'stack'
                current_stack_address = 0x0250
                source_details.append(f"0250h | {line} | {'Correcto'}")
                continue

            # Process line based on current segment
            parts = clean_line.split()
            first_part = parts[0].rstrip(':')

            # Check symbol table for symbol information
            if first_part in self.symbol_table:
                symbol_info = self.symbol_table[first_part]

                if current_segment == 'data':
                    # Data segment processing
                    if symbol_info.get('tipo', '').startswith(('DB', 'DW', 'DD')):
                        size_multiplier = 1
                        size_per_element = 1  # Default to byte

                        # Check for DUP directive
                        if 'DUP' in clean_line.upper():
                            dup_match = re.search(r'(\d+)\s*DUP', clean_line.upper())
                            if dup_match:
                                size_multiplier = int(dup_match.group(1))

                        # Check for DOBLE directive
                        elif 'DOBLE' in clean_line.upper():
                            doble_match = re.search(r'(\d+)\s*DOBLE', clean_line.upper())
                            if doble_match:
                                size_multiplier = int(doble_match.group(1)) * 2

                        # Determine element size
                        if symbol_info['tipo'].startswith('DW'):
                            size_per_element = 2  # Word (16 bits)
                        elif symbol_info['tipo'].startswith('DD'):
                            size_per_element = 4  # Double word (32 bits)

                        # Calculate total size
                        total_size = size_multiplier * size_per_element

                        # Add detailed information
                        source_details.append(
                            f"{current_data_address:04X}h | {line} | Correcto"
                        )

                        # Update data address
                        current_data_address += total_size
                    else:
                        source_details.append(f"{current_data_address:04X}h | {line} | {'Correcto'}")

                elif current_segment == 'code':
                    # Si es una etiqueta (tipo 'etq'), mostrar "Correcto"
                    if symbol_info.get('tipo') == 'etq':
                        source_details.append(
                            f"{current_code_address:04X}h | {line} | {'Correcto'}"
                        )
                    else:
                        # Si la línea está en el mapa de código de máquina
                        if line in self.machine_code_map:
                            details = self.machine_code_map[line]
                            source_details.append(
                                f"{current_code_address:04X}h | {line} | {details['machine_code_hex']}")
                            # Solo incrementar si no hay error
                            if details['machine_code_hex'] != 'Error':
                                current_code_address += 2
                        else:
                            source_details.append(f"{current_code_address:04X}h | {line} | {'Error'}")

            # Lines not in symbol table
            else:
                if current_segment == 'code':
                    if line in self.machine_code_map:
                        details = self.machine_code_map[line]
                        source_details.append(f"{current_code_address:04X}h | {line} | {details['machine_code_hex']}")
                        # Increment code address by 2 only if not marked as "Error"
                        if details['machine_code_hex'] != 'Error':
                            current_code_address += 2
                    else:
                        source_details.append(f"{current_code_address:04X}h | {line} | {'Error'}")
                elif current_segment == 'data':
                    source_details.append(f"{current_data_address:04X}h | {line} | {'Error'}")
                elif current_segment == 'stack':
                    # Nueva lógica para el segmento stack
                    clean_line_lower = clean_line.lower().strip()
                    if clean_line_lower.startswith('dw'):
                        # Verificar si tiene el patrón "dw X DUP(0)"
                        dup_match = re.search(r'dw\s+(\d+)\s+dup\s*\(\s*0\s*\)', clean_line_lower)
                        if dup_match:
                            # Obtener el número X y multiplicar por 2 (tamaño de word)
                            multiplier = int(dup_match.group(1))
                            increment = multiplier * 2
                            source_details.append(f"{current_stack_address:04X}h | {line} | {'Correcto'}")
                            current_stack_address += increment
                        else:
                            source_details.append(f"{current_stack_address:04X}h | {line} | {'Error'}")
                    else:
                        source_details.append(f"{current_stack_address:04X}h | {line} | {'Error'}")

        return source_details

    def is_valid_segment_instruction(self, line):
        # Normalize the line by stripping whitespace and converting to lowercase
        line_stripped = line.strip().lower()

        # Precise patterns for valid segment instructions
        valid_segment_patterns = [
            r'^\.stack\s+segment$',    # .stack segment start
            r'^\.data\s+segment$',     # .data segment start
            r'^\.code\s+segment$',     # .code segment start
            r'^\.\w+\s+ends$',         # Any segment end (modified to allow just 'ENDS')
        ]

        import re

        # Check if the line matches any of the valid segment patterns
        for pattern in valid_segment_patterns:
            if re.match(pattern, line_stripped):
                return True

        # Check for just 'ENDS' without a segment name
        if line_stripped == 'ends':
            return True

        return False

    def get_total_pages(self):
        return math.ceil(len(self.original_code) / self.lines_per_page)

    def get_page_content(self, page_number):
        start_idx = (page_number - 1) * self.lines_per_page
        end_idx = start_idx + self.lines_per_page
        return self.original_code[start_idx:end_idx]

    def analyze_instruction(self, instruction, section):
        parts = re.split(r'[\s,]+', instruction)
        parts = [part.strip() for part in parts if part.strip()]

        result = []
        skip_next = False

        if section == 'code':
            result.append(('.code', 'Sección'))
        elif section == 'data':
            result.append(('.data', 'Sección'))
        elif section == 'stack':
            result.append(('.stack', 'Sección'))

        for i, part in enumerate(parts):
            if skip_next:
                skip_next = False
                continue

            if i < len(parts) - 1:
                combined = f"{part} {parts[i + 1]}".upper()
                if (combined == "DATA SEGMENT" or
                        combined == "CODE SEGMENT" or
                        combined == "STACK SEGMENT"):
                    result.append((part, 'Pseudoinstrucción'))
                    result.append((parts[i + 1], 'Pseudoinstrucción'))
                    skip_next = True
                    continue

            if not skip_next:
                element_type = self.get_element_type(part)
                result.append((part, element_type))

        return result

    def generate_symbol_table(self):
        # Reset address counters to initial base address
        base_address = 0x0250
        self.data_address_counter = base_address
        self.code_address_counter = base_address
        self.symbol_table = {}
        self.label_table = set()

        # First, collect label addresses from source
        current_code_address = base_address
        label_addresses = {}  # Diccionario temporal para rastrear direcciones de etiquetas
        
        for line in self.code_section:
            parts = line.split()
            
            # Verificar si es una etiqueta
            if parts and parts[0].endswith(':'):
                label = parts[0].rstrip(':')
                
                # Validaciones de la etiqueta
                if len(label) > 10:
                    print(f"Error: La etiqueta '{label}' excede 10 caracteres")
                    continue
                
                if label in self.symbol_table:
                    print(f"Error: La etiqueta '{label}' ya está definida")
                    continue
                
                if label[0].isdigit():
                    print(f"Error: El nombre de etiqueta '{label}' no puede comenzar con un número")
                    continue
                
                # Almacenar la dirección de la etiqueta
                label_addresses[label] = current_code_address
            
            # Solo incrementar la dirección de código si la línea no es solo una etiqueta
            if not line.strip().endswith(':') and line.strip():
                # Verificar si la línea está en el mapa de código de máquina
                if line in self.machine_code_map:
                    details = self.machine_code_map[line]
                    # Incrementar por 2 solo si no es "Error"
                    if details['machine_code_hex'] != 'Error':
                        current_code_address += 2
                else:
                    current_code_address += 2

        # Process stack section with improved address tracking
        current_stack_address = base_address
        stack_variables_count = 0

        for line in self.stack_section:
            parts = line.split()
            if len(parts) >= 3:
                symbol = parts[0] if not parts[0].endswith(':') else None
                directive = parts[1].upper()
                value = ' '.join(parts[2:])

                def process_value_size(directive, value):
                    size_map = {'DB': 1, 'DW': 2, 'DD': 4}
                    base_size = size_map.get(directive, 1)

                    if 'DUP' in value:
                        dup_parts = value.split('DUP')
                        dup_count = int(dup_parts[0].strip())
                        inner_value = dup_parts[1].strip('()')
                        total_size = base_size * dup_count
                        return total_size, dup_count, inner_value

                    elif 'DOUBLE' in value:
                        double_parts = value.split('DOUBLE')
                        base_value = double_parts[0].strip()
                        total_size = base_size * 2
                        return total_size, 1, base_value

                    return base_size, 1, value

                if directive not in ['DB', 'DW', 'DD']:
                    continue

                try:
                    total_size, count, inner_value = process_value_size(directive, value)

                    # Generate or use provided symbol name
                    if symbol is None:
                        stack_variable_name = f'_stack_var{stack_variables_count}'
                        stack_variables_count += 1
                    else:
                        stack_variable_name = symbol

                    # Check for duplicate variables
                    if stack_variable_name in self.symbol_table:
                        print(f"Error: Stack variable '{stack_variable_name}' already defined")
                        continue

                    # Modify tipo generation to remove (1)
                    tipo_str = directive
                    if 'DUP' in value:
                        tipo_str += f' DUP({count})'
                    elif 'DOUBLE' in value:
                        tipo_str += ' DOUBLE'

                    # Add to symbol table with correct size and address
                    self.symbol_table[stack_variable_name] = {
                        'símbolo': stack_variable_name,
                        'tipo': tipo_str,
                        'valor': inner_value,
                        'tamaño': total_size,
                        'dirección': f'{current_stack_address:04X}h'
                    }

                    # Update stack address by the total calculated size
                    current_stack_address += total_size

                except ValueError:
                    print(f"Error: Invalid value format in stack segment for {stack_variable_name}")
                    continue

        # Process data section symbols first
        for line in self.data_section:
            parts = line.split()
            if len(parts) >= 3:
                symbol = parts[0]
                directive = parts[1].upper()
                value = ' '.join(parts[2:])

                # Validation for symbol name
                if len(symbol) > 10:
                    print(f"Error: Symbol name '{symbol}' exceeds 10 characters")
                    continue

                # Check for duplicate variables ACROSS ALL TYPES
                if symbol in self.symbol_table:
                    print(f"Error: Symbol '{symbol}' already defined")
                    continue

                if symbol[0].isdigit():
                    print(f"Error: Variable name '{symbol}' cannot start with a number")
                    continue

                # Handling for constants (EQU)
                if directive == 'EQU':
                    if self.get_constant_type(value):
                        self.symbol_table[symbol] = {
                            'símbolo': symbol,
                            'tipo': 'const',
                            'valor': value,
                            'tamaño': 2,
                            'dirección': f'{self.data_address_counter:04X}h'
                        }
                        # Increment address for constants
                        self.data_address_counter += 2
                    else:
                        print(f"Error: Invalid constant value for '{symbol}'")
                    continue

                # Handling for DB, DW, DD directives
                if directive in ['DB', 'DW', 'DD']:
                    def convert_value(val):
                        val = val.strip('"')
                        if val.upper().endswith('H'):
                            return int(val[:-1], 16)
                        elif val.upper().endswith('B'):
                            return int(val[:-1], 2)
                        elif val.upper().endswith('O'):
                            return int(val[:-1], 8)
                        elif val.startswith('0X'):
                            return int(val, 16)
                        else:
                            return int(val)

                    # Handle DUP statement
                    dup_count = None
                    if 'DUP' in value:
                        dup_parts = value.split('DUP')
                        dup_count = int(dup_parts[0].strip())
                        value = dup_parts[1].strip('()')

                    try:
                        # Determine type and size based on directive
                        size_map = {'DB': 1, 'DW': 2, 'DD': 4}
                        tamaño = size_map[directive]

                        # Convert value and calculate total size for DUP
                        numeric_value = convert_value(value)
                        total_size = tamaño * (dup_count if dup_count is not None else 1)

                        # Add symbol to symbol table
                        self.symbol_table[symbol] = {
                            'símbolo': symbol,
                            'tipo': f'{directive}{"" if dup_count is None else f" DUP({dup_count})"}',
                            'valor': value,
                            'tamaño': total_size,
                            'dirección': f'{self.data_address_counter:04X}h'
                        }

                        # Increment address counter by total size
                        self.data_address_counter += total_size

                    except ValueError:
                        print(f"Error: Invalid value format for '{symbol}'")
                        continue

        # Update labels with addresses from source
        for label, address in label_addresses.items():
            if label in self.symbol_table:
                # Update existing label entry
                self.symbol_table[label]['dirección'] = f'{address:04X}h'
            else:
                # Add new label entry if not already in symbol table
                self.symbol_table[label] = {
                    'símbolo': label,
                    'tipo': 'etq',
                    'valor': '',
                    'tamaño': 0,
                    'dirección': f'{address:04X}h'
                }

        return self.symbol_table

    def generate_variables_dict(self):
        self.variables_dict = {}

        for symbol, info in self.symbol_table.items():
            # Solo incluir variables (no etiquetas)
            if info['tipo'].startswith(('DB', 'DW', 'DD')):
                self.variables_dict[symbol] = {
                    'dirección': info['dirección'],
                    'tipo': info['tipo'],
                    'tamaño': info['tamaño']
                }

        return self.variables_dict

    def verify_instructions(self):
        verification_results = []

        for line in self.code_section:
            line_clean = self.remove_comments(line)
            if not line_clean:
                continue

            result = self.verify_single_instruction(line_clean)

            # Solo agregar instrucciones que no sean incorrectas por estructura de segmento
            if result == "Correcta" or not result.startswith("Estructura de segmento inválida"):
                verification_results.append((line_clean, result))

        return verification_results
    
    def verify_single_instruction(self, instruction):
        # Limpiar y convertir a mayúsculas
        instruction_upper = instruction.upper().strip()

        # Validaciones específicas para inicios de segmentos
        valid_segment_starts = [
            '.STACK SEGMENT',
            '.DATA SEGMENT',
            '.CODE SEGMENT'
        ]

        # Verificar instrucciones de segmento
        if any(instruction_upper.startswith(segment) for segment in valid_segment_starts):
            return "Definición de segmento"

        # Instrucciones existentes de verificación
        parts = re.split(r'[\s,]+', instruction)
        parts = [part.strip() for part in parts if part.strip()]

        if not parts:
            return "Instrucción vacía"

        mnemonic = parts[0].upper()

        if mnemonic not in self.instructions:
            if mnemonic in self.label_table:
                if len(parts) > 1:
                    mnemonic = parts[1].upper()
                else:
                    return "Línea de etiqueta sin instrucción"
            else:
                return f"Instrucción no reconocida: {mnemonic}"

        expected_args = {
            'PUSH': 1,
            'POP': 1,
            'MOV': 2,
            'CMP': 2,
        }

        arg_count = len(parts) - 1

        if mnemonic in expected_args:
            if arg_count != expected_args[mnemonic]:
                return f"Número incorrecto de argumentos para {mnemonic}. " \
                       f"Esperados: {expected_args[mnemonic]}, Recibidos: {arg_count}"

        if mnemonic in ['JMP', 'JE', 'JNE', 'JL', 'JLE', 'JG', 'JGE']:
            if len(parts) > 1:
                target_label = parts[1].upper()
                # Check if label exists in symbol table
                if target_label not in self.symbol_table:
                    return f"Error: Jump to undefined label '{target_label}'"
                # Check if target label is defined after this instruction
                label_addr = int(self.symbol_table[target_label]['dirección'].rstrip('h'), 16)
                current_addr = self.code_address_counter
                if label_addr <= current_addr:
                    return f"Error: Forward reference to label '{target_label}'"

        return "Correcta"

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