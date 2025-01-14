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
        self.data_address_counter = 0x0250
        self.code_address_counter = 0x0250
        self.machine_code_map = {}
        self.variables_dict = {}
        self.constants_dict = {}  # Nuevo diccionario para constantes

        self.dicc = Dictionary()

        # Set dictionaries from dictionaries.py
        self.data_dict = self.dicc.data_dict
        self.valid_instructions = self.dicc.valid_instructions
        self.machine_code_reference = self.dicc.machine_code_reference
        self.instructions = self.dicc.instructions
        self.registers_16bit = self.dicc.registers_16bit
        self.registers_8bit = self.dicc.registers_8bit
        self.pseudo_instructions = self.dicc.pseudo_instructions
        self.constant_patterns = self.dicc.constant_patterns
        self.jump_opcodes = self.dicc.jump_opcodes

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
        # Reset sections and counters
        self.data_section = []
        self.code_section = []
        self.stack_section = []
        self.current_section = None
        self.dicc.vars_addresses = {}
        self.dicc.tags_addresses = {}  # Reset tags addresses

        # Variables para seguimiento de direcciones
        current_data_address = 0x0250
        current_code_address = 0x0250
        
        # Primera pasada: recolectar etiquetas y sus direcciones
        temp_code_address = 0x0250
        for line in self.original_code:
            clean_line = self.remove_comments(line)
            if not clean_line:
                continue

            # Detect section changes
            if '.CODE' in clean_line.upper():
                self.current_section = 'code'
                continue
            elif '.DATA' in clean_line.upper():
                self.current_section = 'data'
                continue
            elif '.STACK' in clean_line.upper():
                self.current_section = 'stack'
                continue

            if self.current_section == 'code':
                # Si es una etiqueta
                if clean_line.strip().endswith(':'):
                    label = clean_line.strip()[:-1].strip()
                    self.dicc.tags_addresses[label] = f'{temp_code_address:04X}h'
                else:
                    # Verificar si es una instrucción válida antes de incrementar el contador
                    verification_result = self.verify_single_instruction(clean_line)
                    if verification_result == "Correcta" or verification_result.startswith(("74", "75", "7C", "7E", "7F", "7D", "77", "72", "E2", "E1", "E0")):
                        temp_code_address += 2

        # Segunda pasada: procesar secciones normalmente
        self.current_section = None
        for line in self.original_code:
            clean_line = self.remove_comments(line)
            if not clean_line:
                continue

            # Detect section changes
            if '.CODE' in clean_line.upper():
                self.current_section = 'code'
                continue
            elif '.DATA' in clean_line.upper():
                self.current_section = 'data'
                continue
            elif '.STACK' in clean_line.upper():
                self.current_section = 'stack'
                continue

            if self.current_section == 'data':
                self.data_section.append(clean_line)
                parts = clean_line.split()
                if len(parts) >= 2:
                    var_name = parts[0]
                    directive = parts[1].upper()
                    value = ' '.join(parts[2:]) if len(parts) > 2 else ''

                    # Procesar constantes (EQU)
                    if directive == 'EQU':
                        is_valid, message = self.process_data_line(clean_line)
                        if is_valid:
                            self.constants_dict[var_name] = {
                                'valor': value,
                                'tipo': 'EQU'
                            }
                        continue

                    # Procesar variables normales
                    if len(parts) >= 3:
                        is_valid, message = self.process_data_line(clean_line)
                        if is_valid and message == "Correcto":
                            size_map = {'DB': 1, 'DW': 2, 'DD': 4}
                            base_size = size_map.get(directive, 0)
                            
                            total_size = base_size
                            if 'DUP' in value.upper():
                                dup_parts = value.split('DUP')
                                try:
                                    dup_count = int(dup_parts[0].strip())
                                    total_size = base_size * dup_count
                                except ValueError:
                                    continue

                            self.dicc.vars_addresses[var_name] = {
                                'dirección': f'{current_data_address:04X}h',
                                'tipo': directive,
                                'valor': value,
                                'tamaño': total_size
                            }
                            current_data_address += total_size

            elif self.current_section == 'code':
                self.code_section.append(clean_line)
                if not clean_line.endswith(':'):  # No incrementar para etiquetas
                    verification_result = self.verify_single_instruction(clean_line)
                    if verification_result == "Correcta" or verification_result.startswith(("74", "75", "7C", "7E", "7F", "7D", "77", "72", "E2", "E1", "E0")):
                        current_code_address += 2

            elif self.current_section == 'stack':
                self.stack_section.append(clean_line)

        # Actualizar machine_code después de procesar todas las secciones
        self.generate_machine_code()

    def process_data_line(self, line):
        """
        Procesa y valida una línea de la sección .data
        Retorna una tupla (bool, str) indicando si es válida y el mensaje de error si existe
        """
        parts = line.split()
        if len(parts) < 2:
            return False, "Formato de línea incorrecto"

        symbol = parts[0]
        directive = parts[1].upper()

        # Validar constantes (EQU)
        if directive == 'EQU':
            if len(parts) < 3:
                return False, "Falta valor para la constante"
            
            # Validación del nombre de la constante
            if symbol[0].isdigit():
                return False, f"'{symbol}' No puede comenzar con un número"
            if len(symbol) > 10:
                return False, f"'{symbol}' Nombre mayor a 10 caracteres"

            value = ' '.join(parts[2:])
            # Verificar si es un número válido (decimal, hexadecimal o binario)
            if (re.match(r'^[0-9A-Fa-f]+[Hh]$', value) or 
                value.isdigit() or 
                (value.upper().endswith('B') and all(bit in '01' for bit in value[:-1]))):
                return True, "Correcto"
            return False, f"Valor no válido para la constante '{symbol}'"

        # Resto del código para otras directivas
        if len(parts) >= 3:
            # Validación del nombre de la variable
            if symbol[0].isdigit():
                return False, f"'{symbol}' No puede comenzar con un número"

            # Validación de longitud del símbolo
            if len(symbol) > 10:
                return False, f"'{symbol}' Nombre mayor a 10 caracteres"

            # Validación de la directiva
            if directive not in ['DB', 'DW', 'DD']:
                return False, f"Instruccion '{directive}' no válida"

            value = ' '.join(parts[2:])

            # Validación de la inicialización
            if directive in ['DB', 'DW', 'DD']:
                # Verificar strings con comillas
                if value.startswith('"') and value.endswith('"'):
                    return True, "Correcto"

                # Verificar números binarios
                if value.upper().endswith('B'):
                    binary_str = value[:-1]
                    if all(bit in '01' for bit in binary_str):
                        # Verificar longitud según directiva
                        bit_length = len(binary_str)
                        max_bits = {'DB': 8, 'DW': 16, 'DD': 32}
                        if bit_length <= max_bits[directive]:
                            return True, "Correcto"
                        return False, f"Excede el tamaño permitido para {directive}"

                # Verificar valores numéricos hexadecimales o decimales
                elif re.match(r'^[0-9A-Fa-f]+[Hh]$|^\d+$', value):
                    return True, "Correcto"

                # Verificar DUP
                elif 'DUP' in value.upper():
                    dup_match = re.search(r'(\d+)\s*DUP\s*\(\s*([^)]+)\s*\)', value)
                    if dup_match:
                        count = dup_match.group(1)
                        dup_value = dup_match.group(2)
                        
                        # Verificar si el valor DUP es binario
                        if dup_value.upper().endswith('B'):
                            binary_str = dup_value[:-1]
                            if all(bit in '01' for bit in binary_str):
                                return True, "Correcto"
                        
                        # Verificar otros tipos de valores DUP
                        if (dup_value.strip('\"').isalnum() or
                                re.match(r'^[0-9A-Fa-f]+[Hh]$', dup_value) or
                                dup_value.isdigit()):
                            return True, "Correcto"

                    return False, f"Inicialización DUP no válida para '{symbol}'"

                return False, f"Inicialización no válida para '{symbol}'"

            return False, "Formato de línea incorrecto"

        return False, "Formato de línea incorrecto"

    def get_source_with_details(self):
        source_details = []
        current_code_address = 0x0250
        current_data_address = 0x0250
        current_stack_address = 0x0250
        current_segment = None

        # Primera pasada: recopilar todas las etiquetas y sus direcciones
        temp_code_address = 0x0250
        for line in self.original_code:
            clean_line = self.remove_comments(line)
            if not clean_line:
                continue

            if '.CODE' in clean_line.upper():
                current_segment = 'code'
                continue
            elif '.DATA' in clean_line.upper():
                current_segment = 'data'
                continue
            elif '.STACK' in clean_line.upper():
                current_segment = 'stack'
                continue

            if current_segment == 'code':
                if clean_line.endswith(':'):
                    label = clean_line.rstrip(':').strip()
                    self.dicc.tags_addresses[label] = f'{temp_code_address:04X}h'
                else:
                    # Solo incrementar el contador para instrucciones válidas
                    verification_result = self.verify_single_instruction(clean_line)
                    if verification_result == "Correcta" or verification_result.startswith(("74", "75", "7C", "7E", "7F", "7D", "77", "72", "E2", "E1", "E0")):
                        temp_code_address += 2

        # Segunda pasada: generar los detalles de la fuente
        current_segment = None
        for line in self.original_code:
            clean_line = self.remove_comments(line)
            if not clean_line:
                continue

            if '.CODE' in clean_line.upper():
                current_segment = 'code'
                source_details.append(f"0250h | {clean_line} | {'Correcto'}")
                continue
            elif '.DATA' in clean_line.upper():
                current_segment = 'data'
                source_details.append(f"0250h | {clean_line} | {'Correcto'}")
                continue
            elif '.STACK' in clean_line.upper():
                current_segment = 'stack'
                source_details.append(f"0250h | {clean_line} | {'Correcto'}")
                continue

            if current_segment == 'code':
                if clean_line.endswith(':'):
                    # Es una etiqueta
                    label = clean_line.rstrip(':').strip()
                    address = self.dicc.tags_addresses.get(label, '0000h')
                    source_details.append(
                        f"{address.rstrip('h')}h | {clean_line} | {'Correcto'}"
                    )
                else:
                    # Es una instrucción
                    verification_result = self.verify_single_instruction(clean_line)
                    current_address = f"{current_code_address:04X}h"
                    
                    # Para instrucciones de salto, mostrar la dirección de destino
                    parts = clean_line.split()
                    if parts and parts[0].upper() in self.jump_opcodes and len(parts) > 1:
                        target = parts[1]
                        if target in self.dicc.tags_addresses:
                            verification_result = f"{self.jump_opcodes[parts[0].upper()]} {self.dicc.tags_addresses[target]}"
                    
                    source_details.append(
                        f"{current_address} | {clean_line} | {verification_result}"
                    )
                    
                    if verification_result == "Correcta" or verification_result.startswith(("74", "75", "7C", "7E", "7F", "7D", "77", "72", "E2", "E1", "E0")):
                        current_code_address += 2

            elif current_segment == 'data':
                # Procesar líneas de datos
                is_valid, message = self.process_data_line(clean_line)
                if is_valid:
                    parts = clean_line.split()
                    if len(parts) >= 3:
                        var_name = parts[0]
                        directive = parts[1].upper()
                        source_details.append(
                            f"{current_data_address:04X}h | {clean_line} | {'Correcto'}"
                        )
                        
                        # Actualizar la dirección según el tamaño de la variable
                        if directive in ['DB', 'DW', 'DD']:
                            size_map = {'DB': 1, 'DW': 2, 'DD': 4}
                            current_data_address += size_map[directive]
                else:
                    source_details.append(
                        f"{current_data_address:04X}h | {clean_line} | {'Error: ' + message}"
                    )

            elif current_segment == 'stack':
                # Procesar líneas de stack
                if clean_line.lower().startswith('dw'):
                    dup_match = re.search(r'dw\s+(\d+)\s+dup\s*\(\s*0\s*\)', clean_line.lower())
                    if dup_match:
                        multiplier = int(dup_match.group(1))
                        source_details.append(
                            f"{current_stack_address:04X}h | {clean_line} | {'Correcto'}"
                        )
                        current_stack_address += multiplier * 2
                    else:
                        source_details.append(
                            f"{current_stack_address:04X}h | {clean_line} | {'Error'}"
                        )
                else:
                    source_details.append(
                        f"{current_stack_address:04X}h | {clean_line} | {'Error'}"
                    )

        return source_details

    def is_valid_segment_instruction(self, line):
        # Normalize the line by stripping whitespace and converting to lowercase
        line_stripped = line.strip().lower()

        # Precise patterns for valid segment instructions
        valid_segment_patterns = [
            r'^\.stack\s+segment$',  # .stack segment start
            r'^\.data\s+segment$',  # .data segment start
            r'^\.code\s+segment$',  # .code segment start
            r'^\.\w+\s+ends$',  # Any segment end (modified to allow just 'ENDS')
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
        # Reset symbol table
        self.symbol_table = {}

        # Add constants to symbol table
        for const_name, const_info in self.constants_dict.items():
            if 'JZ' not in const_name.upper():
                self.symbol_table[const_name] = {
                    'símbolo': const_name,
                    'tipo': 'Const',
                    'valor': const_info['valor'],
                    'tamaño': 0,
                    'dirección': '----'
                }

        # Process variables and labels
        variables = {}
        labels = {}

        # Process variables
        for var_name, var_info in self.dicc.vars_addresses.items():
            if 'JZ' not in var_name.upper():
                variables[var_name] = {
                    'símbolo': var_name,
                    'tipo': var_info.get('tipo', ''),
                    'valor': var_info.get('valor', ''),
                    'tamaño': var_info.get('tamaño', 0),
                    'dirección': var_info.get('dirección', '0000h')
                }

        # Process labels
        for label, addr in self.dicc.tags_addresses.items():
            if 'JZ' not in label.upper():
                labels[label] = {
                    'símbolo': label,
                    'tipo': 'etq',
                    'valor': '',
                    'tamaño': 0,
                    'dirección': addr
                }

        # Combine and sort dictionaries
        sorted_constants = dict(sorted(self.symbol_table.items()))
        sorted_variables = dict(sorted(variables.items(),
                                       key=lambda x: int(x[1]['dirección'].rstrip('h'), 16)))
        sorted_labels = dict(sorted(labels.items(),
                                    key=lambda x: int(x[1]['dirección'].rstrip('h'), 16)))

        self.symbol_table = {**sorted_constants, **sorted_variables, **sorted_labels}
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

    def generate_machine_code(self):
        # Reset code address counter and maps
        self.code_address_counter = 0x0250
        self.machine_code_map = {}

        # Generate variables dictionary at the start
        self.generate_variables_dict()

        # Dictionary of addressing modes
        addressing_modes = {
            'REG_REG': '11',  # Register to Register
            'REG_MEM': '00',  # Register to Memory
            'MEM_REG': '10',  # Memory to Register
            'IMM_REG': '01',  # Immediate to Register
            'DIRECT': '00'  # Direct addressing
        }

        # Dictionary for register encoding (unified from both versions)
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

        # Dictionary for no-operand instructions (added from second version)
        no_operand_instructions = {
            'RET': '11000011',  # C3
            'PUSHF': '10011100',  # 9C
            'POPF': '10011101',  # 9D
            'CLC': '11111000',  # F8
            'STC': '11111001',  # F9
            'CLI': '11111010',  # FA
            'STI': '11111011',  # FB
            'NOP': '10010000'  # 90
        }

        # Dictionary for jump instructions opcodes
        jump_opcodes = {
            'JMP': '74', 'JE': '74', 'JNE': '75',
            'JL': '7C', 'JLE': '7E', 'JG': '7F',
            'JGE': '7D', 'JA': '77', 'JNAE': '72',
            'JC': '72', 'LOOP': 'E2', 'LOOPE': 'E1',
            'LOOPNE': 'E0'
        }

        def process_operand(operand):
            """Process an operand and determine its type and value"""
            operand = operand.upper()
            # Check if it's a 16-bit register
            if operand in register_encoding['16BIT']:
                return 'register16', operand
            # Check if it's an 8-bit register
            elif operand in register_encoding['8BIT']:
                return 'register8', operand
            # Check if it's a variable
            elif operand in self.variables_dict:
                return 'variable', operand
            # Check if it's an immediate value (hex or decimal)
            elif re.match(r'^[0-9A-F]+H$', operand) or operand.isdigit():
                return 'immediate', operand
            return 'unknown', operand

        def encode_cmp_instruction(self, op1, op2):
            """Enhanced CMP instruction encoding with support for registers, variables, and immediate values"""

            def get_register_type(reg):
                reg = reg.upper()
                if reg in self.registers_16bit:
                    return '16bit'
                elif reg in self.registers_8bit:
                    return '8bit'
                return None

            def get_immediate_value(imm):
                # Handle hexadecimal values
                if isinstance(imm, str) and imm.upper().endswith('H'):
                    return int(imm[:-1], 16)
                # Handle decimal values
                try:
                    return int(imm)
                except ValueError:
                    return None

            # Clean and prepare operands
            op1 = op1.strip().upper()
            op2 = op2.strip().upper()

            # Define opcodes and ModRM patterns
            CMP_REG_IMM = '1000001'  # Compare immediate with register
            CMP_REG_REG = '001110'  # Compare register with register
            CMP_MEM_IMM = '1000001'  # Compare immediate with memory
            CMP_REG_MEM = '001110'  # Compare register with memory

            # Case 1: CMP register, immediate
            if (get_register_type(op1) and
                    (op2.isdigit() or op2.endswith('H') or op2.endswith('h'))):
                reg_type = get_register_type(op1)
                imm_value = get_immediate_value(op2)

                if reg_type == '16bit':
                    reg_code = self.registers_16bit[op1]
                    machine_code = f"{CMP_REG_IMM}1{reg_code}"  # w=1 for 16-bit
                else:  # 8-bit
                    reg_code = self.registers_8bit[op1]
                    machine_code = f"{CMP_REG_IMM}0{reg_code}"  # w=0 for 8-bit

                # Add immediate value in binary
                imm_binary = format(imm_value, '016b' if reg_type == '16bit' else '08b')
                return machine_code + imm_binary

            # Case 2: CMP register, register
            elif get_register_type(op1) and get_register_type(op2):
                if get_register_type(op1) == get_register_type(op2):  # Must be same size
                    is_16bit = get_register_type(op1) == '16bit'
                    reg_table = self.registers_16bit if is_16bit else self.registers_8bit

                    machine_code = CMP_REG_REG  # Base opcode
                    machine_code += '1'  # Direction bit (reg to reg)
                    machine_code += '1' if is_16bit else '0'  # w bit
                    machine_code += '11'  # Mod for register-to-register
                    machine_code += reg_table[op2]  # reg field
                    machine_code += reg_table[op1]  # r/m field

                    return machine_code

            # Case 3: CMP register, memory (variable)
            elif get_register_type(op1) and op2 in self.variables_dict:
                reg_type = get_register_type(op1)
                var_info = self.variables_dict[op2]

                machine_code = CMP_REG_MEM
                machine_code += '1'  # Direction bit (reg to mem)
                machine_code += '1' if reg_type == '16bit' else '0'  # w bit
                machine_code += '00'  # Mod for memory mode
                machine_code += (self.registers_16bit[op1] if reg_type == '16bit'
                                 else self.registers_8bit[op1])
                machine_code += '110'  # r/m field for direct addressing

                # Add variable address
                var_addr = int(var_info['dirección'].rstrip('h'), 16)
                addr_binary = format(var_addr, '016b')
                return machine_code + addr_binary

            # Case 4: CMP memory (variable), immediate
            elif op1 in self.variables_dict and (op2.isdigit() or op2.endswith('H')):
                var_info = self.variables_dict[op1]
                imm_value = get_immediate_value(op2)

                machine_code = CMP_MEM_IMM
                machine_code += '1'  # w bit for 16-bit operations
                machine_code += '00110'  # ModRM byte for direct addressing

                # Add variable address and immediate value
                var_addr = int(var_info['dirección'].rstrip('h'), 16)
                addr_binary = format(var_addr, '016b')
                imm_binary = format(imm_value, '016b')
                return machine_code + addr_binary + imm_binary

            return "Error: Invalid operand combination for CMP"

        def encode_mov_instruction(op1, op2):
            """Encode MOV instruction with various operand combinations"""
            op1_type, op1_val = process_operand(op1)
            op2_type, op2_val = process_operand(op2)

            # MOV Register, Variable
            if op1_type in ['register16', 'register8'] and op2_type == 'variable':
                var_info = self.variables_dict[op2_val]
                is_word = op1_type == 'register16'
                reg_table = register_encoding['16BIT'] if is_word else register_encoding['8BIT']

                machine_code = '1000101'  # MOV opcode for memory to register
                machine_code += '1' if is_word else '0'  # Word/Byte
                machine_code += addressing_modes['DIRECT']
                machine_code += reg_table[op1_val]
                machine_code += '110'  # Direct addressing mode

                var_addr = int(var_info['dirección'].rstrip('h'), 16)
                addr_binary = format(var_addr, '016b')
                machine_code += addr_binary

                return machine_code

            # MOV Register, Register
            elif op1_type in ['register16', 'register8'] and op2_type == op1_type:
                is_word = op1_type == 'register16'
                reg_table = register_encoding['16BIT'] if is_word else register_encoding['8BIT']

                machine_code = '1000100'  # MOV opcode for register to register
                machine_code += '1' if is_word else '0'  # Word/Byte
                machine_code += addressing_modes['REG_REG']
                machine_code += reg_table[op1_val]
                machine_code += reg_table[op2_val]

                return machine_code

            return "Error: Invalid operand combination for MOV"

        def encode_push_pop_instruction(instruction, operand):
            """Encode PUSH/POP instructions"""
            op_type, op_val = process_operand(operand)

            if op_type == 'register16':
                base = '01010' if instruction == 'PUSH' else '01011'
                machine_code = base + register_encoding['16BIT'][op_val]
                return machine_code

            return f"Error: Invalid operand for {instruction}"

        def encode_jump_instruction(self, instruction, target):
            """
            Encode jump instructions with correct relative addressing
            """
            if target in self.dicc.tags_addresses:
                # Obtener la dirección de destino de la etiqueta
                target_addr = int(self.dicc.tags_addresses[target].rstrip('h'), 16)
                
                # La dirección actual es la dirección de la siguiente instrucción
                current_addr = self.code_address_counter + 2
                
                # Calcular el offset relativo
                offset = target_addr - current_addr
                
                # Verificar que el offset esté en el rango válido (-128 a 127 bytes)
                if -128 <= offset <= 127:
                    # Convertir el offset a complemento a dos de 8 bits si es negativo
                    if offset < 0:
                        offset = offset & 0xFF
                    
                    # Convertir a binario de 8 bits
                    offset_binary = format(offset, '08b')
                    
                    # Obtener el opcode correspondiente
                    opcode = self.jump_opcodes.get(instruction, '74')  # Default a JMP si no se encuentra
                    
                    # Combinar opcode y offset
                    machine_code = f"{opcode}{offset_binary}"
                    
                    return machine_code
                
                return f"Error: Jump offset fuera de rango ({offset} bytes)"
            
            return f"Error: Etiqueta '{target}' no encontrada"

        def group_and_convert_to_hex(binary_str):
            """Convert binary string to grouped hex format"""
            if binary_str.startswith('Error'):
                return 'Error'

            # Pad to multiple of 4
            padded = binary_str.zfill((len(binary_str) + 3) // 4 * 4)

            # Convert to hex groups
            hex_groups = []
            for i in range(0, len(padded), 4):
                group = padded[i:i + 4]
                hex_val = hex(int(group, 2))[2:].upper()
                hex_groups.append(hex_val)

            return ' '.join(hex_groups)

        # Main processing loop
        for line in self.code_section:
            parts = line.split()
            if not parts:
                continue

            instruction = parts[0].upper()

            # Skip labels
            if instruction.endswith(':'):
                continue

            try:
                machine_code_binary = ''
                should_increment_counter = True

                # Handle no-operand instructions first (from second version)
                if instruction in no_operand_instructions:
                    machine_code_binary = no_operand_instructions[instruction]
                else:
                    # Split operands correctly handling commas
                    operands = []
                    if len(parts) > 1:
                        operands_str = ' '.join(parts[1:])
                        operands = [op.strip() for op in operands_str.split(',')]

                    # Process different instruction types
                    if instruction == 'CMP' and len(operands) == 2:
                        machine_code_binary = encode_cmp_instruction(operands[0], operands[1])
                    elif instruction == 'MOV' and len(operands) == 2:
                        machine_code_binary = encode_mov_instruction(operands[0], operands[1])
                    elif instruction in ['PUSH', 'POP'] and len(operands) == 1:
                        machine_code_binary = encode_push_pop_instruction(instruction, operands[0])
                    elif instruction in jump_opcodes and len(operands) == 1:
                        machine_code_binary = encode_jump_instruction(instruction, operands[0])
                    else:
                        machine_code_binary = f"Error: Unsupported instruction or invalid operands"
                        should_increment_counter = False

                # Convert to hex if no error
                machine_code_hex = group_and_convert_to_hex(machine_code_binary)

                # Store results
                self.machine_code_map[line] = {
                    'address': f'{self.code_address_counter:04X}h',
                    'machine_code_binary': machine_code_binary,
                    'machine_code_hex': machine_code_hex,
                    'addressing_mode': addressing_modes.get('REG_REG', 'UNDEFINED')
                }

                # Increment counter for valid instructions
                if should_increment_counter and not machine_code_binary.startswith('Error'):
                    self.code_address_counter += 2

            except Exception as e:
                self.machine_code_map[line] = {
                    'address': f'{self.code_address_counter:04X}h',
                    'machine_code_binary': f"Error: {str(e)}",
                    'machine_code_hex': 'Error',
                    'addressing_mode': 'ERROR'
                }

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

    def verify_cmp_instruction(self, operands):
        """Verify CMP instruction operands"""
        if len(operands) != 2:
            return "CMP requiere dos operandos"

        op1, op2 = operands[0].upper(), operands[1].upper()

        # Valid combinations:
        # 1. Register, Register (same size)
        # 2. Register, Immediate
        # 3. Register, Memory
        # 4. Memory, Immediate
        # 5. Memory, Register

        def is_register(op):
            return op in self.registers_16bit or op in self.registers_8bit

        def is_immediate(op):
            # Check for hex numbers
            if op.upper().endswith('H'):
                try:
                    int(op[:-1], 16)
                    return True
                except ValueError:
                    return False
            # Check for decimal numbers
            return op.isdigit()

        def is_memory(op):
            return op in self.variables_dict

        # Check valid combinations
        if is_register(op1):
            if is_register(op2):
                # Both must be same size (16-bit or 8-bit)
                if ((op1 in self.registers_16bit and op2 in self.registers_16bit) or
                        (op1 in self.registers_8bit and op2 in self.registers_8bit)):
                    return "Correcta"
                return "Los registros deben ser del mismo tamaño"
            elif is_immediate(op2):
                return "Correcta"
            elif is_memory(op2):
                return "Correcta"
        elif is_memory(op1):
            if is_immediate(op2):
                return "Correcta"
            elif is_register(op2):
                return "Correcta"

        return "Error: Operandos invalidos"

    def verify_single_instruction(self, instruction):
        # Clean and convert to uppercase
        instruction_upper = instruction.upper().strip()

        # Special handling for segment definitions
        valid_segment_starts = ['.STACK SEGMENT', '.DATA SEGMENT', '.CODE SEGMENT']
        if any(instruction_upper.startswith(segment) for segment in valid_segment_starts):
            return "Definición de segmento"

        # Split instruction into parts
        parts = re.split(r'[\s,]+', instruction)
        parts = [part.strip() for part in parts if part.strip()]

        if not parts:
            return "Instrucción vacía"

        mnemonic = parts[0].upper()

        # Handle labels
        if mnemonic.endswith(':'):
            if len(parts) > 1:
                mnemonic = parts[1].upper()
            else:
                return "Correcta"  # Just a label is valid

        # Jump instruction opcodes mapping
        jump_opcodes = {
            'JMP': '74', 'JE': '74', 'JNE': '75',
            'JL': '7C', 'JLE': '7E', 'JG': '7F',
            'JGE': '7D', 'JA': '77', 'JNAE': '72',
            'JC': '72', 'LOOP': 'E2', 'LOOPE': 'E1',
            'LOOPNE': 'E0'
        }

        # Special handling for jump instructions - preserve existing logic
        if mnemonic in jump_opcodes:
            if len(parts) == 1:
                return "Error: Falta operando para instrucción de salto"
            target = parts[1].upper()
            if target in self.dicc.tags_addresses:
                target_addr = self.dicc.tags_addresses[target]
                return f"{jump_opcodes[mnemonic]} {target_addr}"
            else:
                return f"Error: Etiqueta indefinida: {target}"

        # Check if it's a valid instruction
        if mnemonic not in self.instructions and not mnemonic.endswith(':'):
            return f"Error"

        # Handle instructions without operands (RET, PUSHF, CLC, etc.)
        no_operand_instructions = {
            'RET': 'C3', 'PUSHF': '9C', 'POPF': '9D',
            'CLC': 'F8', 'STC': 'F9', 'CLI': 'FA',
            'STI': 'FB', 'NOP': '90'
        }
        
        if mnemonic in no_operand_instructions:
            if len(parts) == 1:  # Should have no operands
                return no_operand_instructions[mnemonic]
            else:
                return f"Error: {mnemonic} no debe tener operandos"

        # Get operands
        operands = parts[1:]

        # Handle instructions with operands
        if mnemonic == 'CMP' and len(operands) == 2:
            result = self.verify_cmp_instruction(operands)
            if result == "Correcto":
                # Encode CMP instruction
                try:
                    machine_code = self.encode_cmp_instruction(operands[0], operands[1])
                    if isinstance(machine_code, str) and len(machine_code) >= 16:
                        # Convert binary to hex
                        hex_code = format(int(machine_code[:8], 2), '02X')
                        return hex_code
                except:
                    return "Error: Error en codificación"
            return result

        elif mnemonic == 'MOV' and len(operands) == 2:
            op1, op2 = operands[0].upper(), operands[1].upper()
            # Verify operands are valid
            valid_op1 = (op1 in self.registers_16bit or op1 in self.registers_8bit or
                        op1 in self.variables_dict)
            valid_op2 = (op2 in self.registers_16bit or op2 in self.registers_8bit or
                        op2 in self.variables_dict or self.is_valid_immediate(op2))
            
            if valid_op1 and valid_op2:
                try:
                    # Encode MOV instruction
                    machine_code = self.encode_mov_instruction(op1, op2)
                    if isinstance(machine_code, str) and len(machine_code) >= 16:
                        # Convert binary to hex
                        hex_code = format(int(machine_code[:8], 2), '02X')
                        return hex_code
                except:
                    return "Error: Error en la codificación"
            return "Error: Operandos inválidos"

        elif mnemonic in ['PUSH', 'POP'] and len(operands) == 1:
            op = operands[0].upper()
            if op in self.registers_16bit:
                try:
                    # Encode PUSH/POP instruction
                    machine_code = self.encode_push_pop_instruction(mnemonic, op)
                    if isinstance(machine_code, str) and len(machine_code) >= 8:
                        # Convert binary to hex
                        hex_code = format(int(machine_code, 2), '02X')
                        return hex_code
                except:
                    return "Error: Error en la codificación"
            return "Error: Operando inválido"

        # For any other instruction that reaches here
        return "Error: No es podible codificar"

    def is_valid_immediate(self, value):
        """Check if a value is a valid immediate operand"""
        # Handle hexadecimal numbers
        if value.upper().endswith('H'):
            try:
                int(value[:-1], 16)
                return True
            except ValueError:
                return False

        # Handle decimal numbers
        try:
            int(value)
            return True
        except ValueError:
            return False

        return False

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

    def get_constant_type(self, token):
        # Primero verificar si es un número binario
        if token.upper().endswith('B'):
            try:
                # Remover el sufijo 'B' y verificar si es un número binario válido
                binary_str = token[:-1]
                if all(bit in '01' for bit in binary_str):
                    return 'Binario'
            except:
                pass
                
        # Continuar con el resto de las validaciones existentes
        for pattern, const_type in self.constant_patterns.items():
            if re.match(pattern, token):
                return const_type
        return None