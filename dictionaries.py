
class Dictionary:
    def __init__(self) -> None:
        self.data_dict = {
            'VALOR DE W': {
                'reg': {
                    'AX': '000',
                    'CX': '001',
                    'DX': '010',
                    'BX': '011',
                    'SP': '100',
                    'SI': '110',
                    'DI': '111'
                },
                'REGISTRO': {
                    'ES': '00',
                    'CS': '01',
                    'SS': '10',
                    'DS': '11'
                },
                'regs2': {
                    'AX': '00',
                    'CX': '01',
                    'DX': '10',
                    'BX': '11',
                    'SP': '000',
                    'SI': '001',
                    'DI': '011'
                }
            },
            'DIRECCION DE LA OPERACION': {
                'Reg/Mem, Reg': {'d': '0', 'mod': ''},
                'Reg, Reg/Mem': {'d': '1', 'mod': ''}
            },
            'Efecto sobre dato inme diato de 8 bits': {
                '0': 'Ninguno',
                '1': 'Extension de signo del dato de 8 bits hasta completar los 16 bits'
            },
            'Efecto sobre dato inme diato de 16 bits': {
                '0': 'Ninguno',
                '1': 'Ninguno'
            }
            }

        self.valid_instructions = {
            'DAA', 'PUSHF', 'RET', 'CLC', 'CLD', 'PUSH', 'NOT', 'DIV',
            'POP', 'CMP', 'TEST', 'LEA', 'OR', 'JNAE', 'JNE', 'JNLE',
            'LOOPE', 'JA', 'JC'
        }

        self.machine_code_reference = {
            'DAA': '00100111',
            'PUSHF': '10011100',
            'RET': '11000011',
            'CLC': '11111000',
            'CLD': '11111100',
            'PUSH': {
                'format': '01010reg',  # Reg short push
                'reg_map': {'AX': '000', 'CX': '001', 'DX': '010', 'BX': '011',
                            'SP': '100', 'BP': '101', 'SI': '110', 'DI': '111'}
            },
            'NOT': '1111011w mod 010 r/m',
            'DIV': '1111011w mod 110 r/m',
            'POP': {
                'format': '01011reg',  # Reg short pop
                'reg_map': {'AX': '000', 'CX': '001', 'DX': '010', 'BX': '011',
                            'SP': '100', 'BP': '101', 'SI': '110', 'DI': '111'}
            },
            'CMP': '001110dw mod reg r/m',
            'TEST': '1000010w mod reg r/m',
            'LEA': '10001101 mod reg r/m',
            'OR': '000010dw mod reg r/m',
            'JNAE': '01110010',
            'JNE': '01110101',
            'JNLE': '01111111',
            'LOOPE': '11100001',
            'JA': '01110111',
            'JC': '01110010'
        }

        self.instructions = {
            'DAA': 'Instrucción',
            'DAS': 'Instrucción',
            'PUSHF': 'Instrucción',
            'RET': 'Instrucción',
            'CLC': 'Instrucción',
            'CLD': 'Instrucción',
            'PUSH': 'Instrucción',
            'NOT': 'Instrucción',
            'DIV': 'Instrucción',
            'POP': 'Instrucción',
            'CMP': 'Instrucción',
            'TEST': 'Instrucción',
            'LEA': 'Instrucción',
            'OR': 'Instrucción',
            'JNAE': 'Instrucción',
            'JNE': 'Instrucción',
            'JNLE': 'Instrucción',
            'LOOPE': 'Instrucción',
            'JA': 'Instrucción',
            'JC': 'Instrucción',
        }

        self.registers_16bit = {
            'AX': 'Registro 16 bits',
            'BX': 'Registro 16 bits',
            'CX': 'Registro 16 bits',
            'DX': 'Registro 16 bits',
            'SI': 'Registro 16 bits',
            'DI': 'Registro 16 bits',
            'SP': 'Registro 16 bits',
            'BP': 'Registro 16 bits',
        }

        self.registers_8bit = {
            'AL': 'Registro 8 bits',
            'AH': 'Registro 8 bits',
            'BL': 'Registro 8 bits',
            'BH': 'Registro 8 bits',
            'CL': 'Registro 8 bits',
            'CH': 'Registro 8 bits',
            'DL': 'Registro 8 bits',
            'DH': 'Registro 8 bits',
        }

        self.pseudo_instructions = {
            'SEGMENT': 'Pseudoinstrucción',
            'ENDS': 'Pseudoinstrucción',
            'PROC': 'Pseudoinstrucción',
            'PROCEDURE': 'Pseudoinstrucción',
            'ENDP': 'Pseudoinstrucción',
            'MACRO': 'Pseudoinstrucción',
            'ENDM': 'Pseudoinstrucción',
            'EQU': 'Pseudoinstrucción',
            'DB': 'Pseudoinstrucción',
            'DW': 'Pseudoinstrucción',
            'DD': 'Pseudoinstrucción',
            'ASSUME': 'Pseudoinstrucción',
            'END': 'Pseudoinstrucción',
            'DATA': 'Pseudoinstrucción',
            'CODE': 'Pseudoinstrucción',
            'STACK': 'Pseudoinstrucción',
        }

        self.constant_patterns = {
            r'^[0-9A-Fa-f]+[Hh]$|^0[Xx][0-9A-Fa-f]+$': 'Constante Numérica Hexadecimal',
            r'^\d+$': 'Constante Numérica Decimal',
            r'^[0-7]+[Oo]$|^0[Oo][0-7]+$': 'Constante Numérica Octal',
            r'^[01]+[Bb]$': 'Constante Numérica Binaria',
            r"^'.'$|^'[^']*'$": 'Constante Caracter'
        }