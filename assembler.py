import os
from os import path

class Assembler:
    def __init__(self, file_name:str) -> None:
        """Constructor for the Assembler class

        Args:
            file_name (string): exact file name given from user input

        Raises:
            ValueError: ValueError to stop execution when the file inputted was not found
        """
        # Check if file exists:
        if(path.isfile(file_name)):
            self.file_name = file_name
            # init hexidecimal map:
            self.hex_map = {"0000": '0',"0001": '1',"0010": '2',"0011": '3',"0100": '4',
                "0101": '5',"0110": '6',"0111": '7',"1000": '8',"1001": '9',"1010": 'a',
                "1011": 'b',"1100": 'c',"1101": 'd',"1110": 'e',"1111": 'f'}
            # init opcode map:
            self.opcode_map = {"ADD_REG":"1010000","ADD_IMM":"1011000","SUB_REG":"1110000",
                            "SUB_IMM":"1111000","LDR_POS":"0011101","LDR_NEG":"0111101",
                            "STR_POS":"0001010","STR_NEG":"0101010"} 
        else:
            raise ValueError(f"ERROR: {file_name} NOT FOUND, PLEASE CHECK IF THE GIVEN FILE EXISTS")  
        
    def string_to_binary(self, binary_string:str) -> str:
        """Will convert any string representing a number to its positive binary version

        Args:
            binary_string (str): String representing a number to convert to binary from 0 to 127

        Returns:
            str: A binary representation of the number string
        """
        if int(binary_string) < 0:
            # Only imm8 values will ever get to this point, so just make it 8 bit
            return str(bin(int(binary_string) + (1 << 8)))[2:]
        else:
            return "{0:b}".format(int(binary_string))
    
    def bit_extend(self, binary_string:str,extension:int) -> str:
        """Will take a string representing a binary number and perform a bit extension defined by 'extension'

        Args:
            binary_string (str): Binary String representing a number that is at most 8 bits preferably
            extension (int): Integer representing how many zeros to append to the left side of the binary string

        Returns:
            str: Bit extended version a binary string
        """
        num_zeros = extension-len(binary_string)
        return ("0" * num_zeros) + binary_string

    def parse_instruction(self, instruction_list:list) -> str:
        if instruction_list[0] not in ["ADD", "SUB", "LDR", "STR"]:
            raise ValueError(f"ERROR: INVALID OR UNSUPPORTED INSTRUCTION '{instruction_list[0]}' GIVEN, PLEASE CHECK YOUR ATLAS ASSEMBLY FILE")
        elif (instruction_list[1] not in ["X0","X1","X2","X3"]) or (not 0 <= int(instruction_list[1][1:]) <= 3):
            raise ValueError(f"ERROR: INVALID REGISTER '{instruction_list[1]}' GIVEN OR REGISTER VALUE IS OUT OF RANGE FROM 0 to 3")
        elif (instruction_list[2] not in ["X0","X1","X2","X3"]) or (not 0 <= int(instruction_list[2][1:]) <= 3):
            raise ValueError(f"ERROR: INVALID REGISTER '{instruction_list[2]}' GIVEN OR REGISTER VALUE IS OUT OF RANGE FROM 0 to 3")
        elif (instruction_list[3] not in ["X0","X1","X2","X3"]) and (not -128 <= int(instruction_list[3]) <= 127):
            raise ValueError(f"ERROR: INVALID REGISTER OR 8-BIT INTEGER PROVIDED FOR Rm: '{instruction_list[3]}'")
        else:
            instruction_binary = ""
            if instruction_list[0] == "ADD":
                # Case of its a register
                if instruction_list[3][0] == "X":
                    # instruction_binary = opcode + imm8 + Rn + Rm + Rd
                    instruction_binary = self.opcode_map["ADD_REG"] + "00000000" + self.bit_extend(self.string_to_binary(instruction_list[2][1:]),2) + self.bit_extend(self.string_to_binary(instruction_list[3][1:]),2) + self.bit_extend(self.string_to_binary(instruction_list[1][1:]),2) + "000"
                    return self.convert_to_hex(instruction_binary)
                else:
                    if int(instruction_list[3]) < 0:
                        raise ValueError(f"ERROR: ADD ARGUMENT CANNOT BE LESS THAN 0: GIVEN {instruction_list[3]}")
                    else:
                        instruction_binary = self.opcode_map["ADD_IMM"] + self.bit_extend(self.string_to_binary(instruction_list[3]),8) + self.bit_extend(self.string_to_binary(instruction_list[2][1:]),2) + "00" + self.bit_extend(self.string_to_binary(instruction_list[1][1:]),2) + "000"
                        return self.convert_to_hex(instruction_binary)
            elif instruction_list[0] == "SUB":
                # Case of its a register
                if instruction_list[3][0] == "X":
                    # instruction_binary = opcode + imm8 + Rn + Rm + Rd
                    instruction_binary = self.opcode_map["SUB_REG"] + "00000000" + self.bit_extend(self.string_to_binary(instruction_list[2][1:]),2) + self.bit_extend(self.string_to_binary(instruction_list[3][1:]),2) + self.bit_extend(self.string_to_binary(instruction_list[1][1:]),2) + "000"
                    return self.convert_to_hex(instruction_binary)
                else:
                    if int(instruction_list[3]) < 0:
                        raise ValueError(f"ERROR: SUB ARGUMENT CANNOT BE LESS THAN 0: GIVEN {instruction_list[3]}")
                    else:
                        instruction_binary = self.opcode_map["SUB_IMM"] + self.bit_extend(self.string_to_binary(instruction_list[3]),8) + self.bit_extend(self.string_to_binary(instruction_list[2][1:]),2) + "00" + self.bit_extend(self.string_to_binary(instruction_list[1][1:]),2) + "000"
                        return self.convert_to_hex(instruction_binary)
            elif instruction_list[0] == "LDR":
                if int(instruction_list[3]) < 0:
                    instruction_binary = self.opcode_map["LDR_NEG"] + self.bit_extend(self.string_to_binary(instruction_list[3][1:]),8) + self.bit_extend(self.string_to_binary(instruction_list[2][1:]),2) + "00" + self.bit_extend(self.string_to_binary(instruction_list[1][1:]),2) + "000"
                else:
                    instruction_binary = self.opcode_map["LDR_POS"] + self.bit_extend(self.string_to_binary(instruction_list[3]),8) + self.bit_extend(self.string_to_binary(instruction_list[2][1:]),2) + "00" + self.bit_extend(self.string_to_binary(instruction_list[1][1:]),2) + "000"
                return self.convert_to_hex(instruction_binary)
            else:
                if int(instruction_list[3]) < 0:
                    instruction_binary = self.opcode_map["STR_NEG"] + self.bit_extend(self.string_to_binary(instruction_list[3][1:]),8) + self.bit_extend(self.string_to_binary(instruction_list[2][1:]),2) + "00" + self.bit_extend(self.string_to_binary(instruction_list[1][1:]),2) + "000"
                else:
                    instruction_binary = self.opcode_map["STR_POS"] +  self.bit_extend(self.string_to_binary(instruction_list[3]),8) + self.bit_extend(self.string_to_binary(instruction_list[2][1:]),2) + "00" + self.bit_extend(self.string_to_binary(instruction_list[1][1:]),2) + "000"
                return self.convert_to_hex(instruction_binary)
            
    def parse_file(self) -> list:
        """Will take a .atlas file and parse every individual instruction and store them into a list of instructions

        Returns:
            list: A list of binary instructions that are converted to hexidecimal to be sent to the image file
        """
        hex_code_list = []
        with open(self.file_name, 'r') as f:
            for line in f:
                line = line.strip()
                # ignore empty whitespace lines
                if line.strip():
                    # Start parsing instruction by using dictionary mapping 
                    # for opcodes
                    if not line.startswith(";"):
                        raise ValueError(f"ERROR: INSTRUCTION DOES NOT START WITH ';' PLEASE REVIEW: {line}")
                    inst = line.split(";")[1:]
                    # every instruction for our instruction set will only have 4 elements
                    # in instruction list so just directly check each index:
                    hex_code = self.parse_instruction(inst)
                    hex_code_list.append(hex_code)
        return hex_code_list
                    
    def convert_to_hex(self, binary_string:str) -> str:
        """Converts a 24 bit binary string to its hexidecimal equivilent

        Args:
            binary_string (str): 24-bit binary string

        Returns:
            str: A 24 bit hexidecimal string
        """
        # Given a binary string convert to binary hex without the 0x on it
        # every binary string will be exactly 24 bits in length by the time 
        # its fed into instruction so split to 6 parts:
        binary_hex_list = [binary_string[i:i+4] for i in range(0, len(binary_string),4)]
        for i in range(len(binary_hex_list)):
            binary_hex_list[i] = self.hex_map[binary_hex_list[i]]
        return "".join(binary_hex_list)

    def construct_instruction_memory(self, hex_code_list:list) -> None:
        """Will create an instruction memory image file within the local directory to be loaded into logisim

        Args:
            hex_code_list (list): A list of sequential hexidecimal codes that can be written into the image file in order without the need of sorting
        """
        hex_code_list = hex_code_list + ['000000'] * (256-len(hex_code_list))
        # Delete previously made binary instruction set
        if path.isfile("instruction_memory"):
            os.remove("instruction_memory")
        instruction_mem = open("instruction_memory","w")
        instruction_mem.write("v3.0 hex words addressed")
        curr_address = 0x00
        for instruction in hex_code_list:
            if curr_address % 8 == 0:
                instruction_mem.write(f'\n{(hex(curr_address))[2:].zfill(2)}: ')
            instruction_mem.write(f"{instruction} ")
            curr_address+=1

if __name__ == "__main__":
    # Ask user what file to parse for the atlas assembly assembler
    file = input("Please input file name you want to use with the assembler: ")
    if file[-6:] != '.atlas':
        raise ValueError(f"ERROR: INVALID FILE EXTENSION FOR FILE: {file}")
    # Pass program file to parse
    atlas_assembler = Assembler(file)
    # Generate binary codes
    hex_codes = atlas_assembler.parse_file()
    # Output a file that contains the instruction memory
    atlas_assembler.construct_instruction_memory(hex_codes)