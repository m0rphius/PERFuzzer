import json
from typing import Dict, List
from enum import Enum
import random
from abc import ABC
from utils.utils import flatten

register_allowlist = {
    64 : ['rax', 'rbx', 'rcx', 'rdx'],
    32 : ['eax', 'ebx', 'ecx', 'edx'],
    16 : ['ax', 'bx', 'cx', 'dx'],
    8  : ['al',  'bl', 'cl', 'dl']
}

register_blocklist = {
    64 : ['rbp', 'rsp', 'rip', 'r14', 'r15', 'rdi', 'rsi'],
    32 : ['ebp', 'esp', 'eip', 'r14d', 'r15d', 'edi', 'esi'],
    16 : ['bp', 'sp', 'ip', 'r14w','r15w', 'di', 'si'],
    8 : ['bpl', 'spl', 'r14b','r15b', 'ah', 'bh', 'ch', 'dh', 'sil', 'dil'],
    "other" : ["cr0", "cr2", "cr3", "cr4", "cr8",
               "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7",
               "fs", "ss", "es", "gs", "ds"]
}

memory_register_list = {
    64 : ['r8', 'r9', 'r10', 'r11', 'r12', 'r13'],
    32 : ['r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d'],
    16 : ['r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w'],
    8  : ['r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b']
}
base_register = "r14"

instruction_block_list = []

class OT(Enum):
    """Operand Type"""
    REG = 1
    MEM = 2
    IMM = 3
    LABEL = 4
    AGEN = 5  # memory address in LEA instructions
    FLAGS = 6
    COND = 7

    def __str__(self):
        return str(self._name_)
    
class Operand(ABC):
    value: str
    type: OT
    width: int = 0
    src: bool
    dest: bool

    # certain operand values have special handling (e.g., separate opcode when RAX is a destination)
    # magic_value attribute indicates a specification for this special value
    magic_value: bool = False

    def __init__(self, value: str, type_, src: bool, dest: bool):
        self.value = value
        self.type = type_
        self.src = src
        self.dest = dest
        super(Operand, self).__init__()

    def get_width(self) -> int:
        return self.width
    
class RegisterOperand(Operand):

    def __init__(self, value: str, width: int, src: bool, dest: bool):
        self.width = width
        super().__init__(value.lower(), OT.REG, src, dest)


class MemoryOperand(Operand):

    def __init__(self, address: str, width: int, src: bool, dest: bool):
        self.width = width
        super().__init__(address.lower(), OT.MEM, src, dest)


class ImmediateOperand(Operand):

    def __init__(self, value: str, width: int):
        self.width = width
        super().__init__(value.lower(), OT.IMM, True, False)

class OperandSpec:
    values: List[str]
    type: OT
    width: int
    signed: bool = True
    src: bool
    dest: bool

    # certain operand values have special handling (e.g., separate opcode when RAX is a destination)
    # magic_value attribute indicates a specification for this special value
    magic_value: bool = False

    def __init__(self, values: List[str], type_: OT, src: bool, dest: bool):
        self.values = values
        self.type = type_
        self.src = src
        self.dest = dest
        self.width = 0

    def __str__(self):
        return f"{self.values}"


class InstructionSpec:
    name: str
    operands: List[OperandSpec]
    implicit_operands: List[OperandSpec]
    category: str
    control_flow = False

    has_mem_operand = False
    has_write = False
    has_magic_value: bool = False
    has_empty_operand = False

    def __init__(self):
        self.operands = []
        self.implicit_operands = []

    def __str__(self):
        ops = ""
        for o in self.operands:
            ops += str(o) + " "
        return f"{self.name} {ops}"

class InstructionSet():
    ot_str_to_enum = {
        "REG": OT.REG,
        "MEM": OT.MEM,
        "IMM": OT.IMM,
        "LABEL": OT.LABEL,
        "AGEN": OT.AGEN,
        "FLAGS": OT.FLAGS,
        "COND": OT.COND,
    }
    instructions: List[InstructionSpec]
    instruction_unfiltered: List[InstructionSpec]

    def __init__(self, filename: str, include_only : List[str]=None, exclude_categories : List[str]=None):
        self.instructions: List[InstructionSpec] = []
        self.init_from_file(filename, include_only)
        # self.instruction_unfiltered = deepcopy(self.instructions)
        self.reduce(exclude_categories)
        self.dedup()

        self.control_flow_instructions = \
            [i for i in self.instructions if i.control_flow]

        self.non_control_flow_instructions = \
            [i for i in self.instructions if not i.control_flow]

        self.non_memory_access_instructions = \
            [i for i in self.non_control_flow_instructions if not i.has_mem_operand]
        self.memory_access_instructions = \
            [i for i in self.non_control_flow_instructions if i.has_mem_operand]
        self.load_instructions = [i for i in self.memory_access_instructions if not i.has_write]
        self.store_instructions = [i for i in self.memory_access_instructions if i.has_write]

    def init_from_file(self, filename: str, include_only : List[str]):
        with open(filename, "r") as f:
            root = json.load(f)
        for instruction_node in root:
            if ((include_only == None) or (instruction_node["name"] in include_only)) and instruction_node["control_flow"] == False \
            and (not instruction_node["category"].startswith("SSE")):
                instruction = InstructionSpec()
                instruction.name = instruction_node["name"]
                instruction.category = instruction_node["category"]
                instruction.control_flow = instruction_node["control_flow"]

                for op_node in instruction_node["operands"]:
                    op = self.parse_operand(op_node, instruction)
                    instruction.operands.append(op)
                    if op.magic_value:
                        instruction.has_magic_value = True

                for op_node in instruction_node["implicit_operands"]:
                    op = self.parse_operand(op_node, instruction)
                    instruction.implicit_operands.append(op)

                if not instruction.has_empty_operand:
                    self.instructions.append(instruction)

    def parse_operand(self, op: Dict, parent: InstructionSpec) -> OperandSpec:
        op_type = self.ot_str_to_enum[op["type_"]]
        op_values = op.get("values", [])
        op_values2 = [val for val in op_values if (not (val in flatten(register_blocklist.values()))) and
                                                  (not ((val in flatten(memory_register_list.values())) and op['dest']))]
        if op_type == "REG":
            if op_values2 == []:
                parent.has_empty_operand = True
            op_values2 = sorted(op_values2)
            
        spec = OperandSpec(op_values2, op_type, op["src"], op["dest"])
        spec.width = op["width"]
        spec.signed = op.get("signed", False)

        if op_type == OT.MEM:
            parent.has_mem_operand = True
            if spec.dest:
                parent.has_write = True

        return spec

    def reduce(self, exclude_only : List[str]):
        updated_list = [i for i in self.instructions if not i.category.startswith("SSE")]
        self.instructions = updated_list

    def dedup(self):
        """
        Instruction set spec may contain several copies of the same instruction.
        Remove them.
        """
        skip_list = set()
        for i in range(len(self.instructions)):
            for j in range(i + 1, len(self.instructions)):
                inst1 = self.instructions[i]
                inst2 = self.instructions[j]
                if inst1.name == inst2.name and len(inst1.operands) == len(inst2.operands):
                    match = True
                    for k, op1 in enumerate(inst1.operands):
                        op2 = inst2.operands[k]

                        if op1.type != op2.type:
                            match = False
                            continue

                        if op1.values != op2.values:
                            match = False
                            continue

                        if op1.width != op2.width and op1.type != OT.IMM:
                            match = False
                            continue

                        # assert op1.src == op2.src
                        # assert op1.dest == op2.dest

                    if match:
                        skip_list.add(inst1)

        for s in skip_list:
            self.instructions.remove(s)


def generate_reg_operand(spec: OperandSpec) -> Operand:
        choices = []
        if spec.values:
            choices = [val for val in spec.values if (not (val in flatten(register_blocklist.values()))) and (not (val in flatten(memory_register_list.values()) and spec.dest))]
        else:
            choices = register_allowlist[spec.width]

        return random.choice(choices)

def generate_mem_operand(spec: OperandSpec) -> Operand:

    address_reg = random.choice(memory_register_list[64])

    val = random.randint(0, pow(2, 12) - 1)
    if spec.width == 8:
        op = "byte ptr [{base} + {offset}]".format(base=base_register, offset=address_reg)
    elif spec.width == 16:
        op = "word ptr [{base} + {offset}]".format(base=base_register,  offset=address_reg)
    elif spec.width == 32:
        op = "dword ptr [{base} + {offset}]".format(base=base_register,  offset=address_reg)
    elif spec.width == 64:
        op = "qword ptr [{base} + {offset}]".format(base=base_register,  offset=address_reg)
    return op

def generate_imm_operand(spec: OperandSpec) -> Operand:
    # generate bitmask
    if spec.values and spec.values[0] == "bitmask":
        # FIXME: this implementation always returns the same bitmask
        # make it random
        value = str(pow(2, spec.width) - 2)
        return value

    # generate from width
    if spec.signed:
        range_min = pow(2, spec.width - 1) * -1
        range_max = pow(2, spec.width - 1) - 1
    else:
        range_min = 0
        range_max = pow(2, spec.width - 1)
    value = str(random.randint(range_min, range_max))
    return value

def generate_agen_operand(spec: OperandSpec) -> Operand:
    n_operands = random.randint(1, 3)
    op = ""
    reg1 = random.choice(register_allowlist[spec.width])
    op += "[" + reg1
    if n_operands == 1:
        op += "]"
        return op

    reg2 = random.choice(register_allowlist[spec.width])
    op += " + " + reg2
    if n_operands == 2:
        op += "]"
        return op

    imm = str(random.randint(0, pow(2, 16) - 1))
    op += " + " + imm + "]"
    return op

def generate_test_case(program_size : int, mem_accesses : int, instruction_spec : InstructionSet):
    # ===================================================================================

    # choose "mem_accesses" instructions that will access memory
    inst_indices = list(range(program_size))
    random.shuffle(inst_indices)
    mem_access_indices = inst_indices[0:mem_accesses]

    # Generate code
    code = "" 
    for j in range(program_size):
        inst = ""
        if j not in mem_access_indices:
            inst_desc = random.choice(instruction_spec.non_memory_access_instructions)
        else:
            inst_desc = random.choice(instruction_spec.memory_access_instructions)

        inst += inst_desc.name + " "
        num_operands = len(inst_desc.operands)
        operand_indices = list(range(num_operands))

        # SPECIAL CASE: BASE-STRINGOP implicitly accesses mem and needs alignment
        if inst_desc.category == "BASE-STRINGOP":
            if inst_desc.name.startswith('rep'):
                align_mask = 0xFF  # at most 255 repetitions
                code += f"and rcx, {align_mask}\n"
        for (op, ind) in zip(inst_desc.operands, operand_indices):
            op_str = ""
            if op.type == OT.REG:
                op_str = generate_reg_operand(op)
                # SPECIAL CASE: if BT, BTC, BTS, BTR need to align the offset operand
                if op.src and ind != 0 and inst_desc.name.startswith('bt'):
                    align_mask = 0xF  # use only lower nibble
                    align_inst = f"and {op_str}, {hex(align_mask)}\n"
                    code += align_inst
            elif op.type == OT.MEM:
                op_str = generate_mem_operand(op)
            elif op.type == OT.IMM:
                op_str = generate_imm_operand(op)
            elif op.type == OT.AGEN:
                op_str = generate_agen_operand(op)
            inst += op_str + ", "
        if (num_operands > 0):
            inst = inst[:-2] + "\n"
        else:
            inst = inst[:-1] + "\n"
        code += inst
    return code   

if __name__ == "__main__":
    print("[ERROR]", "This file is not meant to be run directly. Use `fuzzer.py` instead.")
    exit(1)