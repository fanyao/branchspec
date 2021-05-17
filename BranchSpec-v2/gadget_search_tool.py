#!/usr/bin/python

import distorm3
from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import maxint, bytes2str
from elftools.dwarf.descriptions import describe_form_class
from tqdm import tqdm

cond_jmps = {
    "JO": ["OF"],
    "JNO": ["OF"],
    "JS": ["SF"],
    "JNS": ["SF"],

    "JE": ["ZF"],
    "JZ": ["ZF"],
    "JNE": ["ZF"],
    "JNZ": ["ZF"],

    "JB": ["CF"],
    "JNAE": ["CF"],
    "JC": ["CF"],

    "JNB": ["CF"],
    "JAE": ["CF"],
    "JNC": ["CF"],

    "JBE": ["CF", "ZF"],
    "JNA": ["CF", "ZF"],

    "JA": ["CF", "ZF"],
    "JNBE": ["CF", "ZF"],

    "JL": ["SF", "OF"],
    "JNGE": ["SF", "OF"],

    "JGE": ["SF", "OF"],
    "JNL": ["SF", "OF"],

    "JLE": ["SF", "OF", "ZF"],
    "JNG": ["SF", "OF", "ZF"],

    "JG": ["SF", "OF", "ZF"],
    "JNLE": ["SF", "OF", "ZF"],

    "JP": ["PF"],
    "JPE": ["PF"],

    "JNP": ["PF"],
    "JPO": ["PF"]
}

cond_jmps_op = [i for i in cond_jmps]

flag_modifier = {'AAA': ["AF", "CF"],
 'AAD': ["SF", "ZF", "PF"],
 'AAM': ["SF", "ZF", "PF"],
 'AAS': ["AF", "CF"],
 'ADC': ["OF", "SF", "ZF", "AF", "CF", "PF"],
 'ADCX': ["CF"],
 'ADD': ["OF", "SF", "ZF", "AF", "CF", "PF"],
 'ADOX': ["OF"],
 'AND': ["OF", "CF"],
 'ANDN': ["SF", "ZF"],
 'ARPL': ["ZF"],
 'BEXTR': ["ZF"],
 'BLSI': ["ZF", "SF"],
 'BLSMSK': ["SF", "CF", "ZF", "OF"],
 'BLSR': ["ZF", "SF", "CF", "OF"],
 'B"SF"': ["ZF"],
 'BSR': ["ZF"],
 'BT': ["CF"],
 'BTC': ["CF"],
 'BTR': ["CF"],
 'BTS': ["CF"],
 'BZHI': ["ZF", "CF", "SF", "OF"],
 'CLC': ["CF"],
 'CLD': ["DF"],
 'CLI': ["IF"],
 'CMC': ["CF"],
 'CMP': ["CF", "OF", "SF", "ZF", "AF", "PF"],
 'CMPXCHG': ["ZF", "CF", "PF", "AF", "SF", "OF"],
 'DAA': ["CF", "AF", "SF", "ZF", "PF", ],
 'DAS': ["CF", "AF", "SF", "ZF", "PF", ],
 'DEC': ["OF", "SF", "ZF", "AF", "PF"],
 'IMUL': ["CF", "OF"],
 'INC': ["OF", "SF", "ZF", "AF", "PF", ],
 'LSL': ["ZF"],
 'LZCNT': ["ZF", "CF"],
 'MUL': ["OF", "CF"],
 'NEG': ["CF", "OF", "SF", "ZF", "AF", "PF"],
 'OR': ["OF", "CF", "SF", "ZF", "PF"],
 'POPCNT': ["OF", "SF", "ZF", "AF", "CF", "PF", "ZF"],
 'PTEST': ["OF", "AF", "PF", "SF", "ZF", "CF"],
 'RDRAND': ["CF", "OF", "SF", "ZF", "AF", "PF"],
 'RDSEED': ["CF", "OF", "SF", "ZF", "AF", "PF"],
 'SAHF': ["SF", "ZF", "AF", "PF", "CF"],
 'SBB': ["OF", "SF", "ZF", "AF", "PF", "CF"],
 'SHLD': ["CF", "SF", "ZF", "PF"],
 'SHRD': ["CF", "SF", "ZF", "PF"],
 'STC': ["CF"],
 'SUB': ["OF", "SF", "ZF", "AF", "PF", "CF"],
 'TEST': ["OF", "CF", "SF", "ZF", "PF"],
}
code_dict = {}
opcodes = []

def build_code_dict(code, section, dwarfinfo):
    # Credit: https://github.com/HexHive/SMoTherSpectre
    s_off = section['sh_offset']

    ## Create a dictionary of valid instructions at all offsets
    for offset in tqdm(range(len(code))): 
        if code_dict.has_key(offset): continue
        for insn in distorm3.DecomposeGenerator(s_off + offset, code[offset:], distorm3.Decode64Bits, distorm3.DF_STOP_ON_FLOW_CONTROL):
            if insn.valid:
                code_dict[offset] = insn
            offset += insn.size


def find_flag_modifier(key, jmp):
    # For v1 type gadget
    org_key = key
    c_flags = cond_jmps[code_dict[key].mnemonic]
    found_inst = False
    while (key):
        key = key - 1
        if (org_key - key) > 20: break # Assume upto 20 instrunction is speculative (this can be upto 224)
        this_flags = flag_modifier[code_dict[key].mnemonic]
        if any(item in this_flags for item in c_flags):
            found_inst = True
            
    if found_inst:
        for i in code_dict[key:org_key]:
            print(code_dict[i]._toText())
    return found_inst


def checkMemOperand(key):
    operand_type = [j.type for j in code_dict[key].operands]
    if (operand_type == "AbsoluteMemory") or (operand_type == "AbsoluteMemoryAddress"):
        return True
    return False


binary_file = "<SET_BINARY_FILE_LOCATION>"

with open(binary_file, 'rb') as f:
    # Credit: https://github.com/HexHive/SMoTherSpectre
    elffile = ELFFile(f)
    dwarfinfo = None
    if elffile.has_dwarf_info():
        dwarfinfo = elffile.get_dwarf_info()

    for section in elffile.iter_sections():
        if section.name.startswith('.text'):
            code = section.data()
            build_code_dict(code, section, dwarfinfo)


vul_dict = {}
idx = 0

for i in code_dict:
    found_test = False
    if code_dict[i].mnemonic == "TEST":
        start_key = i
        found_test = True
    
    if found_test:
        if (code_dict[i].mnemonic in cond_jmps_op):
            found_test = False
            end_key = i
            vul_dict[idx] = []
            vul_dict[idx].append(code_dict[start_key])
            vul_dict[idx].append(code_dict[end_key])
            idx = idx + 1


for i in vul_dict:
    for j in vul_dict[i]:
        print(j._toText())
    print("=============")