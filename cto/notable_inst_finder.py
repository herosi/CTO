import idc
import ida_idaapi
import ida_search
import ida_bytes
import ida_funcs
import ida_gdl
import ida_ua
import ida_segment

import os
import json
import re

class notable_inst_t(object):
    def __init__(self, frules=os.path.join(os.path.dirname(__file__),"notable_insts.json"), show_high_ent=False, cmt_prefix="NT_INST: "):
        with open(frules) as f:
            insts = json.load(f)
        self.insts = {}
        self.minsts = {}
        for rule_type in insts:
            if rule_type not in self.insts:
                self.insts[rule_type] = {}
            for rule_name in insts[rule_type]:
                self.insts[rule_type][rule_name] = insts[rule_type][rule_name]
        #print(self.insts)
        self.cmt_prefix = cmt_prefix
        
    @staticmethod
    def get_inst_eas(rule, regex=False, ea=idc.get_inf_attr(idc.INF_MIN_EA)):
        flags = ida_search.SEARCH_DOWN|ida_search.SEARCH_NEXT
        if regex:
            flags |= ida_search.SEARCH_REGEX
        ea = ida_search.find_text(ea, 0, 0, rule, flags)
        while ea != ida_idaapi.BADADDR:
            yield ea
            ea = ida_bytes.next_head(ea, ida_idaapi.BADADDR)
            ea = ida_search.find_text(ea, 0, 0, rule, flags)
            
    def get_notable_insts(self):
        for rule_name in self.insts["single"]:
            rule = self.insts["single"][rule_name]["rule"]
            regex = self.insts["single"][rule_name]["regex"]
            for ea in self.get_inst_eas(rule, regex=regex):
                yield ea, rule_name
                
        flags = ida_search.SEARCH_DOWN|ida_search.SEARCH_NEXT
        for rule_name in self.insts["multiple"]:
            rules = self.insts["multiple"][rule_name]["rules"]
            regex = self.insts["multiple"][rule_name]["regex"]
            for ea in self.get_inst_eas(rules[0][0], regex=regex):
                if ea != ida_idaapi.BADADDR:
                    first_ea = ea
                    found_flag = True
                    for rule, tolerance in rules[1:]:
                        false_times = 0
                        while false_times < tolerance and ea != ida_idaapi.BADADDR:
                            ea = ida_search.find_code(ea, flags)
                            disasm = idc.generate_disasm_line(ea, 0)
                            #print(hex(ea), disasm)
                            if not re.match(rule, disasm):
                                false_times += 1
                                found_flag = False
                            elif ea == ida_idaapi.BADADDR:
                                found_flag = False
                                break
                            else:
                                found_flag = True
                                break
                        if not found_flag:
                            break
                    if found_flag:
                        yield first_ea, rule_name
    
    def set_cmt(self, ea, rule_name):
        cmt = ida_bytes.get_cmt(ea, False)
        if not cmt or cmt.find(rule_name) < 0:
            new_cmt = self.cmt_prefix + rule_name
            if cmt:
                cmt = self.cmt_prefix + rule_name + ", " + cmt
            ida_bytes.set_cmt(ea, new_cmt, False)
                
    def collect_notable_insts(self):
        for inst_ea, rule_name in self.get_notable_insts():
            self.set_cmt(inst_ea, rule_name)
            disasm = idc.generate_disasm_line(inst_ea, 0)
            f = ida_funcs.get_func(inst_ea)
            func_ea = idc.BADADDR
            if f:
                func_ea = f.start_ea
            yield func_ea, inst_ea, rule_name, disasm

def main():
    i = notable_inst_t()
    for func_ea, inst_ea, rule_name, disasm in i.collect_notable_insts():
        print("%x %s: %x: %s: %s" % (func_ea, idc.get_name(func_ea), inst_ea, rule_name, disasm))

if __name__ == "__main__":
    main()
