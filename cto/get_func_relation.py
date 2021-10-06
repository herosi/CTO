import idc
import idautils
import ida_xref
import ida_search
import ida_idaapi
import ida_name
import ida_funcs
import ida_bytes
import ida_ua
import ida_gdl
import ida_xref
import ida_nalt
import ida_typeinf
import ida_netnode
import ida_kernwin
import ida_idp
import ida_strlist
import ida_segment
import ida_entry

import inspect
import os
import tempfile

import tinfo
import jump
ida_idaapi.require("tinfo")
ida_idaapi.require("jump")

g_max_recursive = 100
if "g_debug" not in globals():
    g_debug = False
g_fp = None
g_max_lines = 20000
g_lines = 0
g_dont_record_mnems = ['nop']

def l_dbg_print(*msg):
    global g_fp
    global g_lines
    if True:
        if not g_fp:
            try:
                g_fp = tempfile.NamedTemporaryFile(delete=False, buffering=0)
            except TypeError:
                g_fp = tempfile.NamedTemporaryFile(delete=False) # for python 2.7
            if g_fp:
                ida_kernwin.msg("%s was created as a debug log file.\n" % g_fp.name)
                
        callee_stk = inspect.stack()[1]
        # for python 2
        if isinstance(callee_stk, tuple):
            frame, filename, lineno, function, source_code, source_index = callee_stk
        # for python 3
        else:
            filename = callee_stk.filename
            lineno = callee_stk.lineno
            function = callee_stk.function
            
        if len(msg) > 0:
            if isinstance(msg[-1], str):
                if not msg[-1].endswith(os.linesep):
                    msg = list(msg)
                    msg.append(os.linesep)
            else:
                msg = list(msg)
                msg.append(os.linesep)
        msg = "[%s:%d %s] " % (os.path.basename(filename), lineno, function) + " ".join([str(x) for x in msg])
        if g_fp:
            g_fp.write(msg.encode('utf-8'))
        if g_lines < g_max_lines:
            ida_kernwin.msg(msg)
        elif g_lines == g_max_lines:
            ida_kernwin.msg("The number of lines has been exceeded. Stop displaying debug messages.%s" % os.linesep)
            if g_fp:
                ida_kernwin.msg("See %s to check the rest of messages.%s" % (g_fp.name, os.linesep))
        g_lines += 1

def funcs(ea=0):
    while ea != ida_idaapi.BADADDR:
        f = ida_funcs.get_next_func(ea)
        if f:
            ea = f.start_ea
            yield f
        else:
            break

def get_bbs(f):
    bbs = {}
    for block in f:
        bbs[block.start_ea] = block
    return bbs

def get_func_bbs(ea):
    f = ida_funcs.get_func(ea)
    if f:
        fc = ida_gdl.FlowChart(f)
        bbs = get_bbs(fc)
        return f, bbs
    return None, {}

def get_imports():
    def imp_cb(ea, name, ordinal):
        result.append((modname, ea, str(ordinal) if not name else name, ordinal))
        # True -> Continue enumeration
        # False -> Stop enumeration
        return True
    
    nimps = ida_nalt.get_import_module_qty()
    result = []
    for i in range(nimps):
        modname = ida_nalt.get_import_module_name(i)
        if not modname:
            modname = "<unnamed>"
        ida_nalt.enum_import_names(i, imp_cb)
    return result

def is_ea_in_func(target_ea, bbs):
    for bbea in bbs:
        bb = bbs[bbea]
        if bb.start_ea <= target_ea and target_ea < bb.end_ea:
            return True
    return False

FT_UNK = 0    # unknown
FT_GEN = 1    # for general internal calls
FT_LIB = 2    # for static linked libraries
FT_API = 4    # for API call
FT_MEM = 8    # for indicrect calls
FT_VAR = 16   # for global/static variables. strictly speaking, it's not "func type"
FT_STR = 32   # for string variables. strictly speaking, it's not "func type"
FT_STO = 64   # for structure's offset access. strictly speaking, it's not "func type"
FT_VTB = 128  # for vftable
def get_func_type(func_ea, import_eas=None):
    if import_eas is None:
        import_eas = []
    func_type = FT_UNK
    func_flags = idc.get_func_attr(func_ea, idc.FUNCATTR_FLAGS)
    f = ida_funcs.get_func(func_ea)
    
    fn = idc.get_func_name(func_ea)
    if not fn:
        fn = ida_name.get_name(func_ea)
    
    if func_ea in import_eas:
        func_type = FT_API
    elif func_flags != ida_idaapi.BADADDR and func_flags & ida_funcs.FUNC_LIB:
        func_type = FT_LIB
    elif f is not None:
        func_type = FT_GEN
        if f.flags & ida_funcs.FUNC_THUNK:
            v = idc.get_operand_value(f.start_ea, 0)
            fn = idc.get_func_name(v)
            if not fn:
                fn = ida_name.get_name(v)
                
            if v in import_eas:
                func_type = FT_API
            else:
                func_type = FT_LIB
    elif fn and tinfo.get_tinfo_by_name(fn):
        func_type = FT_API
    
    return func_type

def get_func_info_by_name(name):
    func_type = FT_UNK
    func_name = ""
    func_ea = ida_idaapi.BADADDR
    ret = tinfo.get_tinfo_by_name(name)
    if ret:
        # for APIs
        func_name = name
        func_type = FT_API
        func_ea = idc.get_name_ea_simple(func_name)
    else:
        for n in tinfo.guess_true_names(name):
            ret = tinfo.get_tinfo_by_name(n)
            if ret:
                # for APIs
                func_name = n
                func_type = FT_API
                func_ea = idc.get_name_ea_simple(name)
                if func_ea == ida_idaapi.BADADDR:
                    func_ea = idc.get_name_ea_simple(n)
                break
    if ret:
        return func_name, func_type, func_ea
    
    ret = tinfo.get_local_tinfo_by_name(name)
    if ret:
        # for a general function with its function definition
        func_ea = idc.get_name_ea_simple(func_name)
        func_flags = idc.get_func_attr(func_ea, idc.FUNCATTR_FLAGS)
        f = ida_funcs.get_func(func_ea)
        #func_type = FT_GEN
        func_name = name
        func_type = get_func_type(func_ea)
        if func_flags != ida_idaapi.BADADDR and func_flags & ida_funcs.FUNC_LIB:
            func_type = FT_LIB
            
    ea = idc.get_name_ea_simple(name)
    f = ida_funcs.get_func(ea)
    if f:
        func_name = name
        func_ea = ea
        func_type = get_func_type(func_ea)
    else:
        # get addr
        try:
            func_ea = int(name, 16)
            if not ida_bytes.is_mapped(func_ea):
                func_ea = ida_idaapi.BADADDR
            func_type = get_func_type(func_ea)
        except ValueError:
            func_ea = ida_idaapi.BADADDR
            
    if func_ea != ida_idaapi.BADADDR:
        func_flags = idc.get_func_attr(func_ea, idc.FUNCATTR_FLAGS)
        if func_flags != ida_idaapi.BADADDR and func_flags & ida_funcs.FUNC_LIB:
            func_type = FT_LIB
            
    return func_name, func_type, func_ea

def get_func_info_by_cmt(ea):
    func_type = FT_UNK
    func_name = ""
    func_ea = ida_idaapi.BADADDR
    
    # get non-repeatable comment
    cmt = ida_bytes.get_cmt(ea, 0)
    
    cmts = []
    if cmt is not None:
        cmt = cmt.strip()
        cmts.append(cmt)
        # for funcap.py or something
        #     e.g. oleaut32_DispGetIDsOfNames()
        #     e.g. oleaut32_DispGetIDsOfName
        if cmt.find('_') >= 0:
            cmts.append(cmt.split('_', 1)[1].split('(')[0])
    
    for cmt in cmts:
        func_name, func_type, func_ea = get_func_info_by_name(cmt)
        if func_name:
            break
    return func_name, func_type, func_ea
            
def get_func_info_by_opstr(ea, opn):
    func_type = FT_UNK
    func_name = ""
    func_ea = ida_idaapi.BADADDR

    opstr = idc.print_operand(ea, opn)
    
    # api name in structure offset
    # e.g. call    [edi+BaseStructure.kernel32.GetVersionExA] 
    #           or [eax+struc_1.field_3B4_InternetSetOptionA]
    if opstr.find('.') >= 0 and opstr.find(')') < 0:
        member_names = opstr.split('+')[-1].split('.')[:-1]
        member_name = member_names.pop()
        api_name = opstr.split('.')[-1].rstrip(']').strip()
        """
        #orig_api_name = api_name
        struc_name = member_name
        sid = ida_struct.get_struc_id(struc_name)
        if len(member_names) == 0:
            # for stack
            # e.g. call    [ebp+var_88.GetVersionExA]
            # e.g. call    [ebp+var_88.struc_2.GetVersionExA]
            frame = ida_frame.get_frame(ea)
            if frame.id != ida_idaapi.BADADDR:
                sid = frame.id
        #member_offset = idc.get_member_offset(sid, member_name)
        """
        func_name, func_type, func_ea = get_func_info_by_name(api_name)
        if not func_name and api_name.find('_') >= 0 and api_name.startswith("field_"):
            ar_func_name = api_name.split('_', 2)
            if len(ar_func_name) > 2:
                func_name = ar_func_name[2]
                func_name, func_type, func_ea = get_func_info_by_name(func_name)
    # api name in stack offset
    # e.g. call    [ebp+GetVersionExA]
    elif opstr.find('+') >= 0 and opstr.find(')') < 0 and opstr.find('var_') < 0 and opstr.find('h]') < 0:
        api_name = opstr.split('+')[-1].rstrip(']').strip()
        func_name, func_type, func_ea = get_func_info_by_name(api_name)
    # api name in structure offset (for negative direction mainly)
    # e.g. call    [ebp+(struc_1.CreateProcessA-0F7Ch)]
    elif opstr.find('.') >= 0 and (opstr.find('-') >= 0 or opstr.find('+') >= 0) and opstr.find(')') >= 0:
        if opstr.find('-') >= 0 and opstr.find('+') >= 0:
            api_name = opstr.split('.')[-1].split('-')[0].split('+')[0].strip()
        elif opstr.find('-') >= 0:
            api_name = opstr.split('.')[-1].split('-')[0].strip()
            struc_name = opstr.split('.')[-2].split('(')[-1].strip()
        # dead code?
        else:
            api_name = opstr.split('.')[-1].split('+')[0].strip()
            struc_name = opstr.split('.')[-2].split('(')[-1].strip()
        func_name, func_type, func_ea = get_func_info_by_name(api_name)
        if not func_name and api_name.find('_') >= 0 and api_name.startswith("field_"):
            ar_func_name = api_name.split('_', 2)
            if len(ar_func_name) > 2:
                func_name = ar_func_name[2]
                func_name, func_type, func_ea = get_func_info_by_name(func_name)
    # mov     cs:LoadLibraryW_0, rax
    elif opstr.find(':') >= 0:
        func_name = opstr.split(":")[1]
        func_name, func_type, func_ea = get_func_info_by_name(func_name)
    return func_name, func_type, func_ea

def get_offset_fptr(v):
    target_ea = ida_idaapi.BADADDR
    flags = ida_bytes.get_full_flags(v)
    # call    cs:off_180097558 -> offset free
    if ida_bytes.is_qword(flags):
        off_v = ida_bytes.get_qword(v)
        flags = ida_bytes.get_full_flags(off_v)
        if ida_bytes.is_code(flags):
            target_ea = off_v
        #.data:00007FF9648576A8 ; void __stdcall __noreturn FreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode)
        #.data:00007FF9648576A8 FreeLibraryAndExitThread dq ?  
        else:
            tif = tinfo.get_tinfo(v)
            if tif:
                target_ea = v
    elif ida_bytes.is_dword(flags):
        off_v = ida_bytes.get_dword(v)
        flags = ida_bytes.get_full_flags(off_v)
        if ida_bytes.is_code(flags):
            target_ea = off_v
        #.data:00007FF9648576A8 ; void __stdcall __noreturn FreeLibraryAndExitThread(HMODULE hLibModule, DWORD dwExitCode)
        #.data:00007FF9648576A8 FreeLibraryAndExitThread dq ?  
        else:
            tif = tinfo.get_tinfo(v)
            if tif:
                target_ea = v
    return target_ea

def get_ref_func(ea):
    n = ida_netnode.netnode("$ vmm functions")
    r = n.altval(ea)
    if r != ida_idaapi.BADADDR:
        r -= 1
    return r & ida_idaapi.BADADDR

def get_switch_info(ea):
    si = ida_nalt.switch_info_t()
    ida_nalt.get_switch_info(si, ea)
    if si.startea != ida_idaapi.BADADDR:
        return si
    return None

def is_indirect_jump_insn(ea):
    tmp = ida_ua.insn_t()
    if ida_ua.decode_insn(tmp, ea) and ida_idp.is_indirect_jump_insn(tmp):
        return True
    return False
    
def is_call_insn(ea):
    tmp = ida_ua.insn_t()
    if ida_ua.decode_insn(tmp, ea) and ida_idp.is_call_insn(tmp):
        return True
    return False

def guess_var_size(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        return 0
    next_ea = ida_bytes.next_head(ea, ea + seg.abytes()+1)
    sz = seg.abytes()
    while sz > 0:
        if ea + sz <= next_ea :
            break
        sz = sz // 2
    return sz

def get_var_value_with_guess(ea):
    sz = guess_var_size(ea)
    if sz == 0:
        return None
    
    value = None
    if sz == 8:
        value = ida_bytes.get_qword(ea)
    elif sz == 4:
        value = ida_bytes.get_dword(ea)
    elif sz == 2:
        value = ida_bytes.get_word(ea)
    else:
        value = ida_bytes.get_byte(ea)
    return value

def get_var_value(ea):
    value = None
    flags = ida_bytes.get_full_flags(ea)
    if ida_bytes.is_qword(flags):
        value = ida_bytes.get_qword(ea)
    elif ida_bytes.is_dword(flags):
        value = ida_bytes.get_dword(ea)
    elif ida_bytes.is_word(flags):
        value = ida_bytes.get_word(ea)
    elif ida_bytes.is_byte(flags):
        value = ida_bytes.get_byte(ea)
    if not ida_bytes.has_value(flags):
        value = None
    elif value is None:
        value = get_var_value_with_guess(ea)
    return value

def get_str(ea, v, string_eas):
    data = ''
    data_type = FT_VAR
    vflags = ida_bytes.get_full_flags(v)
    if ida_bytes.is_strlit(vflags):
        data_type = FT_STR
        if ea in string_eas:
            data = string_eas[ea][1]
        else:
            sz = ida_bytes.get_item_size(v)
            strtype = idc.get_str_type(v)
            data = ida_bytes.get_strlit_contents(v, sz, strtype)
            if data is None:
                data = ""
            else:
                data = data.decode('utf-8', 'replace')
    elif v in string_eas:
        data_type = FT_STR
        data = string_eas[v][1]
    if data_type == FT_VAR:
        ln, lnnum, keyidx = jump.get_line_no(v, "::`vftable'", chk_cmt=True)
        if ln:
            data_type = FT_VTB
            data = ""
        #print("%x" % v, ln, lnnum, keyidx)
        tmp_data = get_var_value(v)
        if tmp_data is not None:
            data = hex(tmp_data)
        else:
            data = "N/A"
    return data, data_type

def get_funcptr_ea(ea, bbs, import_eas, string_eas):
    target_ea = ida_idaapi.BADADDR
    func_type = FT_UNK
    func_name = ""
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, ea)
    for i in range(inslen):
        if ida_ua.o_void == insn.ops[i].type:
            i = -1
            break
        
        optype = idc.get_operand_type(ea, i)
        v = idc.get_operand_value(ea, i)
        flags = ida_bytes.get_full_flags(v)
        
        # call    sub_xxxxxxxx
        # for jump to a sub routine (jmp     sub_xxxxxxxxxx)
        if optype in [ida_ua.o_near, ida_ua.o_far]:
            if not is_ea_in_func(v, bbs):
                target_ea = v
                break
        # mov    r8, sub_xxxxxxxxx
        elif optype in [ida_ua.o_imm]:
            # flags > 0 means that it is not just a value, but ea.
            if flags > 0 and not is_ea_in_func(v, bbs):
                if ida_bytes.is_code(flags):
                    target_ea = v
                    break
                # for static/global variables or strings or vftable
                elif not ida_bytes.is_code(flags):
                    #print("%x, %x, %x" % (ea, v, target_ea))
                    target_ea = v
                    func_name, func_type = get_str(ea, v, string_eas)
                    break
        elif optype in [ida_ua.o_mem]:
            f = ida_funcs.get_func(ea)
            # call    ReadFile
            if v in import_eas:
                target_ea = v
                func_type = FT_API
                break
            # jmp     jpt_10006965[eax*4] ; switch jump
            elif get_switch_info(ea):
                target_ea = ida_idaapi.BADADDR
                func_type = FT_UNK
                break
            # lea     r8, sub_18002BE60
            # mov     r9, cs:hModule
            elif flags > 0 and not is_ea_in_func(v, bbs):
                target_ea = get_offset_fptr(v)
                if ida_bytes.is_code(flags):
                    target_ea = v
                    break
                # jmp     cs:qword_7FF964905070
                # with Attributes: thunk
                elif f.flags & ida_funcs.FUNC_THUNK:
                    target_ea = v
                    break
                # lea     rdi, off_7FF96484ABF8 -> sub_xxxxxxxxxxxx
                elif target_ea != ida_idaapi.BADADDR and target_ea != v:
                    ln, lnnum, keyidx = jump.get_line_no(v, "::`vftable'", chk_cmt=True)
                    if ln:
                        target_ea = v
                        func_type = FT_VTB
                    break
                # for static/global variables or strings or vftable
                elif not ida_bytes.is_code(flags):
                    tmp_func_name, tmp_func_type, _v = get_func_info_by_opstr(ea, i)
                    if tmp_func_name:
                        func_name = tmp_func_name
                        func_type = tmp_func_type
                        target_ea = v
                    else:
                        # for static/global variables or strings or vftable
                        target_ea = v
                        func_name, func_type = get_str(ea, v, string_eas)
                    break
            else:
                # call    cs:off_180097558 -> offset free
                # jmp     cs:off_180097558 -> offset free
                target_ea = get_offset_fptr(v)
                if target_ea != ida_idaapi.BADADDR:
                    break
                # for static/global variables or strings or vftable
                elif v != ida_idaapi.BADADDR:
                    target_ea = v
                    func_name, func_type = get_str(ea, v, string_eas)
                    break
        # call    qword ptr [rsi+40h]
        # jmp     qword ptr [rsi+40h]
        # call    r9
        # jmp     r9
        elif optype in [ida_ua.o_reg, ida_ua.o_displ, ida_ua.o_phrase]:
            v = get_ref_func(ea)
            target_ea = get_offset_fptr(v)
            # for having an offset of an API
            if optype in [ida_ua.o_reg] and target_ea != ida_idaapi.BADADDR:
                func_type = get_func_type(target_ea, import_eas)
                if func_type == FT_UNK:
                    func_type = FT_MEM
                break
            # for having an offset of a pointer
            elif optype in [ida_ua.o_reg] and v != ida_idaapi.BADADDR:
                target_ea = v
                func_type = get_func_type(target_ea, import_eas)
                if func_type == FT_UNK:
                    func_type = FT_MEM
                break
            # unresolved indirect calls
            elif is_call_insn(ea) or (is_indirect_jump_insn(ea) and not get_switch_info(ea)):
            #if is_call_insn(ea) or (is_indirect_jump_insn(ea) and not get_switch_info(ea)):
                func_type = FT_MEM
                # if ea has an external xref set by a user manually, get it.
                # however, it gets the first one only.
                for v in get_xrefs_from(ea):
                    target_ea = v
                    func_type = get_func_type(v, import_eas)
                    break
                if target_ea == ida_idaapi.BADADDR:
                    tmp_func_name, tmp_func_type, v = get_func_info_by_opstr(ea, i)
                    if tmp_func_name:
                        func_name = tmp_func_name
                        func_type = tmp_func_type
                    if v != ida_idaapi.BADADDR:
                        target_ea = v
                        break
                    tmp_func_name, tmp_func_type, v = get_func_info_by_cmt(ea)
                    if tmp_func_name:
                        func_name = tmp_func_name
                        func_type = tmp_func_type
                    if v != ida_idaapi.BADADDR:
                        target_ea = v
                        break
                break
    
    if func_type not in [FT_API, FT_MEM, FT_VAR, FT_STR, FT_STO, FT_VTB]:
        func_type = get_func_type(target_ea, import_eas)
    return target_ea, func_type, i, func_name

def get_stroff_ea(ea, import_eas):
    target_ea = ida_idaapi.BADADDR
    func_type = FT_UNK
    func_name = ""
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, ea)
    for i in range(inslen):
        if ida_ua.o_void == insn.ops[i].type:
            i = -1
            break
        
        optype = idc.get_operand_type(ea, i)
        v = idc.get_operand_value(ea, i)
        flags = ida_bytes.get_full_flags(v)
        if optype in [ida_ua.o_displ, ida_ua.o_phrase]:
            v = get_ref_func(ea)
            target_ea = get_offset_fptr(v)
            flags = ida_bytes.get_full_flags(ea)
            if not ida_bytes.is_stkvar(flags, i):
                opstr = idc.print_operand(ea, i)
                mnem = idc.print_insn_mnem(ea)
                #print(opstr)
                
                # for avoiding recording "nop" instruction and "stos" instruction
                # stos instruction has a hidden phrase operand as the first operand.
                # nop is used for instruction alignments for AMD64 assembly.
                if opstr and not mnem in g_dont_record_mnems:
                    #print("%x, %x, %x" % (ea, v, target_ea))
                    func_type = FT_STO
                    break
    if func_type not in [FT_API, FT_MEM, FT_VAR, FT_STR, FT_STO, FT_VTB]:
        func_type = get_func_type(target_ea, import_eas)
    return target_ea, func_type, i, func_name

def get_vtbl_methods(target_ea, vtbl):
    ea = get_offset_fptr(target_ea)
    orig_target_ea = target_ea
    prev_target_ea = target_ea
    item_diff = 8
    seg = ida_segment.getseg(target_ea)
    if seg:
        item_diff = 1<<(seg.bitness+1)
    while target_ea != ida_idaapi.BADADDR:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags):
            yield target_ea, ea
            if orig_target_ea in vtbl:
                vtbl[orig_target_ea][target_ea] = (ea, FT_VTB, -1, "")
            else:
                vtbl[orig_target_ea] = {target_ea: (ea, FT_VTB, -1, "")}
        else:
            break
        
        prev_target_ea = target_ea
        target_ea = ida_search.find_data(target_ea, ida_search.SEARCH_DOWN|ida_search.SEARCH_NEXT)
        if target_ea - prev_target_ea != item_diff:
            break
        ea = get_offset_fptr(target_ea)
        
def get_calls_in_bb(bb, bbs, import_eas, string_eas, result=None, apicalls=None, gvars=None, strings=None, stroff=None, vtbl=None):
    if result is None:
        result = {}
    if apicalls is None:
        apicalls = {}
    if gvars is None:
        gvars = {}
    if strings is None:
        strings = {}
    if stroff is None:
        stroff = {}
    if vtbl is None:
        vtbl = {}
    ea = bb.start_ea
    while ea < bb.end_ea:
        target_ea, func_type, op, target_name = get_funcptr_ea(ea, bbs, import_eas, string_eas)
        if func_type == FT_UNK and target_ea == ida_idaapi.BADADDR:
            #print("%x, %d" % (target_ea, func_type))
            target_ea, func_type, op, target_name = get_stroff_ea(ea, import_eas)
        if func_type not in [FT_UNK, FT_VAR, FT_STR, FT_STO] or (func_type == FT_UNK and target_ea != ida_idaapi.BADADDR):
            result[ea] = (target_ea, func_type, op, target_name)
            if func_type == FT_API:
                apicalls[target_ea] = func_type
        elif func_type in [FT_VAR]:
            gvars[ea] = (target_ea, func_type, op, target_name)
        elif func_type in [FT_STR]:
            strings[ea] = (target_ea, func_type, op, target_name)
        elif func_type in [FT_STO]:
            stroff[ea] = (target_ea, func_type, op, target_name)
        if func_type in [FT_VTB]:
            for vtbl_offset_ea, vtbl_method_ea in get_vtbl_methods(target_ea, vtbl):
                pass
            #pass
        ea = ida_search.find_code(ea, ida_search.SEARCH_DOWN|ida_search.SEARCH_NEXT)

def get_children(bbs, import_eas, string_eas):
    result = {}
    apicalls = {}
    gvars = {}
    strings = {}
    stroff = {}
    vtbl = {}
    for bbea in bbs:
        bb = bbs[bbea]
        get_calls_in_bb(bb, bbs, import_eas, string_eas, result=result, apicalls=apicalls, gvars=gvars, strings=strings, stroff=stroff, vtbl=vtbl)
    return result, apicalls, gvars, strings, stroff, vtbl

def get_xrefs_from(ea):
    next_addr = ida_xref.get_first_fcref_from(ea)
    while next_addr != ida_idaapi.BADADDR:
        yield next_addr
        next_addr = ida_xref.get_next_fcref_from(ea, next_addr)
        
def get_xrefs(ea):
    result = {}
    op = -1
    next_addr = ida_xref.get_first_fcref_to(ea)
    while next_addr != ida_idaapi.BADADDR:
        f = ida_funcs.get_func(next_addr)
        func_ea = ida_idaapi.BADADDR
        func_type = FT_UNK
        if f is not None:
            func_ea = f.start_ea
            func_type = get_func_type(func_ea)
            result[next_addr] = (func_ea, func_type, op, "")
        next_addr = ida_xref.get_next_fcref_to(ea, next_addr)
    # lea    r8, sub_xxxxxxxx
    next_addr = ida_xref.get_first_dref_to(ea)
    while next_addr != ida_idaapi.BADADDR:
        f = ida_funcs.get_func(next_addr)
        func_ea = ida_idaapi.BADADDR
        func_type = FT_UNK
        if f is not None:
            func_ea = f.start_ea
            func_type = get_func_type(func_ea)
            flags = ida_bytes.get_full_flags(func_ea)
            if ida_bytes.is_code(flags):
                result[next_addr] = (func_ea, func_type, op, "")
        next_addr = ida_xref.get_next_dref_to(ea, next_addr)
    return result

def get_drefs_to(ea):
    next_addr = ida_xref.get_first_dref_to(ea)
    while next_addr != ida_idaapi.BADADDR:
        yield next_addr
        next_addr = ida_xref.get_next_dref_to(ea, next_addr)

def get_refed_strings():
    result = {}
    s = idautils.Strings()
    s.setup([ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16], minlen=4)
    #s.setup()
    for i in s:
        r = set(get_drefs_to(i.ea))
        #print("%x: len=%d type=%d -> '%s'" % (i.ea, i.length, i.strtype, str(i)))
        if len(r) > 0:
            for x in r:
                result[x] = (i.ea, str(i))
    return result

def get_dyn_apicalls_partial(func_relations, ea):
    if not ea in func_relations:
        f = ida_funcs.get_func(ea)
        if f:
            ea = f.start_ea
    if ea in func_relations:
        for caller in func_relations[ea]['children']:
            func_ea, func_type, op, func_name = func_relations[ea]['children'][caller]
            if func_ea == ida_idaapi.BADADDR and func_name:
                yield caller, func_name
        
def get_dyn_apicalls(func_relations):
    result = {}
    for callee in func_relations:
        for caller, func_name in get_dyn_apicalls_partial(func_relations, callee):
            result[caller] = func_name
    return result
        
def get_entry_points():
    n = ida_entry.get_entry_qty()
    for i in range(n):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        if ea != ida_idaapi.BADADDR:
            yield ea

def get_opnums(func_relations, keyword='children'):
    opnums = {}
    for func_ea in func_relations:
        for caller in func_relations[func_ea][keyword]:
            callee, func_type, op, func_name = func_relations[func_ea][keyword][caller]
            opnums[caller] = op
    return opnums

def get_vtbl_refs(func_relations):
    result = {}
    for func_ea in func_relations:
        for vtbl_offset in func_relations[func_ea]["vftables"]:
            result.update(func_relations[func_ea]["vftables"][vtbl_offset])
    return result

def get_strings_in_funcs():
    strings = get_refed_strings()
    strings_in_func = {}
    for ea in strings:
        f = ida_funcs.get_func(ea)
        if f:
            if f.start_ea in strings_in_func:
                strings_in_func[f.start_ea][ea] = strings[ea]
            else:
                strings_in_func[f.start_ea] = {ea:strings[ea]}
    return strings_in_func

def is_matched(text, regexes):
    matched = False
    for regex in regexes:
        if regex.match(text):
            matched = True
            break
    if matched:
        return True
    return False

def get_cmts_in_func(func_ea, regexes_rpt=None, regexes=None):
    result = {'cmt':{}, 'rcmt':{}}
    f = ida_funcs.get_func(func_ea)
    flag = False
    if not f:
        rcmt = ida_bytes.get_cmt(func_ea, True)
        cmt = ida_bytes.get_cmt(func_ea, False)
        if cmt and is_matched(cmt, regexes):
            result['cmt'][func_ea] = cmt
            flag = True
        if rcmt and not is_matched(rcmt, regexes_rpt):
            result['rcmt'][func_ea] = rcmt
            flag = True
        if flag:
            return result
    for ea in idautils.FuncItems(func_ea):
        rcmt = ida_bytes.get_cmt(ea, True)
        cmt = ida_bytes.get_cmt(ea, False)
        if cmt and is_matched(cmt, regexes):
            result['cmt'][ea] = cmt
        if rcmt and not is_matched(rcmt, regexes_rpt):
            result['rcmt'][ea] = rcmt
    return result

def get_family_members(ea, bbs, import_eas=None, string_eas=None):
    if import_eas is None:
        import_eas = []
    if string_eas is None:
        string_eas = {}
    
    func = ida_funcs.get_func(ea)
    target_ea = ea
    if func is not None:
        target_ea = func.start_ea
    parents = get_xrefs(target_ea)
    children, apicalls, gvars, strings, stroff, vtbl = get_children(bbs, import_eas, string_eas)
    return parents, children, apicalls, gvars, strings, stroff, vtbl

def get_func_relation(f, import_eas=None, string_eas=None):
    if import_eas is None:
        import_eas = []
    if string_eas is None:
        string_eas = {}
    fc = ida_gdl.FlowChart(f)
    bbs = get_bbs(fc)
    parents, children, apicalls, gvars, strings, stroff, vtbl = get_family_members(f.start_ea, bbs, import_eas, string_eas)
    func_type = get_func_type(f.start_ea, import_eas)
    yield f.start_ea, parents, children, func_type, gvars, strings, stroff, vtbl
    for ea in apicalls:
        if ea == ida_idaapi.BADADDR:
            continue
        func_type = apicalls[ea]
        parents = get_xrefs(ea)
        yield ea, parents, {}, func_type, {}, {}, {}, {}
    for ea in vtbl:
        if ea == ida_idaapi.BADADDR:
            continue
        func_type = FT_VTB
        parents = get_xrefs(ea)
        yield ea, parents, vtbl[ea], func_type, {}, {}, {}, {}

def get_relation_in_all_funcs(import_eas=None, string_eas=None):
    for f in funcs():
        for ea, parents, children, func_type, gvars, strings, stroff, vtbl in get_func_relation(f, import_eas, string_eas):
            yield ea, parents, children, func_type, gvars, strings, stroff, vtbl

def get_func_relations():
    result = {}
    imports = get_imports()
    #import_eas = set([x[1] for x in imports])
    import_eas = dict.fromkeys([x[1] for x in imports])
    string_eas = get_refed_strings()
    for func_ea, parents, children, func_type, gvars, strings, stroff, vtbl in get_relation_in_all_funcs(import_eas, string_eas):
        result[func_ea] = {"parents":parents, "children":children, "func_type":func_type, "gvars":gvars, "strings":strings, "struct_offsets": stroff, "vftables": vtbl}
    return result, import_eas, string_eas

# note that ea always needs to be function address.
def trace_func_calls(func_relations, ea, func_ea=ida_idaapi.BADADDR, target_ea=ida_idaapi.BADADDR, direction="parents", result=None, force_trace=False, max_recursive=g_max_recursive, nrecursive=0, skip_lib=False, skip_api=False, filtered_nodes=None, finished=None, finished_in_path=None, finished_nodes_in_path=None, debug=False, dbg_print_func=None):
    # initialize default values
    if result is None:
        result = []
    if filtered_nodes is None:
        filtered_nodes = ()
    if finished is None:
        finished = set([])
    if finished_in_path is None:
        finished_in_path = set([])
    if finished_nodes_in_path == None:
        finished_nodes_in_path = set([])
    dbg_print = dbg_print_func
    if dbg_print_func == None:
        dbg_print = l_dbg_print
    
    if debug: dbg_print("############################# head of trace func: %d" % nrecursive)
    # for the very first entry point, ea may not function address.
    # in that case, change ea to function address.
    if func_ea == ida_idaapi.BADADDR:
        func = ida_funcs.get_func(ea)
        if ea in func_relations:
            func_ea = ea
        elif func is not None:
            func_ea = func.start_ea
        
    if debug: dbg_print("################# func_ea: %x, ea: %x" % (func_ea, ea))
    
    if max_recursive > 0 and nrecursive >= max_recursive and target_ea == ida_idaapi.BADADDR and force_trace == False:
        if debug: dbg_print("recursive limit!!! %d" % nrecursive)
        if len(func_relations[func_ea][direction]) > 0:
            result.append((ida_idaapi.BADADDR, ida_idaapi.BADADDR, FT_UNK))
            yield result
            result.pop(-1)
        else:
            yield result
    else:
        if func_ea != ida_idaapi.BADADDR and (func_ea == target_ea or ea == target_ea):
            if debug: dbg_print("got the target!! func_ea: %x, ea: %x" % (func_ea, ea))
            # if we need to trace beyond the node, we should clear end_ea for additonal tracing points.
            #if func_ea in func_relations and len(func_relations[func_ea][direction]) > 0:
            #    result.append((ida_idaapi.BADADDR, ida_idaapi.BADADDR, FT_UNK))
            yield result
            #if func_ea in func_relations and len(func_relations[func_ea][direction]) > 0:
            #    result.pop(-1)
            finished_in_path.add(tuple(result))
            finished_nodes_in_path.update(set([x[0] for x in result]))
            if debug: dbg_print([(hex(x[0]), hex(x[1])) for x in result])
        # ea reached a limitation
        elif func_ea == ida_idaapi.BADADDR:
            if debug: dbg_print("ea reached a limitation")
            if target_ea == ida_idaapi.BADADDR:
                yield result
        # ea is a leaf node
        elif func_ea in func_relations and len(func_relations[func_ea][direction]) == 0:
            if debug: dbg_print("ea is a leaf node")
            if target_ea == ida_idaapi.BADADDR:
                yield result
        # ea is a leaf node
        elif func_ea not in func_relations:
            if debug: dbg_print("ea is a leaf node")
            if target_ea == ida_idaapi.BADADDR:
                yield result
        # ea is in the middle of the function tree
        else:
            if debug: dbg_print("ea is in the middle of the function tree")
            # next_ea means caller, next_func_ea means callee of its caller
            # we need to trace calee function. not caller (next_ea). do not confuse!!!
            if debug: dbg_print("$$$$$$$$$$$$$$$$$ find %s in %x" % (direction, func_ea))
            for next_ea in func_relations[func_ea][direction]:
                if debug: dbg_print("next_ea: %x" % next_ea)
                next_func_ea, next_func_type, op, next_func_name = func_relations[func_ea][direction][next_ea]
                #next_func = ida_funcs.get_func(next_func_ea)
                # next_ea is a part of path
                if next_ea in finished_nodes_in_path:
                    if debug: dbg_print("next_ea (%x) is a part of a path that is already finished." % (next_ea))
                    tmp_set = set([])
                    for p in finished_in_path:
                        if debug: dbg_print("next_ea: %x" % next_ea, "p:", [(hex(x[0]), hex(x[1])) for x in p])
                        if next_ea in [x[0] for x in p]:
                            if debug: dbg_print("next_ea: %x" % next_ea, "is in a result path")
                            next_ea_idx = [x[0] for x in p].index(next_ea)
                            new_result = result.copy()
                            new_result.extend(p[next_ea_idx:])
                            yield new_result
                            tmp_set.add(tuple(new_result))
                            if debug: dbg_print([(hex(x[0]), hex(x[1])) for x in new_result])
                        else:
                            if target_ea == ida_idaapi.BADADDR:
                                if next_func_ea in func_relations and len(func_relations[next_func_ea][direction]) > 0:
                                    result.append((next_ea, next_func_ea, next_func_type))
                                    result.append((ida_idaapi.BADADDR, ida_idaapi.BADADDR, FT_UNK))
                                    yield result
                                    result.pop(-1)
                                    result.pop(-1)
                                else:
                                    result.append((next_ea, next_func_ea, next_func_type))
                                    yield result
                                    result.pop(-1)
                    for p in tmp_set:
                        finished_in_path.add(p)
                        finished_nodes_in_path.update(set([x[0] for x in p]))
                # next_ea is already finished.
                elif next_ea in finished:
                    if debug: dbg_print("next_ea (%x) or next_func_ea (%x) is already traced." % (next_ea, next_func_ea))
                    if target_ea == ida_idaapi.BADADDR:
                        if next_func_ea in func_relations and len(func_relations[next_func_ea][direction]) > 0:
                            result.append((next_ea, next_func_ea, next_func_type))
                            result.append((ida_idaapi.BADADDR, ida_idaapi.BADADDR, FT_UNK))
                            yield result
                            result.pop(-1)
                            result.pop(-1)
                        else:
                            result.append((next_ea, next_func_ea, next_func_type))
                            yield result
                            result.pop(-1)
                # next ea in a function.
                #elif next_func is not None:
                elif next_func_ea in func_relations:
                    # matched with filtered_nodes
                    if target_ea == ida_idaapi.BADADDR and (next_ea in filtered_nodes or next_func_ea in filtered_nodes):
                        if debug: dbg_print("hit a filtered node")
                        result.append((next_ea, next_func_ea, next_func_type))
                        if next_func_ea in func_relations and len(func_relations[next_func_ea][direction]) > 0:
                            result.append((ida_idaapi.BADADDR, ida_idaapi.BADADDR, FT_UNK))
                        yield result
                        if next_func_ea in func_relations and len(func_relations[next_func_ea][direction]) > 0:
                            result.pop(-1)
                        result.pop(-1)
                    # found an API or a static-linked library
                    elif target_ea == ida_idaapi.BADADDR and target_ea != next_func_ea and target_ea != next_ea and ((skip_api and next_func_type in [FT_API]) or (skip_lib and next_func_type in [FT_LIB])):
                        if debug: dbg_print("hit an API or a lib function")
                        result.append((next_ea, next_func_ea, next_func_type))
                        if next_func_ea in func_relations and len(func_relations[next_func_ea][direction]) > 0:
                            result.append((ida_idaapi.BADADDR, ida_idaapi.BADADDR, FT_UNK))
                        yield result
                        if next_func_ea in func_relations and len(func_relations[next_func_ea][direction]) > 0:
                            result.pop(-1)
                        result.pop(-1)
                    # found a unresolved call
                    elif next_func_ea == ida_idaapi.BADADDR:
                        if debug: dbg_print("found a unresolved callee")
                        result.append((next_ea, next_func_ea, next_func_type))
                        yield result
                        result.pop(-1)
                    ####################################
                    #
                    # recursive tracing a upper or a lower function
                    #
                    # found a new callee and caller, process next callee and caller
                    elif (next_ea, next_func_ea, next_func_type) not in result:
                        result.append((next_ea, next_func_ea, next_func_type))
                        if debug: dbg_print("entering a recursive call", nrecursive)
                        # we need callee (nexgt_func_ea) as the second argument. do not change it to next_ea that is a caller.
                        for r in trace_func_calls(func_relations, next_ea, next_func_ea, target_ea, direction, result, force_trace, max_recursive, nrecursive+1, skip_lib, skip_api, filtered_nodes, finished, finished_in_path, finished_nodes_in_path, debug, dbg_print_func):
                            yield r
                        result.pop(-1)
                        if debug: dbg_print("leaving a recursive call", nrecursive)
                    # found a recursive call
                    else:
                        if debug: dbg_print("detecting a recursive call")
                        # detecting a recursive call
                        if target_ea == ida_idaapi.BADADDR:
                            result.append((next_ea, next_func_ea, next_func_type))
                            yield result
                            result.pop(-1)
                # child_ea is not in a function
                elif target_ea == ida_idaapi.BADADDR:
                    if debug: dbg_print("child_ea is not in a function")
                    result.append((next_ea, next_func_ea, next_func_type))
                    yield result
                    result.pop(-1)
                
                # next_ea is needed for finished ea. we do not need callee (nexgt_func_ea) here.
                finished.add(next_ea)
                if debug: dbg_print("next_ea %x has been finished" % next_ea)

            # if a loop of func_relations[func_ea][direction] is finished, it means func_ea is finished.
            if func_ea != ida_idaapi.BADADDR:
                finished_flag = True
                for direction in ["parents", "children"]:
                    for next_ea in func_relations[func_ea][direction]:
                        if next_ea not in finished:
                            finished_flag = False
                            break
                if finished_flag:
                    finished.add(func_ea)
                    if debug: dbg_print("func_ea %x has been finished" % func_ea)
        
    finished.add(ea)
    if debug: dbg_print("ea %x has been finished" % ea)
    if debug: dbg_print("tail of trace func: %d" % nrecursive)
        

def main():
    imports = get_imports()
    import_eas = dict.fromkeys([x[1] for x in imports])
    string_eas = get_refed_strings()
    ea = here()
    f, bbs = get_func_bbs(ea)
    if f:
        ea = f.start_ea
    parents, children, apicalls, gvars, strings, stroff, vtbl = get_family_members(ea, bbs, import_eas, string_eas)
    print("Parents  :", [(hex(x).rstrip("L"), hex(parents[x][0]).rstrip("L")) for x in parents])
    print("Children :", [(hex(x).rstrip("L"), hex(children[x][0]).rstrip("L"), children[x][1], children[x][2], children[x][3]) for x in children])
    print("APIs     :", [(hex(x).rstrip("L"), apicalls[x]) for x in apicalls])
    print("Variables:", [(hex(x).rstrip("L"), hex(gvars[x][0])) for x in gvars])
    print("Strings  :", [(hex(x).rstrip("L"), hex(strings[x][0]), strings[x][3]) for x in strings])
    print("Struct Offsets:", [(hex(x).rstrip("L"), hex(stroff[x][0]), stroff[x][3]) for x in stroff])
    for x in vtbl:
        print("Vftable: %x" % x)
        print("  ", [(hex(y).rstrip("L"), hex(vtbl[x][y][0]), vtbl[x][y][3]) for y in vtbl[x]])
    #print(vtbl)
    func_type = get_func_type(ea, import_eas)
    print("Func Type:", func_type)

    if g_debug:
        global g_func_relations
        if "dbg_print" not in globals():
            dbg_print = l_dbg_print
        if 'g_func_relations' not in globals():
            g_func_relations, _, _ = get_func_relations()
        
        for r in trace_func_calls(g_func_relations, here(), target_ea=ida_idaapi.BADADDR, direction="parents", max_recursive=-1, skip_lib=True, skip_api=True, debug=True):
            dbg_print("$$$$$$$$$$$$$$$$ found a path:", [(hex(y).rstrip("L"), hex(x).rstrip("L"), z) for x,y,z in reversed(r)], "to ", hex(ea))

        for r in trace_func_calls(g_func_relations, here(), target_ea=ida_idaapi.BADADDR, direction="children", max_recursive=-1, skip_lib=True, skip_api=True, debug=True):
            dbg_print("$$$$$$$$$$$$$$$$ found a path:", [(hex(x).rstrip("L"), hex(y).rstrip("L"), z) for x,y,z in reversed(r)], "to ", hex(ea))
            
if __name__ == '__main__':
    main()
