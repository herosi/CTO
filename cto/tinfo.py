import ida_typeinf
import ida_nalt
import ida_idaapi
import ida_name

import re

def get_tinfo(ea):
    tif = ida_typeinf.tinfo_t()
    result = ida_nalt.get_tinfo(tif, ea)
    return tif if result else None

def get_tinfo_by_name(name):
    tinfo = None
    result = ida_typeinf.get_named_type(ida_typeinf.get_idati(), name, 0)

    if result:
        tinfo = ida_typeinf.tinfo_t()
        ret = tinfo.deserialize(ida_typeinf.get_idati(), result[1], result[2])
        if not ret:
            return None
    return tinfo

def get_local_tinfo_by_name(name, func_flag=True):
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, name)
    if ea == ida_idaapi.BADADDR:
        return None
    tinfo = ida_typeinf.tinfo_t()
    ret = ida_nalt.get_tinfo(tinfo, ea)
    if not ret:
        tinfo = None
    if ret and func_flag:
        if not (tinfo.is_func() or tinfo.is_funcptr()):
            tinfo = None
    return tinfo

def apply_tinfo_to_ea(tinfo, ea, opn=0):
    if not tinfo:
        return False
    if not tinfo.is_funcptr():
        tinfo.create_ptr(tinfo)
    # why do we apply both apply_callee_tinfo & set_op_tinfo?
    # it is because set_op_tinfo() causes change in hexrays decompilation
    # apply_callee_tinfo() updates ida's stack analysis
    ida_typeinf.apply_callee_tinfo(ea, tinfo)
    # apply_callee_tinfo doesn't have return value, so we have to return the result of set_op_tinfo2.
    ret = ida_nalt.set_op_tinfo(ea, opn, tinfo)
    return ret

def get_op_tif(ea, opn=0):
    tif = ida_typeinf.tinfo_t()
    result = ida_nalt.get_op_tinfo(tif, ea, opn)
    return tif  if result else None

def comp_tifs(name, ea, opn=0):
    tif = get_op_tif(ea, opn)
    tif2 = get_tinfo_by_name(name)
    
    if _comp_tifs(tif, tif2):
        return True
    return False

def _comp_tifs(tif, tif2):
    tif2 = get_op_tif(ea, opn)
    
    if not tif2.is_funcptr():
        tif2.create_ptr(tif2)
    
    if not tif.is_funcptr():
        tif.create_ptr(tif)
    
    if tif == tif2:
        return True
    return False

def del_tinfo_from_ea(ea, opn=0):
    ida_nalt.del_op_tinfo(ea, opn)
    # remove comments and reset var names for the result of appy_callee_tinfo()?
    #for ea in ida_typeinf.get_arg_addrs(caller):
    #    print(hex(ea))


g_api_name_postfix_regex = re.compile(r'(.*)_[0-9]+$')
def get_true_name(name):
    r = g_api_name_postfix_regex.search(name)
    if r:
        grps = r.groups()
        if len(grps) > 0:
            return grps[0]
    return name

def guess_true_names(name):
    names = [name]
    removed_postfix = get_true_name(name)
    result = [name]
    if name != removed_postfix:
        names.append(removed_postfix)
        result.append(removed_postfix)
    for n in names:
        for prefix in ["_", "__", "Rtl"]:
            result.append(prefix+n)
    return result

def get_func_detail(tif):
    fi = ida_typeinf.func_type_data_t()
    tif.get_func_details(fi)
    return fi

def get_func_args(fi):
    if not fi.empty():
        #print fi
        for i in fi:
            yield i

def is_thiscall(cc):
    if cc & ida_typeinf.CM_CC_MASK == ida_typeinf.CM_CC_THISCALL:
        return True
    return False

def is_fastcall(cc):
    if cc & ida_typeinf.CM_CC_MASK == ida_typeinf.CM_CC_FASTCALL:
        return True
    return False
