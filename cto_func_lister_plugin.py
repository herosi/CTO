import ida_idaapi
import ida_kernwin
import ida_funcs

import os
import sys
import codecs

ida_idaapi.require("cto")
ida_idaapi.require("cto.cto_base")
ida_idaapi.require("cto.cto_func_lister")
ida_idaapi.require("cto.icon")
ida_idaapi.require("cto.syncdata")
ida_idaapi.require("cto.qtutils")


# for IDA 7.4 or earlier
try:
    g_flags = ida_idaapi.PLUGIN_MULTI
except AttributeError:
    g_flags = ida_idaapi.PLUGIN_DRAW

# for IDA 7.4 or earlier
try:
    g_obj = ida_idaapi.plugmod_t
except AttributeError:
    g_obj = object

g_plugmod_flag = False
if g_flags != ida_idaapi.PLUGIN_DRAW and g_obj != object:
    g_plugmod_flag = True


class cto_func_lister_plugin_t(ida_idaapi.plugin_t):
    flags = g_flags
    comment = "CTO Function Lister"
    toolbar_displayed_name = cto.cto_base.cto_base.orig_title
    toolbar_name = toolbar_displayed_name + 'Toolbar'
    wanted_name = comment
    wanted_hotkey = "Alt-Shift-F"
    help = "Press '" + wanted_hotkey + "' to display the " + comment + " widget."
    
    action_name = "cto_func_lister:execute"
    menu_path = "Edit/Plugins/"
    icon = cto.icon.icon_handler(cto.icon.g_icon_data_ascii, True)
    icon_data = icon.icon_data
    icon_data_dark = icon.icon_bg_change(icon_data, True, True)
    if icon_data_dark is None:
        icon_data_dark = icon_data
    act_icon = ida_kernwin.load_custom_icon(data=icon_data, format="png")
    act_icon_dark = ida_kernwin.load_custom_icon(data=icon_data_dark, format="png")
    
    class exec_from_toolbar(ida_kernwin.action_handler_t):
        def __init__(self, plugin):
            ida_kernwin.action_handler_t.__init__(self)
            import weakref
            self.v = weakref.ref(plugin)
        
        def activate(self, ctx):
            self.v().plugin_mod.run(None)
            
        def update(self, ctx):
            return ida_kernwin.AST_ENABLE_ALWAYS
    
    def init(self):
        ida_kernwin.msg("############### %s (%s) ###############%s" % (self.wanted_name, self.comment, os.linesep))
        ida_kernwin.msg("%s%s" % (self.help, os.linesep))

        # attach to menu
        self.g = None
        ida_kernwin.attach_action_to_menu(
            self.menu_path,
            self.action_name,
            ida_kernwin.SETMENU_APP)

        # attach to toolbar
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
            self.action_name,
            self.comment,
            self.exec_from_toolbar(self),
            None,
            self.wanted_name,
            self.act_icon))
        
        # Insert the action in a toolbar
        ida_kernwin.create_toolbar(self.toolbar_name, self.toolbar_displayed_name)
        ida_kernwin.attach_action_to_toolbar(self.toolbar_name, self.action_name)
        
        # install ui hook to enable toolbar later
        self.ph = cto.qtutils.enable_toolbar_t(self.toolbar_name)
        
        # Check if IDA is darkmode or not.
        # It might fail if the mode is darcula or similar themes
        # because the window color is the same as the default theme color.
        # However, it can still distinguish the default and the dark mode.
        if cto.cto_base.cto_base.is_dark_mode_with_main():
            ida_kernwin.update_action_icon(self.action_name, self.act_icon_dark)
            ida_kernwin.update_action_icon(self.menu_path + self.wanted_name, self.act_icon_dark)
            
        r = self.flags
        self.plugin_mod = cfl_plugmod_t()
        if g_plugmod_flag:
            r = self.plugin_mod
        return r

    # for old IDA til 7.6
    def run(self, arg):
        self.plugin_mod.run(arg)
        
    # for old IDA til 7.6
    def term(self):
        self.plugin_mod.term()

    @staticmethod
    class register_icon(ida_kernwin.UI_Hooks):
        def updated_actions(self):
            if ida_kernwin.update_action_icon(cto_func_lister_plugin_t.menu_path + cto_func_lister_plugin_t.wanted_name, cto_func_lister_plugin_t.act_icon_dark):
                # unhook this if it's successful
                self.unhook()


class cfl_plugmod_t(g_obj):
    toolbar_name = cto_func_lister_plugin_t.toolbar_name
    menu_path = cto_func_lister_plugin_t.menu_path
    action_name = cto_func_lister_plugin_t.action_name
    act_icon = cto_func_lister_plugin_t.act_icon
    wanted_name = cto_func_lister_plugin_t.wanted_name
    comment = cto_func_lister_plugin_t.comment
    help = cto_func_lister_plugin_t.help
        
    def __init__(self):
        g_obj.__init__(self)
        self.g = None
            
    def __del__(self):
        self.term()
        
    def run(self, arg):
        self.exec_cto_func_lister()
        
    def term(self):
        if self.g:
            self.g.Close(0)
        if hasattr(self.g, "sd"):
            self.g.sd.close()
            
        ida_kernwin.free_custom_icon(self.act_icon)
        ida_kernwin.detach_action_from_menu(self.menu_path, self.action_name)
        
        ida_kernwin.detach_action_from_toolbar(self.toolbar_name, self.action_name)
        ida_kernwin.delete_toolbar(self.toolbar_name)
        
        ida_kernwin.unregister_action(self.action_name)
        
        if hasattr(sys.modules["__main__"], "g_cto_func_lister"):
            delattr(sys.modules["__main__"], "g_cto_func_lister")
        if "g_cto_func_lister" in globals():
            global g_cto_func_lister
            del g_cto_func_lister
        self.g = None
        
    def exec_cto_func_lister(self):
        global g_cto_func_lister

        # for degub mode handling
        debug = False
        if "g_debug" in globals() and g_debug:
            debug = True
        elif hasattr(sys.modules["__main__"], "g_debug") and sys.modules["__main__"].g_debug:
            debug = True

        # for the first message when this plugin is launched by a user by pressing shortcut key or going to menu.
        if 'g_cto_func_lister' not in globals():
            ida_kernwin.msg("Launching %s (%s) ...%s" % (self.wanted_name, self.comment, os.linesep))
            ida_kernwin.msg("For the first execution, %s will analyze all functions to build the call tree. Please wait for a while.%s" % (self.wanted_name, os.linesep))
        else:
            ida_kernwin.msg("Reloading %s.%s" % (self.wanted_name, os.linesep))
            
        if self.g:
            # save several important data with pickle and closing hooks...
            self.g.Close(0)
        
        # reload the main modules
        ida_idaapi.require("cto.cto_func_lister")

        # get sync data on a global variable
        sd = cto.syncdata.sync_data()
        sync_data = sd.get()
        # execute the main function
        self.g = cto.cto_func_lister.exec_cto_function_lister(cto_data=sync_data, debug=debug)
        self.g.__dict__["sd"] = sd
        if sync_data is None:
            self.g.sd.set(self.g.cto_data)
            
        # install ui hook to enable toolbar later
        self.ph = cto.qtutils.enable_toolbar_t(self.toolbar_name)
        
        # show the messages after launching
        if 'g_cto_func_lister' not in globals():
            ida_kernwin.msg("Launched %s.%s" % (self.wanted_name, os.linesep))
        else:
            ida_kernwin.msg("Reloaded %s.%s" % (self.wanted_name, os.linesep))
            
        # put the instance in the global variables
        g_cto_func_lister = self.g
        if not hasattr(sys.modules["__main__"], "g_cto_func_lister"):
            setattr(sys.modules["__main__"], "g_cto_func_lister", self.g)
        else:
            sys.modules["__main__"].g_cto_func_lister = self.g


def PLUGIN_ENTRY():
    return cto_func_lister_plugin_t()

"""
def main():
    global g_cto_func_lister
    g_cto_func_lister = cto_func_lister.exec_cto_function_lister()

if __name__ == '__main__':
    main()
"""

ri = cto_func_lister_plugin_t.register_icon()
ri.hook()
