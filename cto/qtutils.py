import ida_kernwin

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

def can_use_qt():
    try:
        import sip
        from PyQt5 import QtCore
        from PyQt5 import QtWidgets
        from PyQt5 import QtGui
    except ModuleNotFoundError:
        return False
    return True
    

def get_qver():
    from PyQt5 import QtCore
    v = QtCore.qVersion()
    maj, mnr, _ =[int(x) for x in v.split(".")]
    return maj, mnr

def get_widget(w, widget_types=None, title=None, max_try=100):
    
    import sip
    from PyQt5 import QtWidgets
    
    if widget_types is None:
        widget_types = set([QtWidgets.QWidget,QtWidgets.QSplitter])
        
    widget = sip.wrapinstance(int(w), QtWidgets.QWidget)
    i = 0
    while i < max_try and widget and type(widget) != QtWidgets.QMainWindow:
        if type(widget) in widget_types:
            #print(widget.windowTitle(), type(widget))
            if title is not None:
                if title == widget.windowTitle():
                    find_flag = True
                    break
            else:
                find_flag = True
                break
        widget = widget.parent()
        i += 1
    return widget

def get_qmain_window(w, max_try = 100):
    if not can_use_qt():
        return None
    import sip
    from PyQt5 import QtWidgets
    if w is None:
        return None
    widget = sip.wrapinstance(int(w), QtWidgets.QWidget)
    find_flag = False
    i = 0
    while i < max_try and widget:
        if  type(widget) == QtWidgets.QMainWindow:
            return widget
        widget = widget.parent()
        i += 1
    return None

def find_toolbar(widget, toolbar_name):
    if not can_use_qt():
        return None
    from PyQt5 import QtWidgets
    for cwidget in widget.children():
        if type(cwidget) == QtWidgets.QToolBar:
            #print(cwidget.objectName())
            #print(cwidget.accessibleName())
            if cwidget.objectName() == toolbar_name:
                return cwidget
    return None

def set_toobar_visible(w, toolbar_name):
    if not can_use_qt():
        return False
    from PyQt5 import QtCore
    widget = get_qmain_window(w)
    if widget:
        tb_widget = find_toolbar(widget, toolbar_name)
        if tb_widget and not tb_widget.isVisible():
            tb_widget.setEnabled(True)
            tb_widget.setVisible(True)
            return True
        widget.addToolBar(QtCore.Qt.TopToolBarArea, tb_widget)
    return False

class enable_toolbar_t(ida_kernwin.UI_Hooks):
    def __init__(self, toolbar_name):
        self.toolbar_name = toolbar_name
        ida_kernwin.UI_Hooks.__init__(self)
        self.hook()
        
    def ready_to_run(self):
        self.enable_toolbar()
        
    def enable_toolbar(self):
        widget = ida_kernwin.open_navband_window(ida_kernwin.get_screen_ea(),1)
        set_toobar_visible(widget, self.toolbar_name)
        
    def __del__(self):
        self.unhook()


class dark_mode_checker_t(object):
    
    @staticmethod
    def is_dark_mode():
        return dark_mode_checker_t.is_dark_mode_with_main()
    
    @staticmethod
    def get_main_window():
        try:
            from PyQt5 import QtWidgets
        except ModuleNotFoundError:
            return None
        
        widget = QtWidgets.QApplication.activeWindow()
        QtWidgets.QApplication.focusWidget()
        for widget in [QtWidgets.QApplication.activeWindow(), QtWidgets.QApplication.focusWidget()] + QtWidgets.QApplication.topLevelWidgets():
            while widget:
                if isinstance(widget, QtWidgets.QMainWindow):
                    break
                widget = widget.parent()
            if isinstance(widget, QtWidgets.QMainWindow):
                return widget
        return None
    
    @staticmethod
    def _is_dark_mode(bgcolor, threshold=128):
        if bgcolor >= 0:
            alpha = bgcolor >> 24
            bgcolor &= 0xffffff
            green = bgcolor >> 16
            blue = (bgcolor >> 8) & 0xff
            red = bgcolor & 0xff
            #print("%x, %x, %x, %x, %x" % (bgcolor, green, blue, red, alpha))
            if green < threshold and blue < threshold and red < threshold:
                return True
        return False
    
    @staticmethod
    def is_dark_mode_with_main():
        try:
            from PyQt5 import QtWidgets
        except ModuleNotFoundError:
            return False

        widget = dark_mode_checker_t.get_main_window()
        if not isinstance(widget, QtWidgets.QMainWindow):
            return False
        bgcolor = dark_mode_checker_t.get_bgcolor(x=0, y=0, w=widget)
        if bgcolor < 0:
            return False
        return dark_mode_checker_t._is_dark_mode(bgcolor)
        
    @staticmethod
    def get_bgcolor(x=0, y=0, w=None):
        bgcolor = -1
        if w is None:
            return bgcolor
        
        try:
            import sip
            from PyQt5 import QtCore
            from PyQt5 import QtWidgets
            from PyQt5 import QtGui
        except ModuleNotFoundError:
            return bgcolor
        
        if str(w).startswith("<Swig Object of type 'TWidget *' at") and str(type(w)) in ["<class 'SwigPyObject'>", "<type 'SwigPyObject'>"]: # type: for py2, class: for py3
            widget = sip.wrapinstance(int(w), QtWidgets.QWidget)
        else:
            widget = w
            
        pixmap = widget.grab(QtCore.QRect(x, y, x+1, y+1))
        image = QtGui.QImage(pixmap.toImage())
        bgcolor = image.pixel(0, 0)
        
        return bgcolor
        
