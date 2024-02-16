from typing import Any, Self, Union, Callable, List, Dict
from .fridalib import *

def repr_js(obj):
    if isinstance(obj, list):
        return '[' + ', '.join(repr_js(e) for e in obj) + ']'
    elif isinstance(obj, dict):
        return '{' + ', '.join(f'{repr_js(k)}: {repr_js(v)}' for k, v in obj.items()) + '}'
    elif isinstance(obj, str) or isinstance(obj, JSObject) or isinstance(obj, float):
        return repr(obj)
    # bool是int的子类, 所以要遵循判断顺序
    elif isinstance(obj, bool):
        return 'true' if obj == True else 'false'
    elif isinstance(obj, int):
        return repr(obj)
    else:
        raise ValueError("Unsupported type")

class JSRuntimeError(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class JSContext:
    def __init__(self, script, vm: int = 0) -> None:
        self.script = script
        self.get_script = script
        self.vm = vm
        self.val = None
        self.err = None

        self.Script = JSObject(self, "Script")
        self.Script: Script
        self.Frida = JSObject(self, "Frida")
        self.Frida: Frida
        self.Process = JSObject(self, "Process")
        self.Process: Process
        self.Memory = JSObject(self, "Memory")
        self.Memory: Memory
        self.MemoryAccessMonitor = JSObject(self, "MemoryAccessMonitor")
        self.MemoryAccessMonitor: MemoryAccessMonitor
        self.Thread = JSObject(self, "Thread")
        self.Thread: Thread
        self.Interceptor = JSObject(self, "Interceptor")
        self.Interceptor: Interceptor
        self.Stalker = JSObject(self, "Stalker")
        self.Stalker: Stalker
        self.Kernel = JSObject(self, "Kernel")
        self.Kernel: Kernel
        self.Cloak = JSObject(self, "Cloak")
        self.Cloak: Cloak
        self.ObjC = JSObject(self, "ObjC")
        self.ObjC: ObjC
        self.Java = JSObject(self, "Java")
        self.Java: Java
        self.Instruction = JSObject(self, "Instruction")
        self.Instruction: Instruction
        self.Module = JSObject(self, "Module")
        self.Module: Module
        self.ModuleMap = JSObject(self, "ModuleMap")
        self.ModuleMap: ModuleMap
        self.NativeCallback = JSObject(self, "NativeCallback")
        self.NativeCallback: NativeCallback
        self.DebugSymbol = JSObject(self, "DebugSymbol")
        self.DebugSymbol: DebugSymbol
        self.Instruction = JSObject(self, "Instruction")
        self.Instruction: Instruction
        self.X86Writer = JSObject(self, "X86Writer")
        self.X86Writer: X86Writer
        self.X86Relocator = JSObject(self, "X86Relocator")
        self.X86Relocator: X86Relocator
        self.ArmWriter = JSObject(self, "ArmWriter")
        self.ArmWriter: ArmWriter
        self.ArmRelocator = JSObject(self, "ArmRelocator")
        self.ArmRelocator: ArmRelocator
        self.ThumbWriter = JSObject(self, "ThumbWriter")
        self.ThumbWriter: ThumbWriter
        self.ThumbRelocator = JSObject(self, "ThumbRelocator")
        self.ThumbRelocator: ThumbRelocator
        self.Arm64Writer = JSObject(self, "Arm64Writer")
        self.Arm64Writer: Arm64Writer
        self.Arm64Relocator = JSObject(self, "Arm64Relocator")
        self.Arm64Relocator: Arm64Relocator
        self.MipsWriter = JSObject(self, "MipsWriter")
        self.MipsWriter: MipsWriter
        self.MipsRelocator = JSObject(self, "MipsRelocator")
        self.MipsRelocator: MipsRelocator

        self.this = JSObject(self, 0)

        # ======= 函数 =======
        self.hexdump = JSObject(self, "hexdump")
        self.hexdump: JSObject
        self.int64 = JSObject(self, "int64")
        self.int64: JSObject
        self.uint64 = JSObject(self, "uint64")
        self.uint64: JSObject
        self.ptr = JSObject(self, "ptr")
        self.ptr: JSObject
        self.setTimeout = JSObject(self, "setTimeout")
        self.setTimeout: JSObject
        self.clearTimeout = JSObject(self, "clearTimeout")
        self.clearTimeout: JSObject
        self.setInterval = JSObject(self, "setInterval")
        self.setInterval: JSObject
        self.clearInterval = JSObject(self, "clearInterval")
        self.clearInterval: JSObject
        self.setImmediate = JSObject(self, "setImmediate")
        self.setImmediate: JSObject
        self.clearImmediate = JSObject(self, "clearImmediate")
        self.clearImmediate: JSObject


        self._js_last_attr = None

    @staticmethod
    def pyobj2js(val: Union[str, int, float, List, Dict]):
        return repr_js(val)

    def _pushObj(self, obj):
        js = "(" + repr_js(obj) + ")"
        return self._evalJsInStack(js)

    def _eval(self, js: str):
        from .pyfrida import FridaScript
        self.script: FridaScript
        api = self.script._js_script.exports_sync
        return api.eval(js)

    def _evalJs(self, js: str):
        self.script._js_script.post({"type": "vm", "opcode": 1, "args": [js]})
        with self.script._js_vm_cond:
            self.script._js_vm_cond.wait()
        val = self.val
        err = self.err
        if err is None:
            return val
        else:
            raise JSRuntimeError(self.err)

    def _evalJsInStack(self, js: str):
        self.script._js_script.post({"type": "vm", "opcode": 0, "args": [js]})
        with self.script._js_vm_cond:
            self.script._js_vm_cond.wait()
        val = self.val
        err = self.err
        if err is None:
            obj = JSObject(self, val)
            return obj
        else:
            raise JSRuntimeError(self.err)
    
    def _exitVM(self, val: int):
        self.script._js_script.post({"type": "vm", "opcode": 2, "args": [val]})

class JSObject:
    def __init__(self, ctx: JSContext, val: Union[str, int]) -> None:
        self.js_ctx = ctx
        self.js_last_attr = None
        if isinstance(val, str) or isinstance(val, int):
            self.js_val = val
        else:
            raise ValueError("val must be str or int") 

    def get_val(self):
        return self.js_ctx._evalJs(repr_js(self))
    
    def get_str(self):
        return self.js_ctx._evalJs("JSON.stringify(%s)" % (repr_js(self), ))

    def js_new(self, *args) -> Self:
        argstr = ", ".join([repr_js(arg) for arg in args])
        js = "new %s(%s)" % (repr_js(self), argstr)
        return self.js_ctx._evalJsInStack(js)

    def js_bind(self, name: str) -> Self:
        js = r"%s.%s.bind(%s)" % (repr_js(self), name, repr_js(self))
        return self.js_ctx._evalJsInStack(js)

    def js_attr(self, name: str) -> Self:
#         js = r'''
# (() => {
# try {
#     if (%s.constructor.prototype.hasOwnProperty("%s")) {
#         // 如果是获取了类实例方法
#         return %s.%s.bind(%s)
#     }
#     else {
#         return %s.%s
#     }
# }
# catch(e) {
#     return %s.%s
# }
# })()
# ''' % (repr_js(self), name, repr_js(self), name, repr_js(self), repr_js(self), name, repr_js(self), name)
        
        js2 = r"%s.%s" % (repr_js(self), name)
        obj = self.js_ctx._evalJsInStack(js2)
        self.js_ctx._js_last_attr = {"name": name, "this": self, "func": obj}
        return obj

    def js_attr_set(self, name, value):
        js = "%s.%s = %s" % (repr_js(self), name, repr_js(value))
        return self.js_ctx._evalJs(js)

    def js_index(self, index: Union[str, int]) -> Self:
        js = "%s[%s]" % (repr_js(self), repr_js(index))
        return self.js_ctx._evalJsInStack(js)

    def js_add(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s + %s" % (repr_js(self), repr_js(val))
        return self.js_ctx._evalJsInStack(js)
    
    def js_iadd(self, val: Union[Self, int, float, str]) -> Self:
        js = "%s += %s" % (repr_js(self), repr_js(val))
        self.js_ctx._evalJs(js)
        return self

    def js_sub(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s - %s" % (repr_js(self), repr_js(val))
        return self.js_ctx._evalJsInStack(js)

    def js_isub(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s -= %s" % (repr_js(self), repr_js(val))
        self.js_ctx._evalJs(js)
        return self

    def js_div(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s / %s" % (repr_js(self), repr_js(val))
        return self.js_ctx._evalJsInStack(js)

    def js_idiv(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s /= %s" % (repr_js(self), repr_js(val))
        self.js_ctx._evalJs(js)
        return self

    def js_mul(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s * %s" % (repr_js(self), repr_js(val))
        return self.js_ctx._evalJsInStack(js)

    def js_imul(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s *= %s" % (repr_js(self), repr_js(val))
        self.js_ctx._evalJs(js)
        return self

    def js_mod(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s %% %s" % (repr_js(self), repr_js(val))
        return self.js_ctx._evalJsInStack(js)

    def js_imod(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s %%= %s" % (repr_js(self), repr_js(val))
        self.js_ctx._evalJs(js)
        return self

    def js_and(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s & %s" % (repr_js(self), repr_js(val))
        return self.js_ctx._evalJsInStack(js)

    def js_iand(self, val: Union[Self, int, str, float]) -> Self:
        js = "%s &= %s" % (repr_js(self), repr_js(val))
        self.js_ctx._evalJs(js)
        return self
    
    def js_neg(self) -> Self:
        js = "-%s" % (repr_js(self), )
        return self.js_ctx._evalJsInStack(js)

    def js_pos(self) -> Self:
        js = "+%s" % (repr_js(self), )
        return self.js_ctx._evalJsInStack(js)

    def js_invert(self) -> Self:
        js = "~%s" % (repr_js(self), )
        return self.js_ctx._evalJsInStack(js)
    
    def __repr__(self) -> str:
        if isinstance(self.js_val, int):
            return "(vms[%d].stack[%d])" % (self.js_ctx.vm, self.js_val)
        elif isinstance(self.js_val, str):
            return "(%s)" % (self.js_val, )
        else:
            raise ValueError("val must be str or int")

    def __call__(self, *args: Any) -> Any:
        if self.js_ctx._js_last_attr is not None and self.js_ctx._js_last_attr["func"].js_val == self.js_val:
            argstr = ", ".join([repr_js(arg) for arg in args])
            js = "%s.call(%s, %s)" % (repr_js(self), repr_js(self.js_ctx._js_last_attr["this"]), argstr)
            return self.js_ctx._evalJsInStack(js)
        else:
            argstr = ", ".join([repr_js(arg) for arg in args])
            js = "%s(%s)" % (repr_js(self), argstr)
            return self.js_ctx._evalJsInStack(js)

    def __getitem__(self, key):
        return self.js_index(key)

    def __setitem__(self, key, value):
        js = "%s[%s] = %s" % (repr_js(self), repr_js(key), repr_js(value))
        self.js_ctx._evalJs(js)

    def __getattr__(self, key: str):
        if key.startswith("__") and key.endswith("__"):
            raise AttributeError()
        else:
            return self.js_attr(key)

    def __setattr__(self, key, value):
        if key in ["js_val", "js_ctx", "js_last_attr"]:
            self.__dict__[key] = value
        else:
            self.js_attr_set(key, value)
    
    def __add__(self, p):
        return self.js_add(p)
    
    def __sub__(self, p):
        return self.js_sub(p)
    
    def __mul__(self, p):
        return self.js_mul(p)
    
    def __truediv__(self, p):
        return self.js_div(p)

class NativePointer(JSObject):
    def __init__(self) -> None:
        super().__init__(val_name="NativePointer")