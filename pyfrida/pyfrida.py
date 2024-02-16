from .jsvm import JSObject, JSContext, repr_js
from inspect import signature
import threading
from threading import Condition
import frida
from typing import Callable, Union, Any

class FridaScript:
    def __init__(self) -> None:
        self._js_funcs = {}
        self._js_func_count = 0
        self._js_global_ctx = JSContext(self, 0)
        self._js_ctx_map = {}
        self._js_vm_cond = Condition()

    def create_js_ctx(self, vmi: int):
        ctx = JSContext(self, vmi)
        self._js_ctx_map[vmi] = ctx
        return ctx
    
    def remove_js_ctx(self, vmi: int):
        del self._js_ctx_map[vmi]
    
    def get_js_ctx(self, vmi: int) -> JSContext:
        return self._js_ctx_map.get(vmi, None)

    def gen_script(self) -> str:
        head = r'''
rpc.exports = {
    "eval": function (js) {
        return eval(js)
    }
}

var vms = []
addVM()
function addVM() {
    return vms.push({stack: []}) - 1
}

function exitVM(vmi, stacki) {
    if (stacki < 0) {
        return undefined
    }
    const val = vms[vmi].stack[stacki]
    vms[vmi] = null
    return val
}

function evalJsInStack(jscode, vmi) {
    return vms[vmi].stack.push(eval(jscode)) - 1
}

function evalJs(jscode) {
    return eval(jscode)
}

function VMEntry(vmi) {
    var stack = vms[vmi].stack
    var opcode, args
    var flag = true
    var return_val = 0
    while (flag) {
        const op = recv("vm", function (msg) {
            opcode = msg["opcode"]
            args = msg["args"]
        })
        op.wait()
        if (opcode == 0) {
            // evalJsInStack
            try {
                send({"type": "vm", "val": evalJsInStack(args[0], vmi), "vmi": vmi})
            }
            catch(e) {
                send({"type": "vm", "err": String(e), "vmi": vmi})
            }
        }
        else if (opcode == 1) {
            // evalJs
            try {
                send({"type": "vm", "val": evalJs(args[0]), "vmi": vmi})
            }
            catch(e) {
                send({"type": "vm", "err": String(e), "vmi": vmi})
            }
        }
        else if (opcode == 2) {
            // exitVM
            flag = false
            return_val = exitVM(vmi, args[0])
        }
    }
    return return_val
}
'''
        
        body = ""

        func_template = """
function Bridge%d(%s) {
    const vmi = addVM()
    var stack = vms[vmi].stack
try {
    stack.push(Java.retain(this))
}
catch {
    stack.push(this)
}
%s
    
    send({"type": "bridge", "func": %d, "vm": vmi})
    return VMEntry(vmi)
}
"""
        for func_id, func in self._js_funcs.items():
            func_args = ", ".join(["a%d" % (i, ) for i in range(func["arg_num"])])
            push_template = r"""
    try {
        stack.push(Java.retain(a%d))
    }
    catch {
        stack.push(a%d)
    }
"""
            push_func_args = "\n".join([push_template % (i, i) for i in range(func["arg_num"])])
            func_body = func_template % (func_id, func_args, push_func_args, func_id)
            body += func_body
        

        src = "%s\n%s" % (head, body)

        return src

    def attach(self, device: frida.core.Device, target: Union[str, int]):
        def _internal_msg_handler(msg, data):
            def _inner_call(payload):
                vm = payload["vm"]
                func_info = self._js_funcs[payload["func"]]
                py_func = func_info["callback"]
                ctx = self.create_js_ctx(vm)
                args = []
                for i in range(func_info["arg_num"]):
                    args.append(JSObject(ctx, i + 1))
                
                result = py_func(ctx, *args)
                # breakpoint()
                if result is None:
                    val_index = -1
                elif isinstance(result, JSObject) and isinstance(result.js_val, int):
                    val_index = result.js_val
                else:
                    val_index = ctx._pushObj(result).js_val
                
                ctx._exitVM(val_index)
                
                self.remove_js_ctx(vm)
            if isinstance(msg, dict) and "type" in msg.keys() and msg["type"] == "send":
                payload = msg["payload"]
                if isinstance(payload, dict) and "type" in payload.keys():
                    if payload["type"] == "bridge":
                        th = threading.Thread(target=_inner_call, args=(payload, ))
                        th.start()
                    elif payload["type"] == "vm":
                        with self._js_vm_cond:
                            vm = payload["vmi"]
                            ctx = self.get_js_ctx(vm)
                            ctx.val = payload.get("val", None)
                            ctx.err = payload.get("err", None)
                            self._js_vm_cond.notify()

        session = device.attach(target)
        script = session.create_script(self.gen_script(), runtime="qjs")
        script.on("message", _internal_msg_handler)
        script.load()
        self._js_script = script

    def add_js_function(self, python_func: Callable, js_func_arg_num: int = -1) -> JSObject:
        if js_func_arg_num == -1:
            js_func_arg_num = len(signature(python_func).parameters) - 1
        func = {
            "callback": python_func,
            "id": self._js_func_count,
            "arg_num": js_func_arg_num
        }
        self._js_funcs[self._js_func_count] = func

        js_func_obj = JSObject(self._js_global_ctx, val="Bridge%d" % (self._js_func_count, ))

        self._js_func_count += 1

        return js_func_obj

    def exec_func(self, js_func: JSObject, *args) -> Any:
        arg_str = ", ".join(repr_js(arg) for arg in args)
        call_str = "%s(%s)" % (repr_js(js_func), arg_str)
        return self._js_global_ctx._eval(call_str)

    def exec_func_in_java(self, js_func: JSObject, *args):
        arg_str = ", ".join(repr_js(arg) for arg in args)
        call_str = r"""
Java.perform(function() {
        %s(%s)
})
""" % (repr_js(js_func), arg_str)
        return self._js_global_ctx._eval(call_str)