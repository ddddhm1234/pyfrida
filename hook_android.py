from pyfrida import pyfrida
from pyfrida.pyfrida import JSContext, JSObject
import frida

def main(ctx: JSContext):
    clz = ctx.Java.use("com.kanxue.pediy1.MainActivity$1")
    clz.onClick.implementation = js_func_hook

def hook_click(ctx: JSContext, arg: JSObject):
    print("=== 调用onclick ===")
    result = ctx.this.onClick(arg)
    print("参数:", arg.get_val())
    print("返回值:", result.get_str())

fs = pyfrida.FridaScript()

# 绑定python函数与js函数
js_func_main = fs.add_js_function(main)
js_func_hook = fs.add_js_function(hook_click)

# with open("test6.js", "w") as f:
#     f.write(fs.gen_script())
#     exit()

# 创建进程并注入Frida HOOK脚本
frida.get_usb_device()
device = frida.get_usb_device()
pid = device.get_process("pediy1").pid
fs.attach(device, pid)
# 执行main函数开始hook
fs.exec_func_in_java(js_func_main)

input()