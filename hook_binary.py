from pyfrida import pyfrida
from pyfrida.pyfrida import JSContext, JSObject
import frida
import time

def main(ctx: JSContext):
    # 部署hook
    ptr_of_msgbox = ctx.Module.getExportByName("user32", "MessageBoxW")
    ctx.Interceptor.attach(ptr_of_msgbox, {
        "onEnter": js_func_hook
    })

def my_msgbox_enter(ctx: JSContext, args: JSObject):
    print("=== 调用MessageBoxW ===")
    print("内容:", args[1].readUtf16String().get_val())
    print("标题:", args[2].readUtf16String().get_val())


fs = pyfrida.FridaScript()

# 绑定python函数与js函数
js_func_main = fs.add_js_function(main)
js_func_hook = fs.add_js_function(my_msgbox_enter)

# 创建进程并注入Frida HOOK脚本
device = frida.get_local_device()
pid = device.spawn("./WindowsProject1.exe")
fs.attach(device, pid)
# 执行main函数开始hook
fs.exec_func(js_func_main)
device.resume(pid)

input()