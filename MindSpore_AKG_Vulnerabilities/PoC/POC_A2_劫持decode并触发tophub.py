import sys, os

sys.path.insert(0, '/usr/local/lib/python3.10/dist-packages/mindspore/_akg')
os.environ['LD_LIBRARY_PATH'] = '/usr/local/lib/python3.10/dist-packages/mindspore/lib/plugin/cpu:' + os.environ.get('LD_LIBRARY_PATH', '')

import akg.tvm.autotvm.record as rec

def new_decode(row, protocol='pickle'):
    return rec._orig_decode(row, 'pickle')

rec._orig_decode = rec.decode
rec.decode = new_decode
rec.load_from_file.__globals__['decode'] = new_decode
print('[+] decode初始化完成')

os.environ['TOPHUB_LOCATION'] = 'http://127.0.0.1:8080'

from akg.tvm.autotvm import tophub
tophub.context('llvm')
print('[+] 完成')