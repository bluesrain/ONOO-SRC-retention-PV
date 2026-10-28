MindSpore AKG 调优日志反序列化远程代码执行

报告编号 A00，上报者 ONOO⁻，影响版本 MindSpore 2.4.1 到 2.9.0，CVSS 3.1 评分 9.8，Critical，发现日期 2026 年 6 月 13 日，文档日期 2026 年 6 月 18 日。

本文是 2026 年 6 月 13 日提交的《AKG 模块 pickle 反序列化 RCE（MindSpore 2.4.1）》的补充材料，用来完善证据链，同时说明该问题在 2.4.1 到 2.9.0 的各版本中一直存在。

漏洞在 MindSpore AKG 模块的 AutoTVM 调优日志处理流程里。系统自动下载预调优参数的时候没有做完整性和签名校验，最后又用 pickle.loads 去反序列化下载到的内容。攻击者只要控制环境变量 TOPHUB_LOCATION，或者劫持下载链路，就能在一次正常的模型编译中完成无交互也无报错的任意代码执行。

这条链路有两个属性。一是供应链投毒，调优参数从远端拉取，没有哈希也没有签名，链路一旦被污染就是水坑。二是本地提权，MindSpore 经常以 root 跑在共享训练节点上，低权限用户可以让高权限进程替自己执行代码。

先说触发。build_module.py 第 230 到 245 行，当 DispatchContext.current 是 FallbackContext，也就是默认上下文时，会直接调用 autotvm.tophub.context(list(target.values()))。这意味着任何一次模型编译都会走进来，不需要显式调用，也不需要额外配置。

其次说下载源。tophub.py 里的 _get_tophub_location 直接用 os.getenv 读 TOPHUB_LOCATION，读到什么就用什么，没有域名白名单，也没有格式限制。攻击者只要在目标环境里设置这个变量，下载源就指向了他自己的服务器。

然后是下载。download_package 只负责拼出 download_url，然后交给 contrib/download.py 里的 download 函数。这个函数只做两件事，拉取和落盘。没有 SHA-256，没有 GPG 签名，也没有证书固定。恶意文件原封不动地穿过安全边界，写进 AUTOTVM_TOPHUB_ROOT_PATH，默认是 ~/.tvm/tophub。

最后是消费端。record.py 的 decode 在 protocol 等于 pickle 的分支里，对 row.split 之后的字段逐个反序列化，没有任何类白名单限制。核心就是这三行。

task_tuple = pickle.loads(base64.b64decode(items[1].encode()))  
config = pickle.loads(base64.b64decode(items[2].encode()))  
result = pickle.loads(base64.b64decode(items[3].encode()))

pickle.loads 反序列化时会自动执行对象里的 __reduce__，这是标准的反序列化 RCE 基础。配合前面那条无校验的下载链路，远端数据到本地代码执行的通路就闭合了。sink 的定位过程见 Images/ast_sink_analysis.png。

复现分七步。第一步，构造带 __reduce__ 的恶意类，按 AutoTVM 日志格式把 cuda 和三个字段拼成 llvm_v0.03.log，放在攻击者的 HTTP 服务器上。第二步，把 TOPHUB_LOCATION 指向这台服务器。第三步，受害者执行一次正常的模型编译，BuildModule 进入 tophub 分支。第四步，本地没有日志，check_backend 读取被污染的环境变量，调用 download_package 去拉取。第五步，download 无校验落盘到 ~/.tvm/tophub。第六步，ApplyHistoryBest.load 调用 load_from_file 读日志。第七步，decode 执行 pickle.loads，__reduce__ 被触发。

payload 严格按 AutoTVM 的格式拼接，cuda 加 task 加 config 加 result，格式上完全合规，能绕过基础的格式校验。root 身份下的执行结果见 Images/poc_pickle_root.png，属主为 root 的证明文件被成功创建。

验证做了两轮，root 和普通用户各一轮。两种身份下 __reduce__ 里的命令都执行了，生成的文件属主分别是 root 和 MS。编译业务都正常继续，没有异常，没有错误日志。也就是说，代码执行权限完全继承自 MindSpore 进程的运行身份。典型部署里 MindSpore 以 root 跑，比如作为系统服务，普通用户 MS 就能让 root 进程执行任意代码，构成本地提权。三次 POC 全程没有崩溃，只输出常规的下载日志，业务功能正常返回，隐蔽性很高。

危害分三层。权限提升，共享 GPU 训练节点上普通租户可以越权执行 root 代码。供应链和水坑，下载链路没有哈希也没有签名，安全性完全依赖传输层，一旦请求可以被劫持或者重定向，比如中间人，企业代理，DNS 或者证书链被控，就能对社区开发者形成无差别攻击。隐蔽性，全程没有报错，常规安全设备很难感知。CVSS 3.1 矢量为 AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H，基础评分 9.8。

影响版本是 2.4.1 到 2.9.0。record.py 和 tophub.py 从 2.4.1 引入之后到 2.9.0 没有实质性修改，危险的反序列化调用和环境变量覆盖逻辑一直都在。在 2.9.0 上用 mindspore.run_check 确认过版本，然后复现成功。

修复从三个层面做。代码层面，废弃 pickle，把 record.py 里的 pickle.loads 换成 json.loads 或者 ast.literal_eval。如果必须保留 pickle，就重写 pickle.Unpickler.find_class，建立严格的类白名单。同时在 download_package 里增加 SHA-256 和签名校验，校验通过才允许加载。配置层面，移除对 TOPHUB_LOCATION 的直接信任，固定为硬编码的官方 HTTPS 源，并且禁止 MindSpore 以 root 运行，改用专用低权限账户。运行时层面，监控 MindSpore 派生出来的 bash 和 sh 子进程，以及指向非官方域名的出站请求，同时对 ~/.tvm/tophub 下的日志做文件完整性监控。

发现过程其实从一个直觉开始。AI 框架普遍有自动拉取外部资源然后直接用的机制，这类机制往往就是最薄的信任边界。静态排查时先定位到 tophub.py 里可以被环境变量覆盖的 TOPHUB_LOCATION，还有无校验的 download，继续往数据消费端追，在 record.py 里命中了连续三行的 pickle.loads。下载，落盘，反序列化，三段拼起来闭环就成形了。为了验证可达性写了完整的 PoC，本地搭恶意 HTTP 服务器，按格式构造日志，设好环境变量，然后跑一次普通的模型编译。build_module 的分支被无条件命中，check_backend 自动下载，load_from_file 读取，pickle.loads 执行 __reduce__，属主为 root 的证明文件生成的那一刻，链路确认闭合。

PoC 一共三个，都在 PoC 目录下。生成 payload 的是 POC_A1_生成恶意payload.py，劫持 decode 并触发 tophub 的是 POC_A2_劫持decode并触发tophub.py，独立验证三次 pickle.loads 的是 POC_A3_pickle反序列化验证.py。
