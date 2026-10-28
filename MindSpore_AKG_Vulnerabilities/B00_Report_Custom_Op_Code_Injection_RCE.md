MindSpore AKG 自定义算子动态加载代码注入

报告编号 B00，上报者 ONOO⁻，影响版本 MindSpore 2.4.1 到 2.9.0，CVSS 3.1 评分 9.8，Critical，发现日期 2026 年 6 月 13 日，文档日期 2026 年 6 月 18 日。

本文是 2026 年 6 月 13 日提交的《AKG 模块 pickle 反序列化 RCE（MindSpore 2.4.1）》的二次补充。后续研究里，AKG 模块还有一条完全独立的任意代码执行攻击面。

漏洞位于 AKG 模块的自定义算子编译流程。akg/composite/topi.py 里的 _launch_kernel_from_path 负责从指定路径加载自定义算子的实现代码，它用 importlib.util.spec_from_file_location 和 exec_module 动态加载并执行 Python 源文件，但对文件来源和内容合法性没有任何校验，也没有沙箱隔离。

攻击者控制 op_impl_path 指向一个恶意 Python 文件，或者通过 malicious_source 参数直接传入代码字符串，就能在模型编译阶段触发任意代码执行。这条链不需要环境变量篡改，也不需要链路劫持，比 pickle 那条更短，更直接。

核心危害有四个。构造恶意自定义算子就能在编译阶段执行任意系统命令。执行权限完全继承自 MindSpore 进程，典型场景是 root。过程没有报错，也没有异常日志，业务功能正常返回。所有使用 AKG 自定义算子编译功能的用户都受影响。

这条链与已经公开的 CVE-2026-40156（PraisonAI）在技术特征上高度一致，属于同类代码注入问题。

成因先说定位。全局检索 importlib.util.spec_from_file_location，在 AKG 模块里命中三处，aks/message.py 第 46 行，composite/topi.py 第 746 行，utils/composite_op_helper.py 第 604 行。其中最直接可利用的是 topi.py 里的 _launch_kernel_from_path。

关键代码是这样的。

custom_mod_name = Path(op_impl_path).resolve().stem  
mod_spec = importlib.util.spec_from_file_location(custom_mod_name, op_impl_path)  
custom_mod = importlib.util.module_from_spec(mod_spec)  
mod_spec.loader.exec_module(custom_mod)  
func_kernel = getattr(custom_mod, func_name, None)

逻辑很清楚。函数接收 op_impl_path，用 Path.resolve().stem 取文件名当模块名，交给 spec_from_file_location，然后调 exec_module 把文件里的顶层代码全部执行，最后按 func_name 取出函数返回。

致命的地方有四个。没有路径校验，不检查 op_impl_path 是否在可信目录。没有内容审查，不做安全检查也不做隔离。没有权限降级，加载的代码以 MindSpore 进程的完整权限运行。没有签名校验，不验证文件来源。

入口这一层也值得说。_launch_kernel_from_path 通过 tvm.register_func("Custom") 注册成 TVM 的自定义算子入口，任何经 TVM 算子协议过来的自定义算子编译请求都会走到这个函数。攻击者只要控制 TVM 算子属性里的 func_name，func_type 和 op_impl_path，就能把恶意路径塞进调用链。

根本原因还是设计假设。AKG 在设计自定义算子加载机制时默认了输入路径和文件来源可信，把危险的文件系统操作和代码动态加载能力暴露给了攻击者可以触及的接口。

攻击链自上而下是这样。构造恶意 Python 文件或者代码字符串，通过 Custom 算子接口传入 func_name，func_type 和 op_impl_path，_launch_kernel_from_path 收到参数，spec_from_file_location 加载文件，exec_module 执行顶层代码，任意代码执行完成，权限继承自 MindSpore 进程。

验证一是直接注入。不需要外部文件，把带恶意代码的字符串传给 malicious_source 就能触发。编译继续执行并返回 Tensor，全程没有报错，执行结果见 Images/poc_importlib.png。脚本是 POC_B1_importlib静默无报错.py。

验证二是信息收集。用同一个入口执行信息收集代码，把当前用户，主机名和系统时间写进 /tmp/akg_info.txt，证明攻击者可以在无感知的情况下窃取系统信息。脚本是 POC_B2_importlib信息收集.py。

验证结论。任意代码执行，/tmp/akg_custom_rce_proof 被创建。信息收集，用户，主机名和时间写进了 /tmp/akg_info.txt。权限验证，文件属主是 root。编译业务继续执行，返回 Tensor，没有报错。隐蔽性上没有任何异常日志，业务功能正常返回。

危害分四层。权限提升，MindSpore 常以 root 运行，普通用户构造自定义算子就能让 root 进程执行任意代码，可以读 /etc/shadow，写 /root/.ssh/authorized_keys，改 /etc/sudoers，直接接管服务器。RCE，不需要绕过任何安全机制，可以装持久化后门，反弹 shell，横向渗透，窃取训练数据和模型权重。供应链，恶意代码可以伪装成合法自定义算子，上传到模型仓库或者算子市场，受害者编译时自动执行。隐蔽性，整个过程都在正常编译流程里完成，没有额外日志，WAF 和 IDS 一类设备很难感知。CVSS 3.1 矢量为 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H，基础评分 9.8。

影响版本是 2.4.1 到 2.9.0。_launch_kernel_from_path 在这几个版本里持续存在且没有被修改，spec_from_file_location 的调用自模块引入就存在，自定义算子接口从 2.4.1 开始正式支持，后续版本持续扩展但没有做安全加固。

受影响场景有三类。AI 训练集群和 MLOps 平台，多用户共享 GPU 节点，root 运行时普通用户可以越权执行任意代码。模型分发和共享平台，恶意算子被上传后，用户编译时自动触发。企业内部 CI/CD，算子代码库一旦被污染，流水线里每次编译都会被植入后门。

修复建议。代码层面，禁止动态加载用户可控的 Python 源文件，用静态算子注册机制替代 spec_from_file_location 和 exec_module，所有自定义算子在编译前走白名单注册。增加路径白名单，只允许从系统可信目录加载，比如 /usr/local/lib/python3.10/dist-packages/mindspore/_akg/，拒绝 /tmp，/home 和当前目录这类用户可控路径。移除 malicious_source 参数，这个参数等于一个远程代码执行 API，应该彻底去掉或者限制成内部可信调用。运行时层面，监控 importlib 的动态加载行为，记录被加载的文件路径，对异常路径告警。用 EDR 或者 Falco 监控 MindSpore 派生出来的 bash，sh 和 python 子进程。对 AKG 模块的关键 Python 文件做完整性监控。

发现这条链是研究 pickle 时的意外收获。完成 record.py 的定位后，决定对 AKG 模块做一次更全面的审查，用 grep 递归检索所有 importlib 的动态导入点，只限定 py 文件，返回了 aks/message.py，composite/topi.py 和 utils/composite_op_helper.py 三个文件。看到 composite/topi.py 里 _launch_kernel_from_path 直接拿调用方给的路径去 spec_from_file_location，一点校验都没有。

随后写了 PoC。先用 malicious_source 直接注入代码字符串，/tmp/akg_custom_rce_proof 被创建，编译照常返回 Tensor。再写一个信息收集的 PoC，拿到当前用户，主机名和时间，写进 /tmp/akg_info.txt。

和 pickle 那条对照，这条不需要环境变量，也不需要网络，触发路径更短。两条链指向同一个设计取向，为了灵活性把动态加载能力放在了安全边界之外。

PoC 两个，都在 PoC 目录下。POC_B1_importlib静默无报错.py 用 malicious_source 触发 RCE，POC_B2_importlib信息收集.py 用同一入口做信息收集。
