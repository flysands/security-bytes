# Quick news

## BUF 早餐铺 | 一加手机曝出后门；谷歌Browse-Secure扩展程序爬取用户社交信息；微软11月修复53个漏洞；Adobe 修复9款产品中的80个漏洞

    http://www.freebuf.com/news/154157.html

    修复狂欢周，要不要来份早餐补一补？ 各位 Buffer 早上好，今天是 2017 年 11 月 16 日星期四。今天份的 BUF 早餐主要有：谷歌 Browse-Secure 扩展程序可爬取用户社交通讯信息；新 IcedID 木马攻击北美；美政府公布朝鲜所使用的 FALLCHILL 恶意程序详情；一加手机出现后门，可能影响其它使用高通芯片的设备；微软 11 月修复 53 个漏洞，Windows 系统、Office 应用、浏览器等多处中招；11 月修复日 SAP 修复 22 个安全漏洞；Adobe 修复 9 款产品中的 80 个漏洞。 以下请看详细内容： 【国际时事】 谷歌 Browse-Secure 扩展程序可爬取用户社交通讯信息 Chrome Web 商店中出现一款新的扩展程序 Browse-Secur，原意是为了保护搜索安全，但事实上，这款扩展程序会爬取用户的 LinkedIn 和 Facebook 账户信息，并将用户名、邮箱地址、性别、手机号、住址等信息发送到远程服务器上。 用户浏览网页时，可能会看到误导性广告：“警告！恶意入侵”，随后，该广告会将 Browse-Secur 扩展程序推送给用户，提示可以确保浏览安全，诱导用户安装。用户一旦安装，在使用谷歌搜索时，不但搜索请求和 IP 地址会被获取，连 Facebook 等社交通讯信息都暴露无余。这已经不是 Chrome 扩展程序第一次出问题了，看起来 Chrome 扩展已经成为了黑客的新乐土，用户在安装扩展程序时务必要谨慎。[来源：bleepingcomputer ] 新 IcedID 木马攻击北美 日前，IBM 的研究员发现一款新的银行木马 IcedID，与 Gozi、Zeus 和 Dridex 等银行木马相似，但代码由该黑客自己开发。研究员表示，该银行木马最早在 9 月份出现，主要针对美国和加拿大的银行、支付卡供应商、移动服务供应商、公司、网页邮件、电子商务网站等发起攻击。此外，英国的两所主流银行也不幸中招。 IcedID 主要利用 Emotet 木马进行传播，Emotet 通过垃圾邮件分发，一般在隐藏在含有恶意宏代码的生产文件中，且持续隐匿以便攻击者传播其他恶意 payload （如 IcedID）。一旦感染用户设备，IcedID 就会监控用户在线活动，其攻击手段主要包括 web 注入、重定向等。用户进入网页后会被重定向到山寨的银行网站（但用户无法分辨），提交的用户名、登录凭证等都会被攻击者获取，进而发起攻击。据分析，IcedID 的代码疑似为说俄语的作者所编写。[来源：Securityaffairs] 美政府公布朝鲜所使用的 FALLCHILL 恶意程序详情 近期，美国计算机应急响应中心 US-CERT 叕发布了 DHS 和 FBI 针对朝鲜政府黑客组织HIDDEN COBRA的联合技术分析预警（TA17-318A），预警中详细披露了 HIDDEN COBRA 用于网络渗透攻击的远控工具-FALLCHILL。US-CERT 称，DHS 和 FBI [&#8230;]
## 利用CVE-2017-5123攻击提供全面保护的SMEP、SMAP和Chrome沙盒

    http://www.freebuf.com/articles/system/153633.html

    前段时间，在群里小伙伴发了最新的linux内核利用，影响版本还挺多，自己也利用国外的exploit来进行实验linux提权&#8230;&#8230;阅读本文需要的基础：c语言，操作系统，内核调用&#8230;&#8230;(虽然没有，也是可以看的 。。偷笑) 在这篇博客文章中，我将解释如何利用CVE-2017-5123这一我在Linux内核中发现的bug，并展示如何使用它来提升权限，即使使用者使用的环境是SMEP，SMAP和Chrome沙箱。 背景 在系统内核调用处理期间，内核需要能够读写与调用系统进程驻留的内存地址。要做到这一点，内核需要具有特殊的功能，比如copy_from_user，put_user和其他那些能实现把数据复制到用户空间的函数。在很高的系统等级上，put_user函数大致如下： put_user(x, void __user *ptr) if (access_ok(VERIFY_WRITE, ptr, sizeof(*ptr))) return -EFAULT user_access_begin() *ptr = x user_access_end() 该access_ok()函数调用并检查PTR是在用户状态态还是在内核驻留的内存中。如果检查通过，user_access_begin()将被调用并将禁用SMAP，这将允许内核访问用户区。内核能够执行内存写入，然后会重新启用SMAP。这里需要注意的一点是：这些用户访问函数在内存读写过程中即使出现内存页错误，在访问未映射的内存地址时也不会导致崩溃。 漏洞 某些系统调用需要多次调用才能使用put/get_user来在内核和用户空间之间复制数据。为了避免重复检查以及SMAP启用/禁用的额外开销，内核开发人员包含了不安全的版本函数：__put_user和unsafe_put_user没有对此进行检查。不出所料，可以确实可以减少额外的开销。但正因为如此，也正是CVE-2017-5123能发生的情况。所以在内核版本4.13中，waitid()在系统调用时被更新成使用unsafe_put_user，但没有进行access_ok()检查。所以易受到攻击的代码详情如下所示。 SYSCALL_DEFINE5(waitid, int, which, pid_t, upid, struct siginfo __user *, infop, int, options, struct rusage __user *, ru) { struct rusage r; struct waitid_info info = {.status = 0}; long err = kernel_waitid(which, upid, &#38;info, options, ru ? &#38;r : NULL); int signo = 0; if (err &#62; 0) { signo = SIGCHLD; err = 0; if (ru &#38;&#38; copy_to_user(ru, &#38;r, sizeof(struct rusage))) return -EFAULT; } if (!infop) return err; user_access_begin(); unsafe_put_user(signo, &#38;infop-&#62;si_signo, Efault); &#60;- no access_ok call [&#8230;]
## 送你一份API安全评估核查清单

    http://www.freebuf.com/articles/web/153376.html

    此份清单对于参与API设计、测试和发布过程的相关安全评估人员而言非常重要，大家可以根据清单核查自身行为！ 认证 不要使用Basic Auth（基本身份认证），而要使用standard authentication（标准身份认证，例如JWT，OAuth）； 在身份认证、令牌生成、密码存储过程中不要重造轮子，必须使用标准的规范； 在登录中使用Max Retry和jail功能； 对所有敏感数据进行加密处理； JWT （全称JSON Web Token） 使用一个随机的、复杂的密钥（JWT密钥）来增加暴力破解令牌的难度； 不要从JWT的有效载荷中提取算法，在后端强制执行算法（HS256 or RS256）； 限制Token的过期时间（TTL，RTTL），越短越好； 不要将敏感数据存储在JWT的有效载荷中，因为它可以很轻松地被解码； OAuth 始终验证服务器端redirect_uri地址，确定其只允许白名单的网址进去； 通过code（代码）而不是tokens（令牌）的方式进行信息交换（禁用response_type=token）； 在state参数中使用一个随机的哈希值，来防止OAuth认证过程中发生CSRF攻击行为； 定义默认范围，并验证每个应用程序的范围参数； 访问 限制请求（节流），以避免DDoS／暴力破解攻击； 在服务器端使用HTTPS来避免中间人攻击（MITM）； 使用带有SSL的HSTS标头，来避免SSL Strip攻击（一种中间人攻击）； 输入 根据实际操作使用适当的HTTP方法：GET（读取）、POST（创建）、PUT（替换／更新）以及DELETE（删除记录），如果请求的方法无法对应请求的资源，则使用“405错误（方法不被允许）”进行响应； 验证请求接受标头（内容协商）中的content-type（内容类型），只允许你支持的格式（例如application/xml、application/json等），如果不匹配，则返回“406 错误（无法接受请求）”； 验证发布数据中你接受的内容类型（例如 application/x-www-form-urlencoded、multipart/form-data、application/json等）； 验证用户输入以避免一些常见的漏洞（例如XSS、SQL注入以及远程代码执行等）； 请勿在链接中使用任何敏感数据（凭据、密码、安全令牌或API密钥等），而要使用标准的Authorization header（认证标头）； 处理 检测所有端点是否受到身份验证保护，以避免身份验证过程中断； 用户应该避免使用自己的资源ID。应该选择使用/me/orders 替代 /user/654321/orders； 禁止使用自增ID，可以使用UUID替代； 如果你正在解析XML文件，请确保未启用实体解析，以避免遭受XXE（XML外部实体攻击）； 如果你正在解析XML文件，请确保实体扩展功能未启用，以避免遭受递归实体扩展攻击（这种方式也被称之为“XML Bomb”或是“Billion Laughs Attack”）； 使用CDN进行文件上传； 如果你需要处理的数据量很大，请尽可能在后台使用Workers 和 Queues的方式进行快速响应，以避免HTTP阻塞； 不要忘记关闭DEBUG模式； 输出 发送X-Content-Type-Options：nosniff 标头； 发送X-Frame-Options：deny标头； 发送Content-Security-Policy：default-src‘none’ 标头； 对响应的内容类型进行限制，如果你返回application/json，那么你的响应内容类型应为application/json； 不要返回凭据、密码、安全令牌等敏感数据； 根据已经完成的操作返回适当的状态码。（例如200 OK、400 Bad Request、401 Unauthorized、405 Method Not Allowed等）； CI（持续集成）&#38; CD（持续交互） 使用unit/integration（单元／集成）测试来审核你的设计和实施活动； 启用代码审查程序，避免盲目自信； 确保你服务器上的所有组件在进入生产之前都通过AV软件进行了静态扫描，包括供应商库（libraries）和其他依赖项； 为部署过程设计一个回滚（rollback）的解决方案。 *参考来源：github，米雪儿编译，转载请注明来自FreeBuf.COM
## HCTF2017 部分 Web 出题思路详解

    https://paper.seebug.org/452/

    作者：LoRexxar'@知道创宇404实验室
11月12日结束的HCTF2017，我总共出了其中4道题目，这4道题目涵盖了我这半年来接触的很多有趣的东西。下面就简单讲讲出题思路以及完整的Writeup。
babycrack

Description 
just babycrack
1.flag.substr(-5,3)==&amp;quot;333&amp;quot;
2.flag.substr(-8,1...
