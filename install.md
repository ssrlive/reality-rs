## 安装

请准备一台 Linux x86_64 的带公网 IP 的主机， 你可以购买 一个 VPS， 它基本都 满足这些条件。

使用 这个 命令

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ssrlive/reality-rs/main/install/installer.sh) install
```

就可以将 anyreality 服务端安装到你的 Linux 主机上， 期间 会询问 两次，
要求 你输入 你选定的 伪装网站的 域名 和 在主机上监听 的 端口。

> [!NOTE]
> 如下所示(这里输入示例是 `cn.bing.com` 和 443 , 提醒一点，请一定选与示例不同的中国能访问的国外网站，否则可能引起 GFW 的封杀；
> 443 端口 可能已经占用， 你可以选其它空闲的端口)

```plaintext
... (略) ...
Installing binary to /usr/local/bin
请输入 你的网站域名 (形如 mygooodsite.com) 并敲回车, 如果不输入（只敲回车）将随机选择一个常见的站点名:
Enter your domain name (for example: mygooodsite.com), or press Enter only to select a random common site: cn.bing.com
请输入服务器监听端口 (默认为 443) 并敲回车:
Enter the listen port for the server (default 443):443
```

如果 你不想停下来 输入 域名 和 端口， 也 可以在 命令行里 直接 加入
```bash
bash <(curl -Ls https://raw.githubusercontent.com/ssrlive/reality-rs/main/install/installer.sh) install cn.bing.com 443
```

安装完毕后， 这时会在终端显示 客户端的 配置 文件 和 自签名 证书， 像这样
```plaintext
==== CA CERT (/etc/anyreality/ca.crt) ====

-----BEGIN CERTIFICATE-----
MIIFHzCCAwegAwIBAgIUeOuljYqqNNxILV1nCdfmMY6rNIowDQYJKoZIhvcNAQEL
...
1XFA1grVfQL9tDNMd4RmcavkOKWIw/lp+WMUbB1gve6YIThA1qFyBtR/XLiwI6gd
08Nqh9tbW8Hqd4WbFWNCdF9DJQ==
-----END CERTIFICATE-----

==== Client config (/etc/anyreality/client-config.toml) ====

[reality]
# shortId: 8-byte hex string (16 hex chars)
shortId = "373ea..."
# publicKey (base64url no-padding) — client may need server public for some flows
publicKey = "Zr0WUF2_jkUH..."
version = "010203"
serverName = "cn.bing.com"

[anytls]
password = "Lmpr9er8tTREFyZK5T..."
idleCheckSecs = 30
idleTimeoutSecs = 30
minIdleSessions = 5

[client]
listen = "127.0.0.1:2080"
serverAddr = "123.45.67.89:443"
caFile = "/etc/anyreality/ca.crt"
insecure = true

Install complete. Server config: /etc/anyreality/config.toml; client config and CA printed above.
```

请将 从 `[reality]` 到 `insecure = true` 的文字复制粘贴并保存到本地的 `anyreality-client-config.toml` 文件里
作为 anyreality 客户端的 配置文件。

值得说明的是， 配置里的 `insecure = true` 代表 客户端在连接服务器时 不验证 服务器证书，这为用户带来一定的 便利性。

> [!TIP]
> 另一方面，由于服务端使用的是未由任何权威机构认证的自签名证书，因此无法通过正常的证书验证流程。这会带来一定安全风险（比如中间人攻击）。
> 如果你想要更安全的连接， 可以将 `insecure` 设置为 `false`， 并将服务器的自签名证书
> （上面显示的 `ca.crt` 内容， 从 `-----BEGIN CERTIFICATE-----` 到 `-----END CERTIFICATE-----`）保存到本地，
> 然后在配置里将 `caFile` 的路径指向这个保存的证书文件(请使用全路径)。 这样客户端在连接服务器时就会验证服务器的证书， 提高安全性。

到 [这里](https://github.com/ssrlive/reality-rs/releases) 下载 anyreality 客户端的二进制文件，
选择与你的操作系统和 CPU 架构相匹配的版本下载并解压.

这样运行 anyreality 客户端

```bash
anyreality-client --config /your/path/to/anyreality-client-config.toml
```

客户端成功连接服务端后， 根据配置里的 `listen = "127.0.0.1:2080"` 参数， 它就是一个监听在 127.0.0.1:2080 的上的 SOCKS5 代理，
你可以在本地的浏览器里设置 SOCKS5 代理的这个地址， 就可以通过 anyreality 连接到你的目标服务器， 从而访问被 GFW 封锁的网站了。

> [!TIP]
> 如果你在 Windows 上使用 anyreality 客户端， 可以这样在 `powershell` 上运行， 它会安静地呆在后台， 不会弹出黑乎乎的命令行窗口
> ```powershell
> Start-Process -FilePath "C:\path\to\anyreality-client.exe" -ArgumentList "--config C:\path\to\anyreality-client-config.toml" -WindowStyle Hidden
> ```

## 卸载

如果你想卸载 anyreality 服务端， 可以运行下面的命令, 在输入 yes 确认后， 它会删除 anyreality 的二进制文件和配置文件以及服务配置， 从而完成卸载。

```bash
bash <(curl -Ls https://raw.githubusercontent.com/ssrlive/reality-rs/main/install/installer.sh) uninstall
```
