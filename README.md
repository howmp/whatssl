# whatssl

识别客户端是否使用OpenSSL,检测网站 <https://whatssl.guage.cool/> 

由于Python,PHP等都使用OpenSSL，也会这可以成为反爬的一个特征

## 部署形态

对外只有 **443** 一个端口。服务器上的 Caddy 用 layer4 插件按 SNI 分流：

- SNI == `whatssl.guage.cool` 的连接**原样 TCP 透传**给 `127.0.0.1:8443` 的本进程，Caddy 不终结这段 TLS；
- 其余 SNI 交回 Caddy 自己终结并按站点路由。

**Caddy 绝不能先终结 TLS 再转发过来**：一旦解密，密文 Finished 记录就不存在了，检测必然失效。
因此本服务对外的 443 也只支持 TLS 1.2，且不宣告 ALPN（只 `http/1.1`）；
Caddy 侧同时用 `protocols h1 h2` 关掉了 HTTP/3 —— QUIC 走 UDP/443、只支持 TLS 1.3，
无论 Caddy 什么版本都不会经过本进程，关掉 `alt-svc` 是为了让浏览器别绕开检测。

证书由 Caddy 通过 ACME 自动签发续期，本进程只读它写下的文件（`certs/` 是指向 Caddy
存储目录的软链），并按内容摘要在运行期热加载，不需要重启。

## 原理

当tls密钥协商结束(ChangeCipherSpec)，开始进入加密通信后

如果使用AEAD算法(这也是推荐算法)

1. 那么使用sequence number(64bit)作为nonce
1. sequence number也会发送，作为Record数据的前8个字节
1. sequence number必须从0开始

由于OpenSSL的sequence number没有从0开始，导致其可以轻松被识别

<https://www.rfc-editor.org/rfc/rfc5246#page-19>

> Each connection state contains a sequence number, which is
> maintained separately for read and write states.  The sequence
> number MUST be set to zero whenever a connection state is made the
> active state.  Sequence numbers are of type uint64 and may not
> exceed 2^64-1.  Sequence numbers do not wrap.  If a TLS
> implementation would need to wrap a sequence number, it must
> renegotiate instead.  A sequence number is incremented after each
> record: specifically, the first record transmitted under a
> particular connection state MUST use sequence number 0.



## 测试

| Name       | OpenSSL | Note      |
|------------|---------|-----------|
| chrome     | N       | boringssl |
| powershell | N       | schannel? |
| Java       | N       | JSSE      |
| python     | Y       | OpenSSL   |
| php        | Y       | OpenSSL   |
| curl       | Y       | OpenSSL   |


### powershell

```ps
Invoke-WebRequest https://whatssl.guage.cool/ | Select -ExpandProperty Content
```

### python

```sh
python -c "print(__import__('requests').get('https://whatssl.guage.cool/').text)"
```

### php

```php
<?php
echo file_get_contents("https://whatssl.guage.cool/");
```

### curl

```sh
curl https://whatssl.guage.cool/
```