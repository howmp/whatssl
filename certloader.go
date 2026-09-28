package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"
)

// fileStamp 用来判断证书文件是否变化。
//
// 用内容摘要而不是 mtime+size：caddy 续期后的新证书是同一家 CA、同一套参数签出来的，
// 字节数很可能一模一样（服务器上现有 whatssl 证书就是 4824 字节），
// 真正可靠的信号只有内容本身。文件很小（~5KB），一分钟读一次无任何开销。
type fileStamp struct {
	digest   [sha256.Size]byte
	certSize int64
	keySize  int64
	certMod  time.Time // 仅用于日志
}

func stampOf(certFile, keyFile string) (fileStamp, error) {
	var stamp fileStamp
	h := sha256.New()
	certInfo, err := os.Stat(certFile) // Stat 会跟随 symlink，certs/ 目录整体是软链到 caddy 证书库的
	if err != nil {
		return fileStamp{}, err
	}
	if err := hashFile(h, certFile); err != nil {
		return fileStamp{}, err
	}
	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		return fileStamp{}, err
	}
	if err := hashFile(h, keyFile); err != nil {
		return fileStamp{}, err
	}
	copy(stamp.digest[:], h.Sum(nil))
	stamp.certSize, stamp.keySize, stamp.certMod = certInfo.Size(), keyInfo.Size(), certInfo.ModTime()
	return stamp, nil
}

func hashFile(h io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(h, f)
	return err
}

// certReloader 定期检查证书文件，变化时重新加载。
//
// 为什么需要它：证书由 caddy 通过 ACME 自动续期后只落到磁盘，
// 而 tls.Config 里的证书是启动时载入内存的快照，进程不重启就一直用旧证书。
// （原服务器上是靠 cron 每天 restart 兜底，证书一旦漏掉那天就过期。）
//
// 握手路径（getCertificate）只读 atomic 指针，不做任何 IO；
// 文件检查放在后台 loop 里，因此不会给每次握手增加 stat 开销。
type certReloader struct {
	certFile string
	keyFile  string
	interval time.Duration
	// expireWarnBefore 剩余有效期低于该值时打 WARN，避免证书过期才发现。
	expireWarnBefore time.Duration

	current atomic.Pointer[tls.Certificate]
	stamps  atomic.Pointer[fileStamp]
}

// newCertReloader 载入一次初始证书并返回加载器。初始加载失败直接返回错误：
// 没有证书的 TLS 服务没有启动价值，让 systemd 拉起重试比在这里假装能跑更诚实。
func newCertReloader(certFile, keyFile string, interval, expireWarnBefore time.Duration) (*certReloader, error) {
	r := &certReloader{
		certFile:         certFile,
		keyFile:          keyFile,
		interval:         interval,
		expireWarnBefore: expireWarnBefore,
	}
	if err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// run 阻塞运行后台检查，直到 ctx 取消。
func (r *certReloader) run(ctx context.Context) {
	if r.interval <= 0 {
		return
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reload()
		}
	}
}

// reload 检查文件是否变化，需要时重新载入。
// 解析失败时保留旧证书（并保持旧 stamp），下个周期自动重试，
// 避免正好撞上 caddy 写文件的瞬间把服务打挂。
func (r *certReloader) reload() error {
	stamp, err := stampOf(r.certFile, r.keyFile)
	if err != nil {
		log.Printf("cert reload: stat 失败: %v (继续使用当前证书)", err)
		return err
	}
	if cur := r.stamps.Load(); cur != nil && *cur == stamp {
		return nil // 未变化
	}

	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		log.Printf("cert reload: 载入 %s 失败: %v (继续使用当前证书，下个周期重试)", r.certFile, err)
		return err
	}
	r.current.Store(&cert)
	r.stamps.Store(&stamp)
	logCertificate(&cert, stamp)
	return nil
}

// getCertificate 作为 tls.Config.GetCertificate 回调。
// Certificates 留空，因此无论客户端是否发送 SNI 都会走这里。
func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if cert := r.current.Load(); cert != nil {
		return cert, nil
	}
	return nil, os.ErrNotExist
}

func logCertificate(cert *tls.Certificate, stamp fileStamp) {
	var name, notAfter string
	if len(cert.Certificate) > 0 && cert.Leaf == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			name, notAfter = leaf.Subject.CommonName, leaf.NotAfter.Format(time.RFC3339)
		}
	}
	if name == "" {
		name = "(未解析)"
	}
	if notAfter == "" {
		notAfter = "(未知)"
	}
	log.Printf("证书已载入: %s  notAfter=%s  crt=%d字节 mtime=%s",
		name, notAfter, stamp.certSize, stamp.certMod.Format(time.RFC3339))
}

// logExpiring 在证书剩余有效期不足时告警。
func (r *certReloader) logExpiring() {
	cert := r.current.Load()
	if cert == nil || len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	if left := time.Until(leaf.NotAfter); left < r.expireWarnBefore {
		log.Printf("警告: 证书 %s 将在 %s 后过期（剩余 %s），请检查 caddy 的 ACME 续期", leaf.Subject.CommonName,
			leaf.NotAfter.Format(time.RFC3339), left.Round(time.Hour))
	}
}
