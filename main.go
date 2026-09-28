package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type contextKey string

const isOpenSSLKey contextKey = "isOpenSSL"

func main() {
	addr := flag.String("addr", "0.0.0.0:8443", "监听地址")
	certFile := flag.String("cert", "./certs/whatssl.guage.cool.crt", "证书文件")
	keyFile := flag.String("key", "./certs/whatssl.guage.cool.key", "私钥文件")
	// 证书由 caddy 续期后只写磁盘，这里轮询检测变化并热加载，
	// 不再依赖 cron 每天重启进程。
	certInterval := flag.Duration("cert-reload-interval", time.Minute, "证书文件检查间隔")
	certWarnBefore := flag.Duration("cert-warn-before", 14*24*time.Hour, "证书剩余有效期低于该值时告警")
	// 握手是在 Accept() 里同步完成的，而 http.Server 串行调用 Accept()。
	// 也就是说：一个“连上但不发 ClientHello”的连接会把整个服务的 accept 循环卡死，
	// 后面的正常请求全部排队等它。所以握手必须有时间上限。
	handshakeTimeout := flag.Duration("handshake-timeout", 10*time.Second, "TLS 握手超时")
	flag.Parse()

	reloader, err := newCertReloader(*certFile, *keyFile, *certInterval, *certWarnBefore)
	if err != nil {
		log.Fatalf("初始证书载入失败: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go reloader.run(ctx)
	go warnLoop(ctx, reloader)

	l, err := newTlsListener(*addr, reloader.getCertificate, *handshakeTimeout)
	if err != nil {
		log.Fatal(err)
	}
	httpServer := http.Server{
		Addr:              *addr,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
		Handler:           http.HandlerFunc(detectionHandler),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			isOpenSSL := false
			if tlsConn, ok := c.(*tls.Conn); ok {
				if fConn, ok := tlsConn.NetConn().(*filterConn); ok {
					isOpenSSL = fConn.isOpenSSL
				}
			}

			return context.WithValue(ctx, isOpenSSLKey, isOpenSSL)
		},
	}
	log.Println("listening on", *addr)
	go func() {
		<-ctx.Done()
		log.Println("收到退出信号, 关闭中")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()
	// 之前这里是 panic(httpServer.Serve(l))：任何 accept 错误（fd 耗尽、临时网络错误）
	// 都会让进程直接退出。现在退出码正常交给 systemd，配合 unit 里的 Restart=always 拉起。
	if err := httpServer.Serve(l); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// detectionHandler 输出检测结论。
// 两种结论的文案差异要一眼可辨：旧版 “you are using OpenSSL” 和
// “you are't using OpenSSL” 只差一个 't'，肉眼扫过去极易看错，
// 而这个页面的全部意义就是让人一眼看出结论。
func detectionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	isOpenSSL, _ := r.Context().Value(isOpenSSLKey).(bool)
	if isOpenSSL {
		fmt.Fprint(w, `==================================================
  检测结果: OpenSSL
==================================================
本连接的客户端 TLS 库是 OpenSSL。

常见于: curl / python requests / PHP / Ruby / Node.js 等。
`)
		return
	}
	fmt.Fprint(w, `==================================================
  检测结果: 非 OpenSSL
==================================================
本连接的客户端 TLS 库不是 OpenSSL。

常见于: Chrome / Edge (BoringSSL)、Windows (schannel)、
        Java (JSSE)、Go (crypto/tls) 等。
`)
}

// warnLoop 每天检查一次证书有效期，快到过期时告警。
func warnLoop(ctx context.Context, r *certReloader) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.logExpiring()
		}
	}
}

type filterListener struct {
	net.Listener
	handshakeTimeout time.Duration
}

func (l *filterListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	// 先给握手整个一个 deadline，握手成功后由 tlsListener 清掉。
	if l.handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(l.handshakeTimeout))
	}
	return &filterConn{Conn: conn, buf: &bytes.Buffer{}, done: &atomic.Bool{}}, nil
}

type filterConn struct {
	net.Conn
	buf       *bytes.Buffer
	done      *atomic.Bool
	isOpenSSL bool
}

func (c *filterConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if !c.done.Load() {
		c.buf.Write(b[:n])
	}
	return n, err
}

type tlsListener struct {
	net.Listener
	// conns 是"已握手完成、等待上层取用"的连接队列。
	conns chan net.Conn
	// closed 用于在底层 listener 关闭后唤醒所有阻塞在 Accept 上的调用。
	closed   chan struct{}
	closeOne sync.Once
}

// handshakeConcurrency 限制同时进行中的握手数量。
// 有了它，慢连接堆积到上限后 acceptLoop 会自然暂停 accept（背压），
// 避免大量半开连接把内存/goroutine 吃光。
const handshakeConcurrency = 256

// newTlsListener 只向上层交付"已完成 TLS 握手"的连接。
// getCertificate 由 certReloader 提供，握手热路径不读磁盘。
// handshakeTimeout 是 TLS 握手阶段的时间上限，<=0 表示不限制（不推荐）。
//
// ⚠ 握手不能在 Accept() 里同步做：上层 http.Server 是串行调用 Accept() 的，
// 一条"连上不发 ClientHello"的慢连接会把整个 accept 循环卡住，期间所有新连接
// 都得排队（实测卡满整整一个 handshake-timeout：正常请求耗时 10.01s）。
// 所以这里自己起后台循环 accept，并用独立 goroutine 并发完成握手，
// 握手好的连接排进 conns 交给上层。慢连接只占用它自己的 goroutine。
func newTlsListener(addr string, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), handshakeTimeout time.Duration) (net.Listener, error) {
	tcpL, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	filterL := &filterListener{Listener: tcpL, handshakeTimeout: handshakeTimeout}
	config := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		MaxVersion:     tls.VersionTLS12,
		GetCertificate: getCertificate,
		// 显式只宣告 http/1.1。whatssl 只回一个纯文本响应，没有任何 HTTP/2 framing，
		// 一旦有人误加 h2，客户端协商成功后拿到的是无法解析的流。
		// 注意这只管 TCP；HTTP/3(QUIC) 在 UDP 上，根本不会经过这个进程，
		// 需要在 caddy 侧用 servers :443 { protocols h1 h2 } 关掉。
		NextProtos: []string{"http/1.1"},
		CipherSuites: []uint16{ // 选择aead模式的套件
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
	l := &tlsListener{
		Listener: tls.NewListener(filterL, config),
		conns:    make(chan net.Conn, handshakeConcurrency),
		closed:   make(chan struct{}),
	}
	go l.acceptLoop()
	return l, nil
}

// acceptLoop 串行 accept 原始连接，每条连接交给独立 goroutine 完成握手。
// tls.Listener 的 Accept 只做包装（filterConn + tls.Conn），握手发生在 Handshake()。
func (l *tlsListener) acceptLoop() {
	sem := make(chan struct{}, handshakeConcurrency)
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return // 底层 listener 已关闭
		}
		select {
		case sem <- struct{}{}: // 拿一个并发握手许可，拿不到就自然背压
		case <-l.closed:
			conn.Close()
			return
		}
		go func(c net.Conn) {
			defer func() { <-sem }()
			l.conns <- l.handshake(c)
		}(conn)
	}
}

// handshake 完成单条连接的 TLS 握手，并在此确定检测结果。
func (l *tlsListener) handshake(conn net.Conn) net.Conn {
	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		// 握手失败（含超时）时把错误包成 conn 返回：上层 http.Server 会把它当作
		// 读错误立即关闭这条连接。
		return &errorConn{tlsConn, err}
	}
	filterConn := tlsConn.NetConn().(*filterConn)
	// 握手已完成，握手期的 deadline 完成使命，撤掉，否则正常的慢速 HTTP
	// 交互会被它误杀（HTTP 阶段改由 http.Server 的 ReadHeaderTimeout / IdleTimeout 负责）。
	_ = filterConn.SetDeadline(time.Time{})
	filterConn.done.Store(true)
	record, err := parseFinishedRecord(filterConn.buf)
	if err == nil {
		// OpenSSL的sequence number不是从0开始
		// 但rfc5246要求sequence number从0开始
		// https://www.rfc-editor.org/rfc/rfc5246#page-19
		filterConn.isOpenSSL = !bytes.Equal(record.recordData[:8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
	}
	return tlsConn
}

// Accept 交给上层（http.Server）一条已握手完成的连接。
func (l *tlsListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *tlsListener) Close() error {
	l.closeOne.Do(func() { close(l.closed) })
	return l.Listener.Close()
}

type errorConn struct {
	net.Conn
	err error
}

func (c *errorConn) Read(b []byte) (int, error) {
	return 0, c.err
}

func (c *errorConn) Write(b []byte) (int, error) {
	return 0, c.err
}

func newCert(name string) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		Subject:               pkix.Name{CommonName: name},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(err)
	}
	certOut := &bytes.Buffer{}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyOut := &bytes.Buffer{}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certOut.Bytes(), keyOut.Bytes())
	if err != nil {
		panic(err)
	}
	return cert
}

const recordHeaderLen = 5

const (
	recordTypeChangeCipherSpec = 20
	recordTypeAlert            = 21
	recordTypeHandshake        = 22
	recordTypeApplicationData  = 23
)

const (
	typeHelloRequest        uint8 = 0
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEndOfEarlyData      uint8 = 5
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeServerKeyExchange   uint8 = 12
	typeCertificateRequest  uint8 = 13
	typeServerHelloDone     uint8 = 14
	typeCertificateVerify   uint8 = 15
	typeClientKeyExchange   uint8 = 16
	typeFinished            uint8 = 20
	typeCertificateStatus   uint8 = 22
	typeKeyUpdate           uint8 = 24
)

type recordOrders []struct {
	recordType    byte
	handshakeType byte
	optional      bool
}

type tlsRecord struct {
	recordType uint8
	version    uint16
	recordData []byte
}

func readTlsRecord(reader io.Reader) (*tlsRecord, error) {
	hdr := make([]byte, recordHeaderLen)
	if _, err := io.ReadFull(reader, hdr); err != nil {
		return nil, err
	}
	recordType := hdr[0]
	version := uint16(hdr[1])<<8 | uint16(hdr[2])
	recordLen := int(hdr[3])<<8 | int(hdr[4])

	recordData := make([]byte, recordLen)
	if _, err := io.ReadFull(reader, recordData); err != nil {
		return nil, err
	}
	return &tlsRecord{
		recordType: recordType,
		version:    version,
		recordData: recordData,
	}, nil
}
func parseFinishedRecord(reader io.Reader) (*tlsRecord, error) {
	var orders = recordOrders{
		{
			recordType:    recordTypeHandshake,
			handshakeType: typeClientHello,
		},
		{
			recordType:    recordTypeHandshake,
			handshakeType: typeCertificate,
			optional:      true,
		},
		{
			recordType:    recordTypeHandshake,
			handshakeType: typeClientKeyExchange,
		},
		{
			recordType:    recordTypeHandshake,
			handshakeType: typeCertificateVerify,
			optional:      true,
		},
		{
			recordType: recordTypeChangeCipherSpec,
		},
		{
			recordType: recordTypeHandshake, // Encrypted Handshake Message(Finished)
		},
	}
	orderPos := 0
	for {
		record, err := readTlsRecord(reader)
		if err != nil {
			return nil, err
		}
		for pos := orderPos; pos < len(orders); pos++ {
			o := orders[pos]
			if o.handshakeType != 0 {
				// 需要判断握手类型
				if len(record.recordData) != 0 &&
					record.recordData[0] == o.handshakeType {
					orderPos = pos + 1
					break
				}
			} else {
				orderPos = pos + 1
				break
			}

			if o.optional {
				orderPos = pos + 1
				continue
			} else {
				return nil, fmt.Errorf(
					"invalid record, want %+v, got %d %x,",
					o, record.recordType, record.recordData,
				)
			}
		}
		if orderPos == len(orders) {
			return record, nil
		}
	}

}
