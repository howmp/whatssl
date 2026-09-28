package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// newTestListener 起一个只含 TLS 层的 listener（不套 http.Server），
// 用来单独观察 Accept 的行为。
func newTestListener(t *testing.T, handshakeTimeout time.Duration) net.Listener {
	t.Helper()
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "a", newCert("t.example"))
	r, err := newCertReloader(certFile, keyFile, time.Minute, time.Hour)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	l, err := newTlsListener("127.0.0.1:0", r.getCertificate, handshakeTimeout)
	if err != nil {
		t.Fatalf("newTlsListener: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// 核心回归：握手是在 Accept() 里同步做的，如果连接不发 ClientHello 就会永久阻塞，
// 而 http.Server 是串行调用 Accept() 的 —— 一条慢连接会卡死整个服务。
// 这里验证握手超时能把 Accept 拉回来。
func TestHandshakeTimeoutUnblocksAccept(t *testing.T) {
	l := newTestListener(t, 300*time.Millisecond)

	// 连上但什么都不发。
	silent, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer silent.Close()

	ch := make(chan acceptResult, 1)
	go func() {
		c, err := l.Accept()
		ch <- acceptResult{c, err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("Accept 返回 error 而非 errorConn: %v", res.err)
		}
		ec, ok := res.conn.(*errorConn)
		if !ok {
			t.Fatalf("期望 *errorConn, 实际 %T", res.conn)
		}
		if !errors.Is(ec.err, os.ErrDeadlineExceeded) {
			t.Fatalf("期望超时错误 i/o timeout, 实际 %v", ec.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("握手超时未生效: Accept 仍阻塞, 整个服务会被这条连接卡死")
	}
}

// 超时不能误伤正常连接：握手成功后 deadline 必须被清掉，
// 否则后续的 HTTP 交互会被握手期的 deadline 干掉。
func TestHandshakeDeadlineClearedAfterSuccess(t *testing.T) {
	l := newTestListener(t, 5*time.Second)

	accepted := make(chan acceptResult, 1)
	go func() {
		c, err := l.Accept()
		accepted <- acceptResult{c, err}
	}()

	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})
	if err := conn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	select {
	case res := <-accepted:
		if res.err != nil {
			t.Fatalf("Accept: %v", res.err)
		}
		if _, ok := res.conn.(*errorConn); ok {
			t.Fatal("正常连接不应返回 errorConn")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept 未返回")
	}

	// 握手 deadline 是 5s；如果它没被清掉，这里的写会踩到 deadline。
	time.Sleep(100 * time.Millisecond)
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: t.example\r\n\r\n")); err != nil {
		t.Fatalf("握手成功后写入失败（deadline 可能没被清除）: %v", err)
	}
}

// 这是本次修复的根因回归：握手曾经是在 Accept() 里同步做的，而 http.Server
// 串行调用 Accept()，于是一条不发 ClientHello 的连接会把整个服务卡住
// （线上实测：慢连接挂着时，正常请求耗时 10.01s = 整个 handshake-timeout）。
// 现在握手在独立 goroutine 并发完成，慢连接不得影响正常连接。
func TestSlowConnectionDoesNotBlockNormalOnes(t *testing.T) {
	l := newTestListener(t, 3*time.Second) // 超时故意给得很大，慢连接会一直挂着

	slow, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer slow.Close() // 只连上，不发任何数据

	// 持续从上层 Accept 取连接（模拟 http.Server 的 accept 循环）
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()

	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial normal: %v", err)
	}
	defer raw.Close()
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
	})

	done := make(chan error, 1)
	go func() { done <- conn.Handshake() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("慢连接存在时正常客户端握手失败: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("慢连接仍然在阻塞 accept 循环（正常客户端 1s 内没能完成握手）")
	}

	// 正常连接应该在 1s 内被交给上层
	select {
	case c := <-accepted:
		if _, ok := c.(*errorConn); ok {
			t.Fatal("正常连接不应返回 errorConn")
		}
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("正常连接未在预期时间内交给上层")
	}
}

// listener 关闭后 Accept 应立即返回，而不是永久阻塞。
func TestAcceptUnblocksOnClose(t *testing.T) {
	l := newTestListener(t, time.Second)
	errc := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		errc <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Close 后 Accept 返回 %v, 期望 net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close 后 Accept 仍阻塞")
	}
}

// 文案回归：两种结论必须一眼可辨（旧版只差一个 't'），
// 且 context 里没有标记时默认按“非 OpenSSL”处理，不能误报成“是”。
func TestDetectionHandlerWording(t *testing.T) {
	cases := []struct {
		name    string
		ctxVal  any
		want    string
		notWant string
	}{
		{"openssl", true, "检测结果: OpenSSL", "非 OpenSSL"},
		{"not-openssl", false, "检测结果: 非 OpenSSL", "检测结果: OpenSSL"},
		{"missing-ctx-value", nil, "检测结果: 非 OpenSSL", "检测结果: OpenSSL"},
	}
	bodies := map[string]string{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.ctxVal != nil {
				req = req.WithContext(context.WithValue(req.Context(), isOpenSSLKey, tc.ctxVal))
			}
			rec := httptest.NewRecorder()
			detectionHandler(rec, req)
			body := rec.Body.String()
			if !strings.Contains(body, tc.want) {
				t.Fatalf("输出缺少 %q:\n%s", tc.want, body)
			}
			if strings.Contains(body, tc.notWant) {
				t.Fatalf("输出不应包含 %q:\n%s", tc.notWant, body)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
				t.Fatalf("Content-Type = %q, 中文内容必须是显式 utf-8", ct)
			}
			bodies[tc.name] = body
		})
	}
	// 硬性要求：两种结论不能是“只差一个字符”的关系
	if d := bodies["openssl"]; len(d) == len(bodies["not-openssl"]) &&
		strings.Replace(d, "OpenSSL", "", 1) == strings.Replace(bodies["not-openssl"], "非 OpenSSL", "", 1) {
		t.Fatal("两种文案实质相同, 现场无法一眼区分")
	}
}
