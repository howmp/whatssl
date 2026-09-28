package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCertPair 把自签证书写到 dir 下的 <name>.crt / <name>.key，返回两个路径。
func writeCertPair(t *testing.T, dir, name string, c tls.Certificate) (string, string) {
	t.Helper()
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certFile := filepath.Join(dir, name+".crt")
	keyFile := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func subjectOf(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.Subject.CommonName
}

func mustGet(t *testing.T, r *certReloader) *tls.Certificate {
	t.Helper()
	c, err := r.getCertificate(nil)
	if err != nil {
		t.Fatalf("getCertificate: %v", err)
	}
	return c
}

// startReloader 启动后台检查循环，测试结束自动停止。
func startReloader(t *testing.T, r *certReloader) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go r.run(ctx)
	t.Cleanup(cancel)
}

// waitCN 轮询等待热加载到指定 CN。
func waitCN(t *testing.T, r *certReloader, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if name := subjectOf(t, mustGet(t, r)); name == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("证书未热加载到 %s, 当前 CN=%q", want, subjectOf(t, mustGet(t, r)))
}

func TestReloaderLoadsInitialCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "a", newCert("first.example"))

	r, err := newCertReloader(certFile, keyFile, 5*time.Millisecond, 24*time.Hour)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	if name := subjectOf(t, mustGet(t, r)); name != "first.example" {
		t.Fatalf("got CN %q, want first.example", name)
	}
}

// 核心场景：caddy 续期后无需重启进程即可用上新证书。
// 注意这里不刻意改变文件大小——真实续期出来的证书字节数经常和旧的一致，
// 只按 mtime+size 判断会漏检（这是实现过程中实测到的问题）。
func TestReloaderPicksUpRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "a", newCert("first.example"))

	r, err := newCertReloader(certFile, keyFile, 5*time.Millisecond, 24*time.Hour)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	startReloader(t, r)

	writeCertPair(t, dir, "a", newCert("second.example"))
	waitCN(t, r, "second.example")
}

// 撞上 caddy 正在写文件时（半个文件），不能让已加载的证书被换成空/坏状态。
func TestReloaderKeepsOldCertificateOnBrokenFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "a", newCert("first.example"))

	r, err := newCertReloader(certFile, keyFile, 5*time.Millisecond, 24*time.Hour)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	startReloader(t, r)

	if err := os.WriteFile(certFile, []byte("-----BEGIN CERTIFICATE-----\ntrunc"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // 至少跑过好几个检查周期
	if name := subjectOf(t, mustGet(t, r)); name != "first.example" {
		t.Fatalf("坏文件覆盖了旧证书: CN=%q", name)
	}
}

// 文件恢复后应能自动追上，无需重启进程。
func TestReloaderRecoversAfterFileFixed(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "a", newCert("first.example"))

	r, err := newCertReloader(certFile, keyFile, 5*time.Millisecond, 24*time.Hour)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	startReloader(t, r)

	if err := os.WriteFile(certFile, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if name := subjectOf(t, mustGet(t, r)); name != "first.example" {
		t.Fatalf("坏文件期间丢掉了旧证书: CN=%q", name)
	}

	writeCertPair(t, dir, "a", newCert("recovered.example"))
	waitCN(t, r, "recovered.example")
}

// 文件消失（caddy 原子替换时的瞬时空窗）也不能让正在服务的证书掉链子。
func TestReloaderSurvivesMissingFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeCertPair(t, dir, "a", newCert("first.example"))

	r, err := newCertReloader(certFile, keyFile, 5*time.Millisecond, 24*time.Hour)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	startReloader(t, r)

	if err := os.Remove(certFile); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if name := subjectOf(t, mustGet(t, r)); name != "first.example" {
		t.Fatalf("文件消失后旧证书被丢弃: CN=%q", name)
	}
}

func TestNewCertReloaderFailsWhenCertMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := newCertReloader(filepath.Join(dir, "nope.crt"), filepath.Join(dir, "nope.key"), time.Minute, time.Hour)
	if err == nil {
		t.Fatal("期望初始加载失败, 实际成功")
	}
}
