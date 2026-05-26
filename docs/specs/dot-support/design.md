# Thiết kế Chi tiết: Hỗ trợ DNS-over-TLS (DoT) (Hướng 7)

## 1. Kiến trúc Hệ thống

Cổng DNS-over-TLS (DoT) được tích hợp trực tiếp vào nhị phân `dns-resolver` chạy dưới dạng một goroutine song song với cổng DNS-over-HTTPS (DoH).

```
                 ┌────────────────────────────────────────────────────────┐
                 │                 Safe Zone dns-resolver                 │
                 │                                                        │
 Client (Browser)│ ┌───────────────┐                                      │
 ───────────────┼─► DoH REST Port │ ────────────────────────┐            │
                 │ │    (:8081)    │                         │            │
                 │ └───────────────┘                         ▼            │
                 │                                  ┌──────────────────┐  │  Upstream DoH
 Client (Mobile) │ ┌───────────────┐                │   risk.Policy    │  │ ──────────────►
 ───────────────┼─► DoT TLS Port  │ ───────────────►│  Decision Engine │  │ (Cloudflare)
 (Private DNS)   │ │    (:853)     │                └──────────────────┘  │
                 │ └───────────────┘                         ▲            │
                 │                                           │            │
                 │                                  ┌──────────────────┐  │
                 │                                  │  Local Overrides │  │
                 │                                  └──────────────────┘  │
                 └────────────────────────────────────────────────────────┘
```

---

## 2. Giải pháp TLS: Local Fallback, Production Fail-Fast

Để giúp lập trình viên phát triển cục bộ một cách dễ dàng nhất, hệ thống tự động sinh ra chứng chỉ TLS tự ký khi không cấu hình cert/key. Trong production, nếu người vận hành đã cấu hình `SAFE_ZONE_DNS_DOT_CERT_FILE` hoặc `SAFE_ZONE_DNS_DOT_KEY_FILE` nhưng `tls.LoadX509KeyPair` thất bại, tiến trình fail fast bằng `os.Exit(1)` để tránh việc DoT âm thầm chạy với chứng chỉ không được client tin cậy.

```go
func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Safe Zone Security"},
			CommonName:   "safezone.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}
```

---

## 3. Khởi tạo máy chủ DoT (`dns.Server`)

Sử dụng thư viện `github.com/miekg/dns` để khởi chạy máy chủ TCP bọc TLS:

```go
// Tải chứng chỉ thật nếu được cấu hình; fail fast nếu cấu hình bị lỗi.
var cert tls.Certificate
if certFile != "" || keyFile != "" {
    var err error
    cert, err = tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        log.Printf("failed to load configured TLS keys: %v", err)
        os.Exit(1)
    }
} else {
    log.Println("TLS key files not configured, generating temporary self-signed cert")
    cert, _ = generateSelfSignedCert()
}

tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{cert},
    MinVersion:   tls.VersionTLS12,
}

dotServer := &dns.Server{
    Addr:      dotAddr,
    Net:       "tcp-tls",
    TLSConfig: tlsConfig,
    Handler:   dns.HandlerFunc(resolver.dotHandler),
}
```

---

## 4. Cấu trúc Handler DoT (`resolver.dotHandler`)

Handler DoT sẽ thực hiện các bước sau:
1.  **Rate Limiting Check:** Trích xuất IP client từ connection TLS và kiểm tra qua `dotLimiter`.
2.  **Extract Domain:** Lấy domain truy vấn từ câu hỏi đầu tiên.
3.  **Evaluate Policy:** Gọi `risk.Policy(ctx, domain, clientInfo)`.
4.  **Action Plan:**
    -   Nếu `BLOCK`: Tạo response theo `SAFE_ZONE_DNS_BLOCK_STRATEGY`: `sinkhole`, `nxdomain`, `refused`, hoặc `nullip`.
    -   Nếu `ALLOW`: Đóng gói DNS message gốc thành payload byte thô, forward tới upstream bằng DoH (`forwardDoH`), parse kết quả nhận được và ghi trả lại cho client TLS.

### Tích hợp Rate Limiting thủ công trong DoT Handler:
```go
func (a *app) dotHandler(w dns.ResponseWriter, r *dns.Msg) {
	// Extract Client IP
	clientIP, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		clientIP = w.RemoteAddr().String()
	}

	// Rate Limiting Check
	if a.dotLimiter != nil && !a.dotLimiter.Allow(clientIP) {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeRefused) // Phản hồi lỗi Từ chối do quá tải
		_ = w.WriteMsg(resp)
		return
	}

	if len(r.Question) == 0 {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeFormatError)
		_ = w.WriteMsg(resp)
		return
	}

	questionDomain := strings.TrimSuffix(r.Question[0].Name, ".")
	clientInfo := risk.ClientInfo{IP: clientIP}
	policy := a.risk.Policy(context.Background(), questionDomain, clientInfo)

	if policy.Policy == "block" {
		responseMsg, err := a.blockedDNSMessage(r)
		if err == nil {
			_ = w.WriteMsg(responseMsg)
			return
		}
	}

	// Forward allowed query to upstream via DoH
	wire, err := r.Pack()
	if err != nil {
		sendServfail(w, r)
		return
	}

	responseWire, err := a.forwardDoH(context.Background(), wire)
	if err != nil {
		sendServfail(w, r)
		return
	}

	responseMsg := new(dns.Msg)
	if err := responseMsg.Unpack(responseWire); err != nil {
		sendServfail(w, r)
		return
	}

	_ = w.WriteMsg(responseMsg)
}
```

---

## 5. Phối hợp Uptime & Graceful Shutdown

Sử dụng `errgroup` hoặc phối hợp thủ công qua channel lỗi để theo dõi trạng thái sống của cả 2 server DoH và DoT:

```go
sigCh := make(chan os.Signal, 1)
signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

go func() {
    log.Printf("DoH listening on %s", addr)
    if err := serve.RunHTTPServer(server, shutdownTimeout); err != nil {
        log.Printf("DoH server error: %v", err)
        sigCh <- syscall.SIGTERM
    }
}()

go func() {
    log.Printf("DoT listening on %s", dotAddr)
    if err := dotServer.ListenAndServe(); err != nil && err != dns.ErrServerClosed {
        log.Printf("DoT server error: %v", err)
        sigCh <- syscall.SIGTERM
    }
}()

// Đợi tín hiệu tắt
<-sigCh
log.Println("Shutting down servers...")

ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
defer cancel()

_ = server.Shutdown(ctx)
_ = dotServer.ShutdownContext(ctx)
log.Println("All services stopped successfully.")
```
