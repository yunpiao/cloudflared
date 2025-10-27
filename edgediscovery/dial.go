package edgediscovery

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/net/proxy"
)

// DialEdge makes a TLS connection to a Cloudflare edge node
// 支持通过 SOCKS5 代理连接，如果代理失败会自动降级到直连
func DialEdge(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
) (net.Conn, error) {
	return DialEdgeWithProxy(ctx, timeout, tlsConfig, edgeTCPAddr, localIP, "")
}

// DialEdgeWithProxy makes a TLS connection to a Cloudflare edge node with optional SOCKS5 proxy support
// proxyURL 格式: "socks5://[user:pass@]host:port" 或 "" (不使用代理)
// 如果代理连接失败，会自动降级到直连方式
func DialEdgeWithProxy(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeTCPAddr *net.TCPAddr,
	localIP net.IP,
	proxyURL string,
) (net.Conn, error) {
	// Inherit from parent context so we can cancel (Ctrl-C) while dialing
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()

	var edgeConn net.Conn
	var err error

	// 如果指定了代理，先尝试通过代理连接
	if proxyURL != "" {
		edgeConn, err = dialViaProxy(dialCtx, proxyURL, edgeTCPAddr.String(), localIP)
		if err != nil {
			// 代理失败，记录错误但继续尝试直连
			// 这里可以添加日志记录
			// log.Warn().Err(err).Msg("Proxy connection failed, falling back to direct connection")
		}
	}

	// 如果没有指定代理，或者代理连接失败，则使用直连
	if edgeConn == nil {
		edgeConn, err = dialDirect(dialCtx, edgeTCPAddr.String(), localIP)
		if err != nil {
			return nil, newDialError(err, "DialContext error")
		}
	}

	// 建立 TLS 连接
	tlsEdgeConn := tls.Client(edgeConn, tlsConfig)
	tlsEdgeConn.SetDeadline(time.Now().Add(timeout))

	if err = tlsEdgeConn.Handshake(); err != nil {
		return nil, newDialError(err, "TLS handshake with edge error")
	}
	// clear the deadline on the conn; http2 has its own timeouts
	tlsEdgeConn.SetDeadline(time.Time{})
	return tlsEdgeConn, nil
}

// dialViaProxy 通过 SOCKS5 代理建立连接
func dialViaProxy(ctx context.Context, proxyURL string, address string, localIP net.IP) (net.Conn, error) {
	// 解析代理 URL
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, errors.Wrap(err, "invalid proxy URL")
	}

	// 创建基础 dialer
	var baseDial proxy.Dialer = proxy.Direct
	if localIP != nil {
		// 注意：SOCKS5 代理模式下，localIP 可能不生效
		// 因为实际的出口 IP 是代理服务器的 IP
		baseDial = &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: localIP, Port: 0},
		}
	}

	// 创建代理 dialer
	var auth *proxy.Auth
	if u.User != nil {
		auth = &proxy.Auth{
			User: u.User.Username(),
		}
		if password, ok := u.User.Password(); ok {
			auth.Password = password
		}
	}

	// 获取代理地址和端口
	proxyAddr := u.Host
	if u.Port() == "" {
		// 如果没有指定端口，使用默认的 1080
		proxyAddr = net.JoinHostPort(u.Hostname(), "1080")
	}

	// 创建 SOCKS5 dialer
	proxyDialer, err := proxy.SOCKS5("tcp", proxyAddr, auth, baseDial)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create SOCKS5 dialer")
	}

	// 尝试通过代理连接
	var conn net.Conn
	if contextDialer, ok := proxyDialer.(proxy.ContextDialer); ok {
		conn, err = contextDialer.DialContext(ctx, "tcp", address)
	} else {
		// 降级到普通 Dial（不支持 context）
		conn, err = proxyDialer.Dial("tcp", address)
	}

	if err != nil {
		return nil, errors.Wrap(err, "proxy dial failed")
	}

	return conn, nil
}

// dialDirect 直接建立 TCP 连接（不通过代理）
func dialDirect(ctx context.Context, address string, localIP net.IP) (net.Conn, error) {
	dialer := &net.Dialer{}
	if localIP != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
	}
	return dialer.DialContext(ctx, "tcp", address)
}

// DialError is an error returned from DialEdge
type DialError struct {
	cause error
}

func newDialError(err error, message string) error {
	return DialError{cause: errors.Wrap(err, message)}
}

func (e DialError) Error() string {
	return e.cause.Error()
}

func (e DialError) Cause() error {
	return e.cause
}
