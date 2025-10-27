// Package supervisor 负责管理和监督 cloudflared 隧道连接的生命周期
// 它处理与 Cloudflare 边缘网络的连接建立、维护、故障恢复和协议降级等核心功能
package supervisor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"

	"github.com/cloudflare/cloudflared/client"
	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/edgediscovery"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	"github.com/cloudflare/cloudflared/fips"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/ingress/origins"
	"github.com/cloudflare/cloudflared/management"
	"github.com/cloudflare/cloudflared/orchestration"
	quicpogs "github.com/cloudflare/cloudflared/quic"
	v3 "github.com/cloudflare/cloudflared/quic/v3"
	"github.com/cloudflare/cloudflared/retry"
	"github.com/cloudflare/cloudflared/signal"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/cloudflare/cloudflared/tunnelstate"
)

const (
	// dialTimeout 定义了建立边缘连接的超时时间
	dialTimeout = 15 * time.Second
)

// TunnelConfig 包含了隧道运行所需的所有配置参数
// 这个结构体集中管理了客户端配置、网络参数、协议选择、安全设置等
type TunnelConfig struct {
	// 客户端相关配置
	ClientConfig  *client.Config // 客户端配置，包含认证信息等
	GracePeriod   time.Duration  // 优雅关闭的等待时间
	CloseConnOnce *sync.Once     // 确保连接信号只关闭一次的同步原语

	// 边缘网络配置
	EdgeAddrs     []string                   // 边缘节点地址列表
	Region        string                     // 指定的区域
	EdgeIPVersion allregions.ConfigIPVersion // IP版本配置（IPv4/IPv6）
	EdgeBindAddr  net.IP                     // 本地绑定的IP地址
	EdgeProxyURL  string                     // SOCKS5 代理 URL（可选），格式: socks5://[user:pass@]host:port，失败时自动降级到直连
	HAConnections int                        // 高可用连接数量

	// 运行状态配置
	IsAutoupdated   bool       // 是否启用自动更新
	LBPool          string     // 负载均衡池名称
	Tags            []pogs.Tag // 隧道标签
	RunFromTerminal bool       // 是否从终端运行

	// 日志配置
	Log          *zerolog.Logger // 通用日志记录器
	LogTransport *zerolog.Logger // 传输层日志记录器

	// 监控和版本
	Observer        *connection.Observer // 连接观察者，用于监控连接状态
	ReportedVersion string               // 上报的版本号

	// 重试配置
	Retries            uint  // 最大重试次数
	MaxEdgeAddrRetries uint8 // 边缘地址最大重试次数

	// 安全配置
	NeedPQ bool // 是否需要后量子加密

	// 隧道属性
	NamedTunnel      *connection.TunnelProperties        // 命名隧道的属性
	ProtocolSelector connection.ProtocolSelector         // 协议选择器（QUIC/HTTP2）
	EdgeTLSConfigs   map[connection.Protocol]*tls.Config // 各协议的TLS配置

	// 服务配置
	ICMPRouterServer    ingress.ICMPRouterServer     // ICMP路由服务器
	OriginDNSService    *origins.DNSResolverService  // 源站DNS解析服务
	OriginDialerService *ingress.OriginDialerService // 源站拨号服务

	// 超时配置
	RPCTimeout         time.Duration // RPC调用超时时间
	WriteStreamTimeout time.Duration // 写流超时时间

	// QUIC 特定配置
	DisableQUICPathMTUDiscovery         bool   // 是否禁用QUIC路径MTU发现
	QUICConnectionLevelFlowControlLimit uint64 // QUIC连接级流控限制
	QUICStreamLevelFlowControlLimit     uint64 // QUIC流级流控限制
}

// connectionOptions 根据源站本地地址和之前的尝试次数创建连接选项快照
// originLocalAddr: 源站本地地址（host:port格式）
// previousAttempts: 之前的连接尝试次数
// 返回: 连接选项的快照，用于本次连接尝试
func (c *TunnelConfig) connectionOptions(originLocalAddr string, previousAttempts uint8) *client.ConnectionOptionsSnapshot {
	// 尝试解析源站IP地址，但即使失败也不报错，因为这只是一个信息字段
	host, _, _ := net.SplitHostPort(originLocalAddr)
	originIP := net.ParseIP(host)
	return c.ClientConfig.ConnectionOptionsSnapshot(originIP, previousAttempts)
}

// StartTunnelDaemon 启动隧道守护进程
// 这是启动整个隧道服务的入口函数，它会创建一个Supervisor并运行它
// ctx: 上下文，用于控制整个守护进程的生命周期
// config: 隧道配置
// orchestrator: 编排器，负责协调各个组件
// connectedSignal: 连接成功信号，用于通知外部已建立连接
// reconnectCh: 重连信号通道
// graceShutdownC: 优雅关闭信号通道
// 返回: 如果启动或运行过程中出错，返回错误信息
func StartTunnelDaemon(
	ctx context.Context,
	config *TunnelConfig,
	orchestrator *orchestration.Orchestrator,
	connectedSignal *signal.Signal,
	reconnectCh chan ReconnectSignal,
	graceShutdownC <-chan struct{},
) error {
	s, err := NewSupervisor(config, orchestrator, reconnectCh, graceShutdownC)
	if err != nil {
		return err
	}
	return s.Run(ctx, connectedSignal)
}

// ConnectivityError 表示连接性错误
// 用于标识网络连接问题，并追踪是否已达到最大重试次数
type ConnectivityError struct {
	reachedMaxRetries bool // 是否已达到最大重试次数
}

// NewConnectivityError 创建一个新的连接性错误
// hasReachedMaxRetries: 指示是否已达到最大重试次数
// 返回: ConnectivityError实例指针
func NewConnectivityError(hasReachedMaxRetries bool) *ConnectivityError {
	return &ConnectivityError{
		reachedMaxRetries: hasReachedMaxRetries,
	}
}

// Error 实现error接口，返回错误描述字符串
func (e *ConnectivityError) Error() string {
	return fmt.Sprintf("connectivity error - reached max retries: %t", e.HasReachedMaxRetries())
}

// HasReachedMaxRetries 检查是否已达到最大重试次数
// 返回: true表示已达到最大重试次数，false表示还可以继续重试
func (e *ConnectivityError) HasReachedMaxRetries() bool {
	return e.reachedMaxRetries
}

// EdgeAddrHandler 提供了一个机制来在ServeTunnel中切换不同的错误处理行为
// 用于处理尝试建立边缘连接时的错误
type EdgeAddrHandler interface {
	// ShouldGetNewAddress 检查边缘连接错误并决定是否需要更换边缘地址
	// 同时判断该错误应被识别为连接性错误还是一般应用错误
	// connIndex: 连接索引
	// err: 发生的错误
	// 返回: needsNewAddress表示是否需要新地址，connectivityError表示连接性错误
	ShouldGetNewAddress(connIndex uint8, err error) (needsNewAddress bool, connectivityError error)
}

// NewIPAddrFallback 创建一个新的IP地址回退处理器
// maxRetries: 每个连接索引允许的最大重试次数
// 返回: ipAddrFallback实例指针
func NewIPAddrFallback(maxRetries uint8) *ipAddrFallback {
	return &ipAddrFallback{
		retriesByConnIndex: make(map[uint8]uint8),
		maxRetries:         maxRetries,
	}
}

// ipAddrFallback 对特定的边缘连接错误有更多的回退到新地址的条件
// 这意味着该处理器会在更多情况下（如重复连接注册和边缘QUIC拨号错误）返回连接性错误
type ipAddrFallback struct {
	m                  sync.Mutex      // 互斥锁，保护并发访问
	retriesByConnIndex map[uint8]uint8 // 记录每个连接索引的重试次数
	maxRetries         uint8           // 最大重试次数
}

// ShouldGetNewAddress 实现EdgeAddrHandler接口
// 根据错误类型决定是否需要切换到新的边缘地址
// connIndex: 连接索引
// err: 发生的错误
// 返回: needsNewAddress表示是否需要新地址，connectivityError表示连接性错误
func (f *ipAddrFallback) ShouldGetNewAddress(connIndex uint8, err error) (needsNewAddress bool, connectivityError error) {
	f.m.Lock()
	defer f.m.Unlock()
	switch err.(type) {
	case nil: // 没有错误，保持当前IP地址
	// 如果是QUIC空闲超时错误或重复连接注册错误，尝试下一个地址
	// DupConnRegisterTunnelError 也需要获取新的IP地址
	case connection.DupConnRegisterTunnelError,
		*quic.IdleTimeoutError:
		return true, nil
	// 网络问题应立即使用新地址重试，并报告为连接性错误
	case edgediscovery.DialError, *connection.EdgeQuicDialError:
		if f.retriesByConnIndex[connIndex] >= f.maxRetries {
			// 达到最大重试次数，重置计数器并返回连接性错误
			f.retriesByConnIndex[connIndex] = 0
			return true, NewConnectivityError(true)
		}
		// 增加重试计数
		f.retriesByConnIndex[connIndex]++
		return true, NewConnectivityError(false)
	default: // 其他错误，保持当前IP地址
	}
	return false, nil
}

// EdgeTunnelServer 边缘隧道服务器，负责管理与Cloudflare边缘网络的连接
// 它处理连接的建立、维护、重连和协议降级等核心功能
type EdgeTunnelServer struct {
	config            *TunnelConfig               // 隧道配置
	orchestrator      *orchestration.Orchestrator // 编排器，协调各组件工作
	sessionManager    v3.SessionManager           // V3协议会话管理器
	datagramMetrics   v3.Metrics                  // 数据报指标收集
	edgeAddrHandler   EdgeAddrHandler             // 边缘地址处理器，决定何时切换地址
	edgeAddrs         *edgediscovery.Edge         // 边缘地址发现服务
	edgeBindAddr      net.IP                      // 本地绑定地址
	reconnectCh       chan ReconnectSignal        // 重连信号通道
	gracefulShutdownC <-chan struct{}             // 优雅关闭信号通道
	tracker           *tunnelstate.ConnTracker    // 连接状态追踪器

	connAwareLogger *ConnAwareLogger // 连接感知日志记录器
}

// TunnelServer 隧道服务器接口，定义了服务隧道连接的基本方法
type TunnelServer interface {
	// Serve 为单个隧道连接提供服务
	// ctx: 上下文
	// connIndex: 连接索引
	// protocolFallback: 协议降级处理器
	// connectedSignal: 连接成功信号
	// 返回: 如果发生错误则返回错误信息
	Serve(ctx context.Context, connIndex uint8, protocolFallback *protocolFallback, connectedSignal *signal.Signal) error
}

// Serve 实现TunnelServer接口，为单个隧道连接提供服务
// 这个方法管理整个连接的生命周期，包括地址获取、连接建立、错误处理和重试逻辑
// ctx: 上下文，用于控制连接的生命周期
// connIndex: 连接索引，用于标识该连接在HA连接池中的位置
// protocolFallback: 协议降级处理器，管理协议选择和退避策略
// connectedSignal: 连接成功信号，用于通知外部连接已建立
// 返回: 如果发生错误则返回错误信息
func (e *EdgeTunnelServer) Serve(ctx context.Context, connIndex uint8, protocolFallback *protocolFallback, connectedSignal *signal.Signal) error {
	// 增加高可用连接计数
	haConnections.Inc()
	defer haConnections.Dec()

	// 创建一个布尔熔断器，用于跟踪连接是否成功建立
	connectedFuse := newBooleanFuse()
	go func() {
		// 当连接成功时，通知外部
		if connectedFuse.Await() {
			connectedSignal.Notify()
		}
	}()
	// 确保如果在连接前返回，上面的goroutine会终止
	defer connectedFuse.Fuse(false)

	// 获取与连接索引关联的边缘IP地址
	addr, err := e.edgeAddrs.GetAddr(int(connIndex))
	switch err.(type) {
	case nil: // 没有错误
	case edgediscovery.ErrNoAddressesLeft:
		// 没有可用的地址了
		return err
	default:
		return err
	}

	// 创建带有连接上下文信息的日志记录器
	logger := e.config.Log.With().
		Int(management.EventTypeKey, int(management.Cloudflared)).
		IPAddr(connection.LogFieldIPAddress, addr.UDP.IP).
		Uint8(connection.LogFieldConnIndex, connIndex).
		Logger()
	connLog := e.connAwareLogger.ReplaceLogger(&logger)

	// 每个连接保持自己的协议副本，因为单个连接可能会在特定的边缘节点
	// 不支持新协议时降级到另一个协议
	// 每个连接也可以有自己的IP版本，因为单个连接可能会降级到另一个IP版本
	err, shouldFallbackProtocol := e.serveTunnel(
		ctx,
		connLog,
		addr,
		connIndex,
		connectedFuse,
		protocolFallback,
		protocolFallback.protocol,
	)

	// 检查连接错误是否来自主机的IP问题或建立到边缘的连接问题
	// 如果是，则轮换IP地址
	shouldRotateEdgeIP, cErr := e.edgeAddrHandler.ShouldGetNewAddress(connIndex, err)
	if shouldRotateEdgeIP {
		// 轮换IP，强制内部状态为连接索引分配新的IP
		if _, err := e.edgeAddrs.GetDifferentAddr(int(connIndex), true); err != nil {
			return err
		}

		// 此外，如果这是一个连接性错误，并且我们已经用尽了可配置的最大边缘IP轮换次数，
		// 那么在下一次迭代运行时降级协议
		connectivityErr, ok := cErr.(*ConnectivityError)
		if ok {
			shouldFallbackProtocol = connectivityErr.HasReachedMaxRetries()
		}
	}

	// 设置连接正在重连，并记录下一次重试的退避时间
	duration, ok := protocolFallback.GetMaxBackoffDuration(ctx)
	if !ok {
		return err
	}
	e.config.Observer.SendReconnect(connIndex)
	connLog.Logger().Info().Msgf("Retrying connection in up to %s", duration)

	select {
	case <-ctx.Done():
		// 上下文已取消
		return ctx.Err()
	case <-e.gracefulShutdownC:
		// 收到优雅关闭信号
		return nil
	case <-protocolFallback.BackoffTimer():
		// 退避定时器到期，决定是否需要降级协议
		// 如果不需要降级协议，直接返回。否则，为下一次方法调用设置新协议
		if !shouldFallbackProtocol {
			return err
		}

		// 如果单个连接已经使用当前协议连接成功，我们知道不需要降级到不同的协议
		if e.tracker.HasConnectedWith(e.config.ProtocolSelector.Current()) {
			return err
		}

		// 选择下一个协议
		if !selectNextProtocol(
			connLog.Logger(),
			protocolFallback,
			e.config.ProtocolSelector,
			err,
		) {
			return err
		}
	}

	return err
}

// protocolFallback 是对backoffHandler的包装，当退避达到最大重试次数时会尝试降级选项
// 它管理协议选择和退避策略
type protocolFallback struct {
	retry.BackoffHandler                     // 退避处理器
	protocol             connection.Protocol // 当前使用的协议
	inFallback           bool                // 是否处于降级状态
}

// reset 重置协议降级状态
// 清除退避计时器并标记为非降级状态
func (pf *protocolFallback) reset() {
	pf.ResetNow()
	pf.inFallback = false
}

// fallback 执行协议降级
// fallback: 要降级到的协议
func (pf *protocolFallback) fallback(fallback connection.Protocol) {
	pf.ResetNow()
	pf.protocol = fallback
	pf.inFallback = true
}

// selectNextProtocol 为下一次重试迭代选择连接协议
// 根据错误原因和重试次数决定是否需要切换协议或降级
// connLog: 日志记录器
// protocolBackoff: 协议降级处理器
// selector: 协议选择器
// cause: 导致重试的错误原因
// 返回: true表示能够选择协议并继续重试，false表示已无选项应停止重试
func selectNextProtocol(
	connLog *zerolog.Logger,
	protocolBackoff *protocolFallback,
	selector connection.ProtocolSelector,
	cause error,
) bool {
	// 检查QUIC是否损坏（无法正常工作）
	isQuicBroken := isQuicBroken(cause)
	_, hasFallback := selector.Fallback()

	// 如果达到最大重试次数，或者有降级选项且QUIC损坏，则尝试降级
	if protocolBackoff.ReachedMaxRetries() || (hasFallback && isQuicBroken) {
		if isQuicBroken {
			// 记录QUIC连接问题的警告信息
			connLog.Warn().Msg("If this log occurs persistently, and cloudflared is unable to connect to " +
				"Cloudflare Network with `quic` protocol, then most likely your machine/network is getting its egress " +
				"UDP to port 7844 (or others) blocked or dropped. Make sure to allow egress connectivity as per " +
				"https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/configuration/ports-and-ips/\n" +
				"If you are using private routing to this Tunnel, then ICMP, UDP (and Private DNS Resolution) will not work " +
				"unless your cloudflared can connect with Cloudflare Network with `quic`.")
		}

		// 获取降级协议
		fallback, hasFallback := selector.Fallback()
		if !hasFallback {
			// 没有降级选项，停止重试
			return false
		}
		// 已经在使用降级协议，没有必要再重试
		if protocolBackoff.protocol == fallback {
			return false
		}
		connLog.Info().Msgf("Switching to fallback protocol %s", fallback)
		protocolBackoff.fallback(fallback)
	} else if !protocolBackoff.inFallback {
		// 如果不在降级状态，检查是否需要更新当前协议
		current := selector.Current()
		if protocolBackoff.protocol != current {
			protocolBackoff.protocol = current
			connLog.Info().Msgf("Changing protocol to %s", current)
		}
	}
	return true
}

// isQuicBroken 检查错误是否表明QUIC协议无法正常工作
// 通过检查特定的错误类型来判断QUIC是否损坏
// cause: 要检查的错误
// 返回: true表示QUIC损坏，false表示QUIC可能仍然可用
func isQuicBroken(cause error) bool {
	// 检查是否是QUIC空闲超时错误
	var idleTimeoutError *quic.IdleTimeoutError
	if errors.As(cause, &idleTimeoutError) {
		return true
	}

	// 检查是否是QUIC传输错误，且错误信息包含"operation not permitted"
	// 这通常表示UDP流量被防火墙阻止
	var transportError *quic.TransportError
	if errors.As(cause, &transportError) && strings.Contains(cause.Error(), "operation not permitted") {
		return true
	}

	return false
}

// serveTunnel 运行单个隧道连接，在优雅关闭时返回nil
// 发生错误时返回一个标志，指示错误是否可以重试
// ctx: 上下文
// connLog: 连接感知日志记录器
// addr: 边缘地址
// connIndex: 连接索引
// fuse: 布尔熔断器，用于追踪连接状态
// backoff: 协议降级处理器
// protocol: 要使用的协议
// 返回: err为错误信息，recoverable表示错误是否可恢复（可重试）
func (e *EdgeTunnelServer) serveTunnel(
	ctx context.Context,
	connLog *ConnAwareLogger,
	addr *allregions.EdgeAddr,
	connIndex uint8,
	fuse *booleanFuse,
	backoff *protocolFallback,
	protocol connection.Protocol,
) (err error, recoverable bool) {
	// 将panic视为可恢复的错误
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			err, ok = r.(error)
			if !ok {
				err = fmt.Errorf("ServeTunnel: %v", r)
			}
			err = errors.Wrapf(err, "stack trace: %s", string(debug.Stack()))
			recoverable = true
		}
	}()

	// 确保在函数退出时发送断开连接通知
	defer e.config.Observer.SendDisconnect(connIndex)
	err, recoverable = e.serveConnection(
		ctx,
		connLog,
		addr,
		connIndex,
		fuse,
		backoff,
		protocol,
	)

	// 根据错误类型进行不同的处理
	if err != nil {
		switch err := err.(type) {
		case connection.DupConnRegisterTunnelError:
			// 重复连接注册错误
			connLog.ConnAwareLogger().Err(err).Msg("Unable to establish connection.")
			// 不再重试此连接，让supervisor选择新地址
			return err, false
		case connection.ServerRegisterTunnelError:
			// 服务器端注册隧道错误
			connLog.ConnAwareLogger().Err(err).Msg("Register tunnel error from server side")
			// 不要将服务器返回的注册错误发送到Sentry，它们已在服务器端记录
			return err.Cause, !err.Permanent
		case *connection.EdgeQuicDialError:
			// 边缘QUIC拨号错误，不可恢复
			return err, false
		case ReconnectSignal:
			// 收到重连信号
			connLog.Logger().Info().
				IPAddr(connection.LogFieldIPAddress, addr.UDP.IP).
				Uint8(connection.LogFieldConnIndex, connIndex).
				Msgf("Restarting connection due to reconnect signal in %s", err.Delay)
			err.DelayBeforeReconnect()
			return err, true
		default:
			// 处理其他错误
			if err == context.Canceled {
				// 上下文已取消，记录调试信息
				connLog.Logger().Debug().Err(err).Msgf("Serve tunnel error")
				return err, false
			}
			connLog.ConnAwareLogger().Err(err).Msgf("Serve tunnel error")
			// 检查是否为不可恢复的错误
			_, permanent := err.(unrecoverableError)
			return err, !permanent
		}
	}
	return nil, false
}

// serveConnection 为单个连接提供服务，处理具体的协议连接逻辑
// 根据协议类型（QUIC或HTTP2）建立不同的连接
// ctx: 上下文
// connLog: 连接感知日志记录器
// addr: 边缘地址
// connIndex: 连接索引
// fuse: 布尔熔断器
// backoff: 协议降级处理器
// protocol: 要使用的协议
// 返回: err为错误信息，recoverable表示错误是否可恢复
func (e *EdgeTunnelServer) serveConnection(
	ctx context.Context,
	connLog *ConnAwareLogger,
	addr *allregions.EdgeAddr,
	connIndex uint8,
	fuse *booleanFuse,
	backoff *protocolFallback,
	protocol connection.Protocol,
) (err error, recoverable bool) {
	// 创建连接熔断器，结合布尔熔断器和协议降级处理器
	connectedFuse := &connectedFuse{
		fuse:    fuse,
		backoff: backoff,
	}
	// 创建控制流，用于管理隧道的控制消息
	controlStream := connection.NewControlStream(
		e.config.Observer,
		connectedFuse,
		e.config.NamedTunnel,
		connIndex,
		addr.UDP.IP,
		nil,
		e.config.RPCTimeout,
		e.gracefulShutdownC,
		e.config.GracePeriod,
		protocol,
	)

	// 根据协议类型选择不同的连接方式
	switch protocol {
	case connection.QUIC:
		// 使用QUIC协议
		// nolint: gosec
		connOptions := e.config.connectionOptions(addr.UDP.String(), uint8(backoff.Retries()))
		// nolint: zerologlint
		connOptions.LogFields(connLog.Logger().Debug().Uint8(connection.LogFieldConnIndex, connIndex)).Msgf("Tunnel connection options")
		return e.serveQUIC(ctx,
			addr.UDP.AddrPort(),
			connLog,
			connOptions,
			controlStream,
			connIndex)

	case connection.HTTP2:
		// 使用HTTP2协议
		// 首先建立到边缘的TLS连接，支持通过 SOCKS5 代理（失败时自动降级到直连）
		edgeConn, err := edgediscovery.DialEdgeWithProxy(ctx, dialTimeout, e.config.EdgeTLSConfigs[protocol], addr.TCP, e.edgeBindAddr, e.config.EdgeProxyURL)
		if err != nil {
			connLog.ConnAwareLogger().Err(err).Msg("Unable to establish connection with Cloudflare edge")
			return err, true
		}

		// nolint: gosec
		connOptions := e.config.connectionOptions(edgeConn.LocalAddr().String(), uint8(backoff.Retries()))
		// nolint: zerologlint
		connOptions.LogFields(connLog.Logger().Debug().Uint8(connection.LogFieldConnIndex, connIndex)).Msgf("Tunnel connection options")
		if err := e.serveHTTP2(
			ctx,
			connLog,
			edgeConn,
			connOptions,
			controlStream,
			connIndex,
		); err != nil {
			return err, false
		}

	default:
		// 无效的协议选择
		return fmt.Errorf("invalid protocol selected: %s", protocol), false
	}
	return
}

// unrecoverableError 表示不可恢复的错误
// 这种错误类型表明连接无法通过重试来恢复
type unrecoverableError struct {
	err error // 底层错误
}

// Error 实现error接口
func (r unrecoverableError) Error() string {
	return r.err.Error()
}

// serveHTTP2 使用HTTP2协议为连接提供服务
// ctx: 上下文
// connLog: 连接感知日志记录器
// tlsServerConn: TLS服务器连接
// connOptions: 连接选项快照
// controlStreamHandler: 控制流处理器
// connIndex: 连接索引
// 返回: 如果发生错误则返回错误信息
func (e *EdgeTunnelServer) serveHTTP2(
	ctx context.Context,
	connLog *ConnAwareLogger,
	tlsServerConn net.Conn,
	connOptions *client.ConnectionOptionsSnapshot,
	controlStreamHandler connection.ControlStreamHandler,
	connIndex uint8,
) error {
	// 检查后量子加密模式
	pqMode := connOptions.FeatureSnapshot.PostQuantum
	if pqMode == features.PostQuantumStrict {
		// HTTP/2传输不支持后量子加密
		return unrecoverableError{errors.New("HTTP/2 transport does not support post-quantum")}
	}

	connLog.Logger().Debug().Msgf("Connecting via http2")
	// 创建HTTP2连接
	h2conn := connection.NewHTTP2Connection(
		tlsServerConn,
		e.orchestrator,
		connOptions,
		e.config.Observer,
		connIndex,
		controlStreamHandler,
		e.config.Log,
	)

	// 使用errgroup并发运行服务和监听重连信号
	errGroup, serveCtx := errgroup.WithContext(ctx)
	errGroup.Go(func() error {
		// 运行HTTP2连接服务
		return h2conn.Serve(serveCtx)
	})

	errGroup.Go(func() error {
		// 监听重连信号和优雅关闭信号
		err := listenReconnect(serveCtx, e.reconnectCh, e.gracefulShutdownC)
		if err != nil {
			// 强制断开连接（仅用于测试）
			// errgroup将为h2conn.Serve返回context canceled
			connLog.Logger().Debug().Msg("Forcefully breaking http2 connection")
		}
		return err
	})

	// 等待所有goroutine完成
	return errGroup.Wait()
}

// serveQUIC 使用QUIC协议为连接提供服务
// ctx: 上下文
// edgeAddr: 边缘地址（IP:端口）
// connLogger: 连接感知日志记录器
// connOptions: 连接选项快照
// controlStreamHandler: 控制流处理器
// connIndex: 连接索引
// 返回: err为错误信息，recoverable表示错误是否可恢复
func (e *EdgeTunnelServer) serveQUIC(
	ctx context.Context,
	edgeAddr netip.AddrPort,
	connLogger *ConnAwareLogger,
	connOptions *client.ConnectionOptionsSnapshot,
	controlStreamHandler connection.ControlStreamHandler,
	connIndex uint8,
) (err error, recoverable bool) {
	// 获取QUIC协议的TLS配置
	tlsConfig := e.config.EdgeTLSConfigs[connection.QUIC]

	// 根据后量子加密模式和FIPS模式确定曲线偏好
	pqMode := connOptions.FeatureSnapshot.PostQuantum
	curvePref, err := curvePreference(pqMode, fips.IsFipsEnabled(), tlsConfig.CurvePreferences)
	if err != nil {
		connLogger.ConnAwareLogger().Err(err).Msgf("failed to get curve preferences")
		return err, true
	}

	connLogger.Logger().Info().Msgf("Tunnel connection curve preferences: %v", curvePref)

	tlsConfig.CurvePreferences = curvePref

	// quic-go 0.44将初始包大小默认增加到1280，这会导致通过WARP运行隧道的问题
	// 因为WARP的MTU是1280
	var initialPacketSize uint16 = 1252
	if edgeAddr.Addr().Is4() {
		// IPv4地址使用更小的包大小
		initialPacketSize = 1232
	}

	// 创建QUIC配置
	quicConfig := &quic.Config{
		HandshakeIdleTimeout:       quicpogs.HandshakeIdleTimeout,                            // 握手空闲超时
		MaxIdleTimeout:             quicpogs.MaxIdleTimeout,                                  // 最大空闲超时
		KeepAlivePeriod:            quicpogs.MaxIdlePingPeriod,                               // 保活周期
		MaxIncomingStreams:         quicpogs.MaxIncomingStreams,                              // 最大入站流数量
		MaxIncomingUniStreams:      quicpogs.MaxIncomingStreams,                              // 最大入站单向流数量
		EnableDatagrams:            true,                                                     // 启用数据报
		Tracer:                     quicpogs.NewClientTracer(connLogger.Logger(), connIndex), // 跟踪器
		DisablePathMTUDiscovery:    e.config.DisableQUICPathMTUDiscovery,                     // 是否禁用路径MTU发现
		MaxConnectionReceiveWindow: e.config.QUICConnectionLevelFlowControlLimit,             // 连接级接收窗口
		MaxStreamReceiveWindow:     e.config.QUICStreamLevelFlowControlLimit,                 // 流级接收窗口
		InitialPacketSize:          initialPacketSize,                                        // 初始包大小
	}

	// 拨号建立到边缘的QUIC连接
	conn, err := connection.DialQuic(
		ctx,
		quicConfig,
		tlsConfig,
		edgeAddr,
		e.edgeBindAddr,
		connIndex,
		connLogger.Logger(),
	)
	if err != nil {
		connLogger.ConnAwareLogger().Err(err).Msgf("Failed to dial a quic connection")

		// 将错误报告到Sentry（如果符合条件）
		e.reportErrorToSentry(err, connOptions.FeatureSnapshot.PostQuantum)
		return err, true
	}

	// 根据数据报版本创建相应的会话管理器
	var datagramSessionManager connection.DatagramSessionHandler
	if connOptions.FeatureSnapshot.DatagramVersion == features.DatagramV3 {
		// 使用V3版本的数据报连接
		datagramSessionManager = connection.NewDatagramV3Connection(
			ctx,
			conn,
			e.sessionManager,
			e.config.ICMPRouterServer,
			connIndex,
			e.datagramMetrics,
			connLogger.Logger(),
		)
	} else {
		// 使用V2版本的数据报连接
		datagramSessionManager = connection.NewDatagramV2Connection(
			ctx,
			conn,
			e.config.OriginDialerService,
			e.config.ICMPRouterServer,
			connIndex,
			e.config.RPCTimeout,
			e.config.WriteStreamTimeout,
			e.orchestrator.GetFlowLimiter(),
			connLogger.Logger(),
		)
	}

	// 将quic.Connection包装为TunnelConnection
	tunnelConn := connection.NewTunnelConnection(
		ctx,
		conn,
		connIndex,
		e.orchestrator,
		datagramSessionManager,
		controlStreamHandler,
		connOptions,
		e.config.RPCTimeout,
		e.config.WriteStreamTimeout,
		e.config.GracePeriod,
		connLogger.Logger(),
	)

	// 为隧道连接提供服务
	errGroup, serveCtx := errgroup.WithContext(ctx)
	errGroup.Go(func() error {
		// 运行隧道连接服务
		err := tunnelConn.Serve(serveCtx)
		if err != nil {
			connLogger.ConnAwareLogger().Err(err).Msg("failed to serve tunnel connection")
		}
		return err
	})

	errGroup.Go(func() error {
		// 监听重连信号和优雅关闭信号
		err := listenReconnect(serveCtx, e.reconnectCh, e.gracefulShutdownC)
		if err != nil {
			// 强制断开连接（仅用于测试）
			// errgroup将为tunnelConn.Serve返回context canceled
			connLogger.Logger().Debug().Msg("Forcefully breaking tunnel connection")
		}
		return err
	})

	// 等待所有goroutine完成
	return errGroup.Wait(), false
}

// reportErrorToSentry 是一个辅助函数，用于处理和验证错误是否应该报告到Sentry
// 只有在特定条件下（FIPS启用、后量子严格模式、加密错误）才会报告
// err: 要检查的错误
// pqMode: 后量子加密模式
func (e *EdgeTunnelServer) reportErrorToSentry(err error, pqMode features.PostQuantumMode) {
	dialErr, ok := err.(*connection.EdgeQuicDialError)
	if ok {
		// TransportError提供了Unwrap函数，但err可能并不总是被设置
		transportErr, ok := dialErr.Cause.(*quic.TransportError)
		if ok &&
			transportErr.ErrorCode.IsCryptoError() &&
			fips.IsFipsEnabled() &&
			pqMode == features.PostQuantumStrict {
			// 仅在使用FIPS、后量子严格模式且错误是由EdgeQuicDialError报告的加密错误时
			// 才报告到Sentry
			sentry.CaptureException(err)
		}
	}
}

// listenReconnect 监听重连信号、优雅关闭信号或上下文取消
// 这个函数用于在连接服务过程中响应外部控制信号
// ctx: 上下文
// reconnectCh: 重连信号通道
// gracefulShutdownCh: 优雅关闭信号通道
// 返回: 重连信号或nil（如果是优雅关闭或上下文取消）
func listenReconnect(ctx context.Context, reconnectCh <-chan ReconnectSignal, gracefulShutdownCh <-chan struct{}) error {
	select {
	case reconnect := <-reconnectCh:
		// 收到重连信号
		return reconnect
	case <-gracefulShutdownCh:
		// 收到优雅关闭信号
		return nil
	case <-ctx.Done():
		// 上下文已取消
		return nil
	}
}

// connectedFuse 连接熔断器，结合布尔熔断器和协议降级处理器
// 用于跟踪连接状态并在连接成功时重置退避策略
type connectedFuse struct {
	fuse    *booleanFuse      // 布尔熔断器，跟踪连接是否成功
	backoff *protocolFallback // 协议降级处理器
}

// Connected 标记连接已成功建立
// 触发熔断器并重置退避策略
func (cf *connectedFuse) Connected() {
	cf.fuse.Fuse(true)
	cf.backoff.reset()
}

// IsConnected 检查连接是否已建立
// 返回: true表示已连接，false表示未连接
func (cf *connectedFuse) IsConnected() bool {
	return cf.fuse.Value()
}
