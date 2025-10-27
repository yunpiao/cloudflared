// Package supervisor 负责管理和监督 cloudflared 的隧道连接
// 它处理隧道的建立、重连、故障转移以及优雅关闭等核心功能
package supervisor

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/rs/zerolog"

	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/edgediscovery"
	"github.com/cloudflare/cloudflared/orchestration"
	v3 "github.com/cloudflare/cloudflared/quic/v3"
	"github.com/cloudflare/cloudflared/retry"
	"github.com/cloudflare/cloudflared/signal"
	"github.com/cloudflare/cloudflared/tunnelstate"
)

const (
	// tunnelRetryDuration 定义了隧道连接失败后等待重试的时间
	// 设置为 10 秒，给予足够的时间让临时网络问题得以恢复
	tunnelRetryDuration = time.Second * 10

	// registrationInterval 定义了在注册新隧道之间的时间间隔
	// 通过错开注册时间，避免所有隧道同时连接造成的突发负载
	registrationInterval = time.Second
)

// Supervisor 管理非声明式隧道。它负责与 Cloudflare 边缘节点建立连接，
// 并在连接断开时自动重连，确保隧道的高可用性。
//
// 主要职责包括：
// - 初始化和管理多个并行的隧道连接（HA 连接）
// - 监控隧道状态并在失败时进行重试和故障转移
// - 处理协议降级和边缘地址选择
// - 协调优雅关闭流程
type Supervisor struct {
	// config 包含隧道的配置信息，如连接数、重试策略等
	config *TunnelConfig

	// orchestrator 协调器，管理配置更新和流量控制
	orchestrator *orchestration.Orchestrator

	// edgeIPs 边缘节点 IP 地址管理器，负责解析和选择边缘节点
	edgeIPs *edgediscovery.Edge

	// edgeTunnelServer 边缘隧道服务器，负责实际的隧道连接建立
	edgeTunnelServer TunnelServer

	// tunnelErrors 接收各个隧道连接的错误信息的通道
	tunnelErrors chan tunnelError

	// tunnelsConnecting 记录正在连接的隧道索引及其完成信号
	// key 是隧道索引，value 是该隧道连接成功时关闭的 channel
	tunnelsConnecting map[int]chan struct{}

	// tunnelsProtocolFallback 存储每个隧道的协议降级状态
	// 当某个协议连接失败时，可以尝试降级到其他协议
	tunnelsProtocolFallback map[int]*protocolFallback

	// nextConnectedIndex 和 nextConnectedSignal 用于等待当前正在连接的隧道完成
	// 当所有隧道都连接成功后，可以重置退避计时器
	nextConnectedIndex  int           // 下一个预期完成连接的隧道索引
	nextConnectedSignal chan struct{} // 下一个隧道连接完成的信号通道

	// log 连接感知日志记录器，可以记录每个连接的详细信息
	log *ConnAwareLogger

	// logTransport 传输层日志记录器
	logTransport *zerolog.Logger

	// reconnectCh 接收重连信号的通道
	reconnectCh chan ReconnectSignal

	// gracefulShutdownC 优雅关闭信号通道，当收到信号时开始关闭流程
	gracefulShutdownC <-chan struct{}
}

// errEarlyShutdown 当在初始化阶段就收到关闭信号时返回的错误
var errEarlyShutdown = errors.New("shutdown started")

// tunnelError 包装了隧道连接的错误信息
type tunnelError struct {
	index int   // 隧道的索引号，用于标识是哪个隧道出错
	err   error // 具体的错误信息
}

// NewSupervisor 创建并初始化一个新的 Supervisor 实例
//
// 参数:
//   - config: 隧道配置，包含连接数、重试策略、边缘地址等信息
//   - orchestrator: 编排器，用于管理配置和流量限制
//   - reconnectCh: 接收重连信号的通道
//   - gracefulShutdownC: 优雅关闭信号通道
//
// 返回:
//   - *Supervisor: 初始化完成的 Supervisor 实例
//   - error: 初始化过程中的错误，如边缘节点解析失败等
func NewSupervisor(config *TunnelConfig, orchestrator *orchestration.Orchestrator, reconnectCh chan ReconnectSignal, gracefulShutdownC <-chan struct{}) (*Supervisor, error) {
	// 判断是否使用静态边缘地址（用户手动指定）还是动态解析
	isStaticEdge := len(config.EdgeAddrs) > 0

	var err error
	var edgeIPs *edgediscovery.Edge
	if isStaticEdge {
		// 使用静态配置的边缘地址
		edgeIPs, err = edgediscovery.StaticEdge(config.Log, config.EdgeAddrs)
	} else {
		// 根据区域和 IP 版本动态解析边缘节点地址
		edgeIPs, err = edgediscovery.ResolveEdge(config.Log, config.Region, config.EdgeIPVersion)
	}
	if err != nil {
		return nil, err
	}

	// 创建连接状态跟踪器，用于监控所有隧道连接的状态
	tracker := tunnelstate.NewConnTracker(config.Log)

	// 创建连接感知的日志记录器，可以为每个连接记录详细的日志信息
	log := NewConnAwareLogger(config.Log, tracker, config.Observer)

	// 创建边缘地址故障转移处理器，当连接失败时自动切换到其他边缘地址
	edgeAddrHandler := NewIPAddrFallback(config.MaxEdgeAddrRetries)

	// 获取边缘绑定地址，用于指定本地出站网络接口
	edgeBindAddr := config.EdgeBindAddr

	// 创建数据报度量收集器，用于监控 QUIC 数据报的性能指标
	datagramMetrics := v3.NewMetrics(prometheus.DefaultRegisterer)

	// 创建会话管理器，负责管理 QUIC 会话和流量控制
	sessionManager := v3.NewSessionManager(datagramMetrics, config.Log, config.OriginDialerService, orchestrator.GetFlowLimiter())

	// 创建边缘隧道服务器，这是实际建立和维护隧道连接的核心组件
	edgeTunnelServer := EdgeTunnelServer{
		config:            config,
		orchestrator:      orchestrator,
		sessionManager:    sessionManager,
		datagramMetrics:   datagramMetrics,
		edgeAddrs:         edgeIPs,
		edgeAddrHandler:   edgeAddrHandler,
		edgeBindAddr:      edgeBindAddr,
		tracker:           tracker,
		reconnectCh:       reconnectCh,
		gracefulShutdownC: gracefulShutdownC,
		connAwareLogger:   log,
	}

	// 组装并返回完整的 Supervisor 实例
	return &Supervisor{
		config:                  config,
		orchestrator:            orchestrator,
		edgeIPs:                 edgeIPs,
		edgeTunnelServer:        &edgeTunnelServer,
		tunnelErrors:            make(chan tunnelError),      // 创建错误通道
		tunnelsConnecting:       map[int]chan struct{}{},     // 初始化连接中的隧道映射
		tunnelsProtocolFallback: map[int]*protocolFallback{}, // 初始化协议降级映射
		log:                     log,
		logTransport:            config.LogTransport,
		reconnectCh:             reconnectCh,
		gracefulShutdownC:       gracefulShutdownC,
	}, nil
}

// Run 启动 Supervisor 的主事件循环，管理所有隧道连接的生命周期
//
// 此方法负责：
// 1. 启动辅助服务（ICMP 路由器、DNS 解析器）
// 2. 初始化第一个隧道连接
// 3. 在主循环中处理隧道错误、重连和优雅关闭
//
// 参数:
//   - ctx: 上下文，用于取消操作和超时控制
//   - connectedSignal: 当第一个隧道成功连接时发出的信号
//
// 返回:
//   - error: 运行过程中的致命错误，nil 表示正常退出
func (s *Supervisor) Run(
	ctx context.Context,
	connectedSignal *signal.Signal,
) error {
	// 如果配置了 ICMP 路由器服务器，在后台启动它
	// ICMP 用于网络诊断（如 ping、traceroute）
	if s.config.ICMPRouterServer != nil {
		go func() {
			if err := s.config.ICMPRouterServer.Serve(ctx); err != nil {
				if errors.Is(err, net.ErrClosed) {
					s.log.Logger().Info().Err(err).Msg("icmp router terminated")
				} else {
					s.log.Logger().Err(err).Msg("icmp router terminated")
				}
			}
		}()
	}

	// 启动 DNS 解析器的刷新循环
	// 定期刷新源站 DNS 记录，确保连接到正确的后端服务器
	go s.config.OriginDNSService.StartRefreshLoop(ctx)

	// 初始化阶段：建立第一个隧道连接，然后启动其余的 HA 连接
	if err := s.initialize(ctx, connectedSignal); err != nil {
		if err == errEarlyShutdown {
			// 在初始化阶段就收到了关闭信号，正常退出
			return nil
		}
		s.log.Logger().Error().Err(err).Msg("initial tunnel connection failed")
		return err
	}

	// tunnelsWaiting 记录正在等待重连的隧道索引列表
	var tunnelsWaiting []int

	// tunnelsActive 记录当前活跃（已启动）的隧道数量
	tunnelsActive := s.config.HAConnections

	// 创建退避计时器，用于控制重试间隔，避免频繁重连
	backoff := retry.NewBackoff(s.config.Retries, tunnelRetryDuration, true)
	var backoffTimer <-chan time.Time

	// shuttingDown 标记是否正在关闭，用于在关闭时停止新的重连
	shuttingDown := false

	// 主事件循环：监听各种事件并做出响应
	for {
		select {
		// 上下文被取消（程序退出）
		case <-ctx.Done():
			// 等待所有活跃的隧道都退出
			for tunnelsActive > 0 {
				<-s.tunnelErrors
				tunnelsActive--
			}
			return nil

		// 收到隧道错误或完成信号
		// 注意：这也可能是由于上下文取消引起的
		case tunnelError := <-s.tunnelErrors:
			tunnelsActive--
			s.log.ConnAwareLogger().Err(tunnelError.err).Int(connection.LogFieldConnIndex, tunnelError.index).Msg("Connection terminated")

			// 如果隧道出错且不在关闭状态，则尝试重连
			if tunnelError.err != nil && !shuttingDown {
				switch tunnelError.err.(type) {
				case ReconnectSignal:
					// 对于收到重连信号的隧道，立即重连（不等待退避时间）
					// 这通常发生在边缘节点要求客户端重新连接的情况
					go s.startTunnel(ctx, tunnelError.index, s.newConnectedTunnelSignal(tunnelError.index))
					tunnelsActive++
					continue
				}

				// 检查是否还允许协议降级和重试
				// 如果所有降级选项都已用尽，则不再重试这个隧道
				if _, retry := s.tunnelsProtocolFallback[tunnelError.index].GetMaxBackoffDuration(ctx); !retry {
					continue
				}

				// 将隧道加入等待队列，稍后重试
				tunnelsWaiting = append(tunnelsWaiting, tunnelError.index)
				s.waitForNextTunnel(tunnelError.index)

				// 如果退避计时器还未启动，则启动它
				if backoffTimer == nil {
					backoffTimer = backoff.BackoffTimer()
				}
			} else if tunnelsActive == 0 {
				// 所有隧道都已优雅退出，没有更多工作要做
				s.log.ConnAwareLogger().Msg("no more connections active and exiting")
				return nil
			}

		// 退避计时器到期，重新启动等待中的隧道
		case <-backoffTimer:
			backoffTimer = nil
			// 为所有等待的隧道重新建立连接
			for _, index := range tunnelsWaiting {
				go s.startTunnel(ctx, index, s.newConnectedTunnelSignal(index))
			}
			tunnelsActive += len(tunnelsWaiting)
			tunnelsWaiting = nil

		// 有隧道成功连接
		case <-s.nextConnectedSignal:
			// 检查是否还有其他隧道正在连接
			if !s.waitForNextTunnel(s.nextConnectedIndex) && len(tunnelsWaiting) == 0 {
				// 没有更多未完成的隧道，重置退避计时器的宽限期
				// 这样下次失败时可以更快地重试
				backoff.SetGracePeriod()
			}

		// 收到优雅关闭信号
		case <-s.gracefulShutdownC:
			shuttingDown = true
		}
	}
}

// initialize 初始化隧道连接
//
// 工作流程：
// 1. 首先尝试连接第一个隧道
// 2. 如果成功，则启动其余的 HA 连接（最多到 config.HAConnections）
// 3. 如果第一个隧道连接失败，则返回错误
//
// 参数:
//   - ctx: 上下文
//   - connectedSignal: 当第一个隧道成功连接时发出的信号
//
// 返回:
//   - error: 如果初始化成功返回 nil，否则返回初始化错误
func (s *Supervisor) initialize(
	ctx context.Context,
	connectedSignal *signal.Signal,
) error {
	// 获取可用的边缘地址数量
	availableAddrs := s.edgeIPs.AvailableAddrs()

	// 如果请求的 HA 连接数超过了可用地址数，则调整为可用地址数
	if s.config.HAConnections > availableAddrs {
		s.log.Logger().Info().Msgf("You requested %d HA connections but I can give you at most %d.", s.config.HAConnections, availableAddrs)
		s.config.HAConnections = availableAddrs
	}

	// 为第一个隧道（索引 0）初始化协议降级配置
	s.tunnelsProtocolFallback[0] = &protocolFallback{
		retry.NewBackoff(s.config.Retries, retry.DefaultBaseTime, true), // 退避计时器
		s.config.ProtocolSelector.Current(),                             // 当前选择的协议
		false,                                                           // 是否已降级
	}

	// 启动第一个隧道连接（在后台运行）
	go s.startFirstTunnel(ctx, connectedSignal)

	// 等待第一个隧道的响应，然后再尝试启动其他 HA 边缘隧道
	// 这确保了至少有一个可工作的连接，然后再建立其余连接
	select {
	case <-ctx.Done():
		// 上下文被取消，等待隧道错误并返回
		<-s.tunnelErrors
		return ctx.Err()
	case tunnelError := <-s.tunnelErrors:
		// 第一个隧道连接失败
		return tunnelError.err
	case <-s.gracefulShutdownC:
		// 在初始化期间收到关闭信号
		return errEarlyShutdown
	case <-connectedSignal.Wait():
		// 第一个隧道成功连接，继续后续流程
	}

	// 至少有一个成功的连接，启动其余的隧道
	for i := 1; i < s.config.HAConnections; i++ {
		// 为每个隧道设置协议降级配置
		s.tunnelsProtocolFallback[i] = &protocolFallback{
			retry.NewBackoff(s.config.Retries, retry.DefaultBaseTime, true),
			// 使用第一个隧道成功连接的协议
			// 这样可以避免重复尝试已知失败的协议
			s.tunnelsProtocolFallback[0].protocol,
			false,
		}
		// 启动隧道连接
		go s.startTunnel(ctx, i, s.newConnectedTunnelSignal(i))
		// 在启动隧道之间等待一小段时间，避免同时建立大量连接
		time.Sleep(registrationInterval)
	}
	return nil
}

// startFirstTunnel 启动第一个隧道连接
//
// 这是一个特殊的函数，专门用于启动第一个隧道。与 startTunnel 不同，
// 它会在遇到某些错误时自动重试，因为第一个隧道的成功对整个系统至关重要。
//
// 结果错误会发送到 s.tunnelErrors 通道。
// 如果注册成功，会通过 connectedSignal 发送信号。
//
// 参数:
//   - ctx: 上下文
//   - connectedSignal: 连接成功时发送的信号
func (s *Supervisor) startFirstTunnel(
	ctx context.Context,
	connectedSignal *signal.Signal,
) {
	var err error
	const firstConnIndex = 0
	isStaticEdge := len(s.config.EdgeAddrs) > 0

	// 函数返回时，将错误发送到 tunnelErrors 通道
	defer func() {
		s.tunnelErrors <- tunnelError{index: firstConnIndex, err: err}
	}()

	// 如果第一个隧道断开连接，继续重启它
	// 这是一个重试循环，对于某些可恢复的错误会持续尝试
	for {
		err = s.edgeTunnelServer.Serve(ctx, firstConnIndex, s.tunnelsProtocolFallback[firstConnIndex], connectedSignal)

		// 如果上下文被取消，停止重试
		if ctx.Err() != nil {
			return
		}

		// 如果没有错误，正常退出
		if err == nil {
			return
		}

		// 确保还有降级选项可用，否则不再继续
		if _, retry := s.tunnelsProtocolFallback[firstConnIndex].GetMaxBackoffDuration(ctx); !retry {
			return
		}

		// 对于 Unauthorized 错误继续重试
		// 这可能是由于新隧道的边缘传播延迟造成的临时问题
		if strings.Contains(err.Error(), "Unauthorized") {
			continue
		}

		// 根据错误类型决定是否重试
		switch err.(type) {
		case edgediscovery.ErrNoAddressesLeft:
			// 如果是静态边缘地址且没有可用地址，继续重试
			// 对于动态解析的地址，则放弃
			if !isStaticEdge {
				return
			}
		case connection.DupConnRegisterTunnelError,
			*quic.IdleTimeoutError,
			*quic.ApplicationError,
			edgediscovery.DialError,
			*connection.EdgeQuicDialError,
			*connection.ControlStreamError,
			*connection.StreamListenerError,
			*connection.DatagramManagerError:
			// 这些错误类型被认为是可恢复的，继续重试
		default:
			// 未捕获的错误类型，停止启动流程
			return
		}
	}
}

// startTunnel 启动一个新的隧道连接
//
// 这个函数设计为在 goroutine 中运行。与 startFirstTunnel 不同，
// 它不会自动重试，而是将错误发送到 s.tunnelErrors 通道，
// 由主循环决定是否重连。
//
// 参数:
//   - ctx: 上下文
//   - index: 隧道的索引号
//   - connectedSignal: 连接成功时发送的信号
func (s *Supervisor) startTunnel(
	ctx context.Context,
	index int,
	connectedSignal *signal.Signal,
) {
	// nolint: gosec - index 的范围由调用方控制，转换是安全的
	err := s.edgeTunnelServer.Serve(ctx, uint8(index), s.tunnelsProtocolFallback[index], connectedSignal)
	// 将结果（成功或失败）发送到 tunnelErrors 通道
	s.tunnelErrors <- tunnelError{index: index, err: err}
}

// newConnectedTunnelSignal 为指定索引的隧道创建一个新的连接信号
//
// 这个信号用于通知主循环该隧道已成功连接。同时，它会更新
// nextConnectedSignal 和 nextConnectedIndex，以便主循环知道
// 下一个预期完成连接的隧道是哪个。
//
// 参数:
//   - index: 隧道的索引号
//
// 返回:
//   - *signal.Signal: 新创建的信号对象
func (s *Supervisor) newConnectedTunnelSignal(index int) *signal.Signal {
	// 创建一个新的信号通道
	sig := make(chan struct{})

	// 将这个通道记录到正在连接的隧道映射中
	s.tunnelsConnecting[index] = sig

	// 更新下一个预期连接的隧道信息
	s.nextConnectedSignal = sig
	s.nextConnectedIndex = index

	// 返回封装后的信号对象
	return signal.New(sig)
}

// waitForNextTunnel 处理已完成连接的隧道，并查找下一个正在连接的隧道
//
// 当一个隧道完成连接（成功或失败）时调用此方法。它会：
// 1. 从正在连接的隧道列表中移除已完成的隧道
// 2. 查找下一个正在连接的隧道并更新 nextConnectedSignal
//
// 参数:
//   - index: 已完成连接的隧道索引
//
// 返回:
//   - bool: 如果还有其他隧道正在连接返回 true，否则返回 false
func (s *Supervisor) waitForNextTunnel(index int) bool {
	// 从正在连接的隧道映射中移除这个已完成的隧道
	delete(s.tunnelsConnecting, index)

	// 清空下一个连接信号
	s.nextConnectedSignal = nil

	// 遍历剩余正在连接的隧道，选择一个作为下一个要等待的
	for k, v := range s.tunnelsConnecting {
		s.nextConnectedIndex = k
		s.nextConnectedSignal = v
		return true // 还有隧道正在连接
	}

	// 没有更多隧道正在连接
	return false
}
