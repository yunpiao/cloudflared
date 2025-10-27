# Cloudflare Tunnel client (SOCKS5 代理增强版)

> **注意**: 这是 cloudflared 的一个增强版本，添加了 SOCKS5 代理支持功能。

Contains the command-line client for Cloudflare Tunnel, a tunneling daemon that proxies traffic from the Cloudflare network to your origins.
This daemon sits between Cloudflare network and your origin (e.g. a webserver). Cloudflare attracts client requests and sends them to you
via this daemon, without requiring you to poke holes on your firewall --- your origin can remain as closed as possible.
Extensive documentation can be found in the [Cloudflare Tunnel section](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps) of the Cloudflare Docs.
All usages related with proxying to your origins are available under `cloudflared tunnel help`.

You can also use `cloudflared` to access Tunnel origins (that are protected with `cloudflared tunnel`) for TCP traffic
at Layer 4 (i.e., not HTTP/websocket), which is relevant for use cases such as SSH, RDP, etc.
Such usages are available under `cloudflared access help`.

You can instead use [WARP client](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/configuration/private-networks)
to access private origins behind Tunnels for Layer 4 traffic without requiring `cloudflared access` commands on the client side.

## 🆕 增强功能: SOCKS5 代理支持

此版本新增了 SOCKS5 代理支持,允许 cloudflared 通过 SOCKS5 代理连接到 Cloudflare 边缘节点。

**主要特性:**
- ✅ 支持标准 SOCKS5 协议 (RFC 1928)
- ✅ 支持用户名/密码认证 (RFC 1929)
- ✅ 智能降级: 代理失败时自动切换到直连
- ✅ 完全向后兼容,不影响现有功能

**快速开始:**

```bash
# 通过 SOCKS5 代理运行隧道
cloudflared tunnel run --edge-proxy-url socks5://127.0.0.1:1080 mytunnel

# 带认证的代理
cloudflared tunnel run --edge-proxy-url socks5://user:pass@proxy:1080 mytunnel

# 或在配置文件中设置
# config.yml
edge-proxy-url: socks5://127.0.0.1:1080
```

**详细文档:**
- [SOCKS5 代理完整使用指南](SOCKS5_PROXY_GUIDE.md)
- [功能测试报告](TEST_PROXY.md)


## Before you get started

Before you use Cloudflare Tunnel, you'll need to complete a few steps in the Cloudflare dashboard: you need to add a
website to your Cloudflare account. Note that today it is possible to use Tunnel without a website (e.g. for private
routing), but for legacy reasons this requirement is still necessary:
1. [Add a website to Cloudflare](https://support.cloudflare.com/hc/en-us/articles/201720164-Creating-a-Cloudflare-account-and-adding-a-website)
2. [Change your domain nameservers to Cloudflare](https://support.cloudflare.com/hc/en-us/articles/205195708)


## Installing `cloudflared`

Downloads are available as standalone binaries, a Docker image, and Debian, RPM, and Homebrew packages. You can also find releases [here](https://github.com/cloudflare/cloudflared/releases) on the `cloudflared` GitHub repository.

* You can [install on macOS](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation#macos) via Homebrew or by downloading the [latest Darwin amd64 release](https://github.com/cloudflare/cloudflared/releases)
* Binaries, Debian, and RPM packages for Linux [can be found here](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation#linux)
* A Docker image of `cloudflared` is [available on DockerHub](https://hub.docker.com/r/cloudflare/cloudflared)
* You can install on Windows machines with the [steps here](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation#windows)
* To build from source, install the required version of go, mentioned in the [Development](#development) section below. Then you can run `make cloudflared`.

User documentation for Cloudflare Tunnel can be found at https://developers.cloudflare.com/cloudflare-one/connections/connect-apps


## Creating Tunnels and routing traffic

Once installed, you can authenticate `cloudflared` into your Cloudflare account and begin creating Tunnels to serve traffic to your origins.

* Create a Tunnel with [these instructions](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/)
* Route traffic to that Tunnel:
  * Via public [DNS records in Cloudflare](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/routing-to-tunnel/dns)
  * Or via a public hostname guided by a [Cloudflare Load Balancer](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/routing-to-tunnel/lb)
  * Or from [WARP client private traffic](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/private-net/)


## TryCloudflare

Want to test Cloudflare Tunnel before adding a website to Cloudflare? You can do so with TryCloudflare using the documentation [available here](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/).

## Deprecated versions

Cloudflare currently supports versions of cloudflared that are **within one year** of the most recent release. Breaking changes unrelated to feature availability may be introduced that will impact versions released more than one year ago. You can read more about upgrading cloudflared in our [developer documentation](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/#updating-cloudflared).

For example, as of January 2023 Cloudflare will support cloudflared version 2023.1.1 to cloudflared 2022.1.1.

## Development

### Requirements
- [GNU Make](https://www.gnu.org/software/make/)
- [capnp](https://capnproto.org/install.html)
- [go >= 1.24](https://go.dev/doc/install)
- Optional tools:
  - [capnpc-go](https://pkg.go.dev/zombiezen.com/go/capnproto2/capnpc-go)
  - [goimports](https://pkg.go.dev/golang.org/x/tools/cmd/goimports)
  - [golangci-lint](https://github.com/golangci/golangci-lint)
  - [gomocks](https://pkg.go.dev/go.uber.org/mock)

### Build
To build cloudflared locally run `make cloudflared`

### Test
To locally run the tests run `make test`

### Linting
To format the code and keep a good code quality use `make fmt` and `make lint`

### Mocks
After changes on interfaces you might need to regenerate the mocks, so run `make mock`
