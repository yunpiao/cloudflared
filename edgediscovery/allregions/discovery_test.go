package allregions

import (
	"fmt"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func (ea *EdgeAddr) String() string {
	return fmt.Sprintf("%s-%s", ea.TCP, ea.UDP)
}

func TestEdgeDiscovery(t *testing.T) {
	mockAddrs := newMockAddrs(19, 2, 5)
	netLookupSRV = mockNetLookupSRV(mockAddrs)
	netLookupIP = mockNetLookupIP(mockAddrs)

	expectedAddrSet := map[string]bool{}
	for _, addrs := range mockAddrs.addrMap {
		for _, addr := range addrs {
			expectedAddrSet[addr.String()] = true
		}
	}

	l := zerolog.Nop()
	addrLists, err := edgeDiscovery(&l, "")
	assert.NoError(t, err)
	actualAddrSet := map[string]bool{}
	for _, addrs := range addrLists {
		for _, addr := range addrs {
			actualAddrSet[addr.String()] = true
		}
	}

	assert.Equal(t, expectedAddrSet, actualAddrSet)
}

func TestRealEdgeDiscovery(t *testing.T) {
	l := zerolog.Nop()
	// 不设置 mock，使用真实的 DNS 查询
	addrLists, err := edgeDiscovery(&l, "v2-origintunneld")
	assert.NoError(t, err)

	// 打印真实的边缘 IP
	for _, addrs := range addrLists {
		for _, addr := range addrs {
			fmt.Printf("Edge IP: %s\n", addr.TCP.IP.String())
		}
	}
}
