package boot

import (
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ebpfNetworkPacketObserver struct {
	kernel *kernel.Kernel
}

func (o ebpfNetworkPacketObserver) IsObservingNetworkPackets(direction stack.NetworkPacketDirection) bool {
	if o.kernel == nil {
		return false
	}
	if mgr := o.kernel.EBPF(); mgr != nil {
		return mgr.IsObservingNetworkPackets(direction)
	}
	return false
}

func (o ebpfNetworkPacketObserver) ObserveNetworkPacket(evt stack.NetworkPacketEvent) {
	if o.kernel == nil {
		return
	}
	if mgr := o.kernel.EBPF(); mgr != nil {
		mgr.ObserveNetworkPacket(evt)
	}
}
