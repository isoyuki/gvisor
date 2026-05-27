package ebpf

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// AccessMode describes context field access permissions.
type AccessMode uint8

const (
	// AccessRead permits reads.
	AccessRead AccessMode = 1 << iota

	// AccessWrite permits writes.
	AccessWrite
)

// ContextSpec describes a stable virtual eBPF context layout.
type ContextSpec struct {
	Name   string
	Size   uint32
	Fields []ContextField
}

// ContextField describes one field in an eBPF context.
type ContextField struct {
	Name   string
	Offset uint32
	Size   uint32
	Access AccessMode
	Reg    RegState
}

// ValidAccess returns the register state yielded by a context access.
func (c *ContextSpec) ValidAccess(off int32, size uint32, write bool) (RegState, bool) {
	if c == nil || off < 0 || size == 0 {
		return RegState{}, false
	}
	end := uint32(off) + size
	if end > c.Size {
		return RegState{}, false
	}
	for _, f := range c.Fields {
		if uint32(off) < f.Offset || end > f.Offset+f.Size {
			continue
		}
		if write && f.Access&AccessWrite == 0 {
			return RegState{}, false
		}
		if !write && f.Access&AccessRead == 0 {
			return RegState{}, false
		}
		reg := f.Reg
		if reg.Type == RegNotInit {
			reg.Type = RegScalar
			reg.Readable = true
		}
		return reg, true
	}
	return RegState{}, false
}

// RuntimeContext provides VM access to a stable virtual eBPF context.
type RuntimeContext interface {
	Spec() *ContextSpec
	Load(off int32, size uint32) (uint64, error)
	Store(off int32, size uint32, value uint64) error
}

var rawSyscallEnterContextSpec = &ContextSpec{
	Name: "gvisor_raw_sys_enter_ctx",
	Size: 56,
	Fields: []ContextField{
		{Name: "id", Offset: 0, Size: 8, Access: AccessRead},
		{Name: "arg0", Offset: 8, Size: 8, Access: AccessRead},
		{Name: "arg1", Offset: 16, Size: 8, Access: AccessRead},
		{Name: "arg2", Offset: 24, Size: 8, Access: AccessRead},
		{Name: "arg3", Offset: 32, Size: 8, Access: AccessRead},
		{Name: "arg4", Offset: 40, Size: 8, Access: AccessRead},
		{Name: "arg5", Offset: 48, Size: 8, Access: AccessRead},
	},
}

var rawSyscallExitContextSpec = &ContextSpec{
	Name: "gvisor_raw_sys_exit_ctx",
	Size: 16,
	Fields: []ContextField{
		{Name: "id", Offset: 0, Size: 8, Access: AccessRead},
		{Name: "ret", Offset: 8, Size: 8, Access: AccessRead},
	},
}

var rawTracepointContextSpec = &ContextSpec{
	Name: "gvisor_raw_tracepoint_ctx",
	Size: 128,
	Fields: []ContextField{
		{Name: "data", Offset: 0, Size: 128, Access: AccessRead},
	},
}

var networkPacketContextSpec = &ContextSpec{
	Name: "gvisor_net_packet_ctx",
	Size: 88,
	Fields: []ContextField{
		{Name: "direction", Offset: 0, Size: 8, Access: AccessRead},
		{Name: "nic_id", Offset: 8, Size: 8, Access: AccessRead},
		{Name: "network_protocol", Offset: 16, Size: 8, Access: AccessRead},
		{Name: "transport_protocol", Offset: 24, Size: 8, Access: AccessRead},
		{Name: "total_len", Offset: 32, Size: 8, Access: AccessRead},
		{Name: "src_port", Offset: 40, Size: 8, Access: AccessRead},
		{Name: "dst_port", Offset: 48, Size: 8, Access: AccessRead},
		{Name: "src_addr", Offset: 56, Size: 16, Access: AccessRead},
		{Name: "dst_addr", Offset: 72, Size: 16, Access: AccessRead},
	},
}

func contextSpecForProgramType(typ linux.BPFProgramType) *ContextSpec {
	switch typ {
	case linux.BPF_PROG_TYPE_TRACEPOINT, linux.BPF_PROG_TYPE_RAW_TRACEPOINT, linux.BPF_PROG_TYPE_PERF_EVENT:
		return rawTracepointContextSpec
	case linux.BPF_PROG_TYPE_SYSCALL:
		return rawSyscallEnterContextSpec
	case linux.BPF_PROG_TYPE_XDP, linux.BPF_PROG_TYPE_SCHED_CLS, linux.BPF_PROG_TYPE_SCHED_ACT, linux.BPF_PROG_TYPE_SOCKET_FILTER:
		return networkPacketContextSpec
	default:
		return rawSyscallEnterContextSpec
	}
}

// SyscallEnterContext is the raw syscall-enter eBPF runtime context.
type SyscallEnterContext struct {
	Sysno uint64
	Args  [6]uint64
}

// Spec implements RuntimeContext.Spec.
func (c *SyscallEnterContext) Spec() *ContextSpec {
	return rawSyscallEnterContextSpec
}

// Load implements RuntimeContext.Load.
func (c *SyscallEnterContext) Load(off int32, size uint32) (uint64, error) {
	if size != 8 || off < 0 || off%8 != 0 || off >= int32(rawSyscallEnterContextSpec.Size) {
		return 0, linuxerr.EFAULT
	}
	if off == 0 {
		return c.Sysno, nil
	}
	return c.Args[(off/8)-1], nil
}

// Store implements RuntimeContext.Store.
func (*SyscallEnterContext) Store(int32, uint32, uint64) error {
	return linuxerr.EPERM
}

// SyscallExitContext is the raw syscall-exit eBPF runtime context.
type SyscallExitContext struct {
	Sysno uint64
	Ret   uint64
}

// Spec implements RuntimeContext.Spec.
func (c *SyscallExitContext) Spec() *ContextSpec {
	return rawSyscallExitContextSpec
}

// Load implements RuntimeContext.Load.
func (c *SyscallExitContext) Load(off int32, size uint32) (uint64, error) {
	if size != 8 || off < 0 || off%8 != 0 || off >= int32(rawSyscallExitContextSpec.Size) {
		return 0, linuxerr.EFAULT
	}
	if off == 0 {
		return c.Sysno, nil
	}
	return c.Ret, nil
}

// Store implements RuntimeContext.Store.
func (*SyscallExitContext) Store(int32, uint32, uint64) error {
	return linuxerr.EPERM
}

// NetworkPacketContext is the raw network-packet eBPF runtime context.
type NetworkPacketContext struct {
	Event stack.NetworkPacketEvent
	data  [88]byte
}

// NewNetworkPacketContext returns a serialized network packet context. The
// packet hook may read several fields, so precomputing the fixed layout avoids
// rebuilding it for every eBPF load.
func NewNetworkPacketContext(evt stack.NetworkPacketEvent) *NetworkPacketContext {
	c := &NetworkPacketContext{Event: evt}
	hostarch.ByteOrder.PutUint64(c.data[0:], uint64(evt.Direction))
	hostarch.ByteOrder.PutUint64(c.data[8:], uint64(evt.NICID))
	hostarch.ByteOrder.PutUint64(c.data[16:], uint64(evt.NetworkProtocol))
	hostarch.ByteOrder.PutUint64(c.data[24:], uint64(evt.TransportProtocol))
	hostarch.ByteOrder.PutUint64(c.data[32:], uint64(evt.TotalLength))
	hostarch.ByteOrder.PutUint64(c.data[40:], uint64(evt.SourcePort))
	hostarch.ByteOrder.PutUint64(c.data[48:], uint64(evt.DestinationPort))
	copy(c.data[56:72], evt.SourceAddress[:])
	copy(c.data[72:88], evt.DestinationAddress[:])
	return c
}

// Spec implements RuntimeContext.Spec.
func (*NetworkPacketContext) Spec() *ContextSpec {
	return networkPacketContextSpec
}

// Load implements RuntimeContext.Load.
func (c *NetworkPacketContext) Load(off int32, size uint32) (uint64, error) {
	if off < 0 || size == 0 || uint32(off)+size > networkPacketContextSpec.Size {
		return 0, linuxerr.EFAULT
	}
	return loadBytes(c.data[:], int64(off), size)
}

// Store implements RuntimeContext.Store.
func (*NetworkPacketContext) Store(int32, uint32, uint64) error {
	return linuxerr.EPERM
}
