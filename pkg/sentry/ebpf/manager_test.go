package ebpf

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestArrayMapUpdateLookupNextKey(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	mp, err := mgr.MapCreate(MapCreateAttrs{
		Type:       linux.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatalf("MapCreate() failed: %v", err)
	}
	var key [4]byte
	var value [8]byte
	hostarch.ByteOrder.PutUint32(key[:], 1)
	hostarch.ByteOrder.PutUint64(value[:], 0xfeedface)
	if err := mp.Update(key[:], value[:], linux.BPF_ANY); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}
	got, err := mp.Lookup(key[:])
	if err != nil {
		t.Fatalf("Lookup() failed: %v", err)
	}
	if got := hostarch.ByteOrder.Uint64(got); got != 0xfeedface {
		t.Fatalf("Lookup() = %#x, want %#x", got, uint64(0xfeedface))
	}
	hostarch.ByteOrder.PutUint32(key[:], 0)
	next, err := mp.NextKey(key[:])
	if err != nil {
		t.Fatalf("NextKey() failed: %v", err)
	}
	if got := hostarch.ByteOrder.Uint32(next); got != 1 {
		t.Fatalf("NextKey() = %d, want 1", got)
	}
}

func TestHashMapDelete(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	mp, err := mgr.MapCreate(MapCreateAttrs{
		Type:       linux.BPF_MAP_TYPE_HASH,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("MapCreate() failed: %v", err)
	}
	key := []byte{1, 2, 3, 4}
	value := []byte{5, 6, 7, 8}
	if err := mp.Update(key, value, linux.BPF_NOEXIST); err != nil {
		t.Fatalf("Update() failed: %v", err)
	}
	if err := mp.Delete(key); err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}
	if _, err := mp.Lookup(key); err == nil {
		t.Fatalf("Lookup() after Delete() succeeded, want error")
	}
}

func TestPinGetPreservesObject(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	mp, err := mgr.MapCreate(MapCreateAttrs{
		Type:       linux.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatalf("MapCreate() failed: %v", err)
	}
	ctx := context.Background()
	if err := mgr.Pin(ctx, "/sys/fs/bpf/counts", mp); err != nil {
		t.Fatalf("Pin() failed: %v", err)
	}
	mp.DecRef(ctx)
	obj, err := mgr.GetPinned("/sys/fs/bpf/counts")
	if err != nil {
		t.Fatalf("GetPinned() failed: %v", err)
	}
	got, ok := obj.(*Map)
	if !ok {
		t.Fatalf("GetPinned() = %T, want *Map", obj)
	}
	got.DecRef(ctx)
	if err := mgr.Unpin(ctx, "/sys/fs/bpf/counts"); err != nil {
		t.Fatalf("Unpin() failed: %v", err)
	}
	if _, err := mgr.GetPinned("/sys/fs/bpf/counts"); err == nil {
		t.Fatalf("GetPinned() after Unpin succeeded, want error")
	}
}

func TestBTFLoadSyntheticBlob(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	ctx := context.Background()
	btf, err := mgr.BTFLoad(SyntheticBTFBlob(), "vmlinux")
	if err != nil {
		t.Fatalf("BTFLoad() failed: %v", err)
	}
	defer btf.DecRef(ctx)
	got, err := mgr.BTFByID(btf.ID())
	if err != nil {
		t.Fatalf("BTFByID() failed: %v", err)
	}
	got.DecRef(ctx)
}

func TestLinkCreateXDPAttach(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	ctx := context.Background()
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_XDP,
		Insns: []Insn{
			mov64Imm(linux.BPF_REG_0, 0),
			exitInsn(),
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	defer prog.DecRef(ctx)
	link, err := mgr.LinkCreate(prog, linux.BPF_XDP, 0)
	if err != nil {
		t.Fatalf("LinkCreate() failed: %v", err)
	}
	link.DecRef(ctx)
}

func TestNetworkObservationMaskTracksAttachDetach(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	if mgr.IsObservingNetworkPackets(stack.NetworkPacketIngress) {
		t.Fatalf("IsObservingNetworkPackets(ingress) = true before attach, want false")
	}
	ctx := context.Background()
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_XDP,
		Insns: []Insn{
			mov64Imm(linux.BPF_REG_0, 0),
			exitInsn(),
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	defer prog.DecRef(ctx)
	link, err := mgr.LinkCreate(prog, linux.BPF_XDP, 0)
	if err != nil {
		t.Fatalf("LinkCreate() failed: %v", err)
	}
	if !mgr.IsObservingNetworkPackets(stack.NetworkPacketIngress) {
		t.Fatalf("IsObservingNetworkPackets(ingress) = false after attach, want true")
	}
	if mgr.IsObservingNetworkPackets(stack.NetworkPacketEgress) {
		t.Fatalf("IsObservingNetworkPackets(egress) = true after ingress-only attach, want false")
	}
	link.Detach()
	if mgr.IsObservingNetworkPackets(stack.NetworkPacketIngress) {
		t.Fatalf("IsObservingNetworkPackets(ingress) = true after detach, want false")
	}
	link.DecRef(ctx)
}

func TestNetworkHookRejectsInvalidContextAccess(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	ctx := context.Background()
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_RAW_TRACEPOINT,
		Insns: []Insn{
			ldxMem(linux.BPF_DW, linux.BPF_REG_0, linux.BPF_REG_1, 120),
			exitInsn(),
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	defer prog.DecRef(ctx)
	if _, err := mgr.RawTracepointOpen("gvisor/net/packet", prog, 0); err == nil {
		t.Fatalf("RawTracepointOpen() succeeded, want invalid context access rejection")
	}
}

func TestNetworkHookAcceptsSpilledContextPointer(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	ctx := context.Background()
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_RAW_TRACEPOINT,
		Insns: []Insn{
			stxMem(linux.BPF_DW, linux.BPF_REG_10, linux.BPF_REG_1, -8),
			ldxMem(linux.BPF_DW, linux.BPF_REG_2, linux.BPF_REG_10, -8),
			ldxMem(linux.BPF_DW, linux.BPF_REG_0, linux.BPF_REG_2, 32),
			exitInsn(),
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	defer prog.DecRef(ctx)
	link, err := mgr.RawTracepointOpen("gvisor/net/packet", prog, 0)
	if err != nil {
		t.Fatalf("RawTracepointOpen() failed: %v", err)
	}
	link.DecRef(ctx)
}

func TestNetworkHookRejectsTaskHelper(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	ctx := context.Background()
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_RAW_TRACEPOINT,
		Insns: []Insn{
			callInsn(linux.BPF_FUNC_get_current_pid_tgid),
			exitInsn(),
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	defer prog.DecRef(ctx)
	if _, err := mgr.RawTracepointOpen("gvisor/net/packet", prog, 0); err == nil {
		t.Fatalf("RawTracepointOpen() succeeded, want helper rejection")
	}
}

func TestRingbufReserveSubmitHelper(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	rb, err := mgr.MapCreate(MapCreateAttrs{
		Type:       linux.BPF_MAP_TYPE_RINGBUF,
		MaxEntries: hostarch.PageSize,
	})
	if err != nil {
		t.Fatalf("ringbuf MapCreate() failed: %v", err)
	}
	ctx := context.Background()
	defer rb.DecRef(ctx)
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_SYSCALL,
		Insns: []Insn{
			ldMapFD(linux.BPF_REG_1, 9),
			{},
			mov64Imm(linux.BPF_REG_2, 8),
			mov64Imm(linux.BPF_REG_3, 0),
			callInsn(linux.BPF_FUNC_ringbuf_reserve),
			jmpImm(linux.BPF_JEQ, linux.BPF_REG_0, 0, 5),
			mov64Imm(linux.BPF_REG_2, 42),
			stxMem(linux.BPF_DW, linux.BPF_REG_0, linux.BPF_REG_2, 0),
			mov64Reg(linux.BPF_REG_1, linux.BPF_REG_0),
			mov64Imm(linux.BPF_REG_2, 0),
			callInsn(linux.BPF_FUNC_ringbuf_submit),
			mov64Imm(linux.BPF_REG_0, 0),
			exitInsn(),
		},
		MapResolver: func(fd int32) (*Map, error) {
			if fd != 9 {
				t.Fatalf("MapResolver(%d), want 9", fd)
			}
			rb.IncRef()
			return rb, nil
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	defer prog.DecRef(ctx)
	if _, err := mgr.ProgramTestRun(prog, &SyscallEnterContext{}, TaskInfo{}); err != nil {
		t.Fatalf("ProgramTestRun() failed: %v", err)
	}
	record, err := rb.ops.(*ringbufMap).ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord() failed: %v", err)
	}
	if got := hostarch.ByteOrder.Uint64(record); got != 42 {
		t.Fatalf("ringbuf record = %d, want 42", got)
	}
}

func TestNetworkPacketHookEmitsRingbufEvent(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	rb, err := mgr.MapCreate(MapCreateAttrs{
		Type:       linux.BPF_MAP_TYPE_RINGBUF,
		MaxEntries: hostarch.PageSize,
	})
	if err != nil {
		t.Fatalf("ringbuf MapCreate() failed: %v", err)
	}
	ctx := context.Background()
	defer rb.DecRef(ctx)
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_RAW_TRACEPOINT,
		Insns: []Insn{
			ldxMem(linux.BPF_DW, linux.BPF_REG_0, linux.BPF_REG_1, 32),
			stxMem(linux.BPF_DW, linux.BPF_REG_10, linux.BPF_REG_0, -8),
			ldMapFD(linux.BPF_REG_1, 9),
			{},
			mov64Reg(linux.BPF_REG_2, linux.BPF_REG_10),
			alu64Imm(linux.BPF_ADD, linux.BPF_REG_2, -8),
			mov64Imm(linux.BPF_REG_3, 8),
			mov64Imm(linux.BPF_REG_4, 0),
			callInsn(linux.BPF_FUNC_ringbuf_output),
			mov64Imm(linux.BPF_REG_0, 0),
			exitInsn(),
		},
		MapResolver: func(fd int32) (*Map, error) {
			if fd != 9 {
				t.Fatalf("MapResolver(%d), want 9", fd)
			}
			rb.IncRef()
			return rb, nil
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	defer prog.DecRef(ctx)
	link, err := mgr.RawTracepointOpen("gvisor/net/packet", prog, 0)
	if err != nil {
		t.Fatalf("RawTracepointOpen() failed: %v", err)
	}
	defer link.DecRef(ctx)
	mgr.ObserveNetworkPacket(stack.NetworkPacketEvent{
		Direction:       stack.NetworkPacketEgress,
		NICID:           1,
		NetworkProtocol: 0x800,
		TotalLength:     1234,
	})
	record, err := rb.ops.(*ringbufMap).ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord() failed: %v", err)
	}
	if got := hostarch.ByteOrder.Uint64(record); got != 1234 {
		t.Fatalf("ringbuf record = %d, want 1234", got)
	}
}
