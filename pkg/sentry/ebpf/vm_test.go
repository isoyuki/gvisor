package ebpf

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
)

func TestProgramLoadAndExecuteReturnImmediate(t *testing.T) {
	mgr := NewManager(DefaultConfig(true))
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_SYSCALL,
		Insns: []Insn{
			mov64Imm(linux.BPF_REG_0, 42),
			exitInsn(),
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	r0, err := mgr.ProgramTestRun(prog, &SyscallEnterContext{}, TaskInfo{})
	if err != nil {
		t.Fatalf("ProgramTestRun() failed: %v", err)
	}
	if r0 != 42 {
		t.Fatalf("ProgramTestRun() = %d, want 42", r0)
	}
}

func TestMapLookupHelper(t *testing.T) {
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
	var key [4]byte
	var value [8]byte
	hostarch.ByteOrder.PutUint64(value[:], 99)
	if err := mp.Update(key[:], value[:], linux.BPF_ANY); err != nil {
		t.Fatalf("Map.Update() failed: %v", err)
	}
	prog, _, err := mgr.ProgramLoad(ProgramLoadAttrs{
		Type: linux.BPF_PROG_TYPE_SYSCALL,
		Insns: []Insn{
			ldMapFD(linux.BPF_REG_1, 7),
			{},
			stMem(linux.BPF_W, linux.BPF_REG_10, -4, 0),
			mov64Reg(linux.BPF_REG_2, linux.BPF_REG_10),
			alu64Imm(linux.BPF_ADD, linux.BPF_REG_2, -4),
			callInsn(linux.BPF_FUNC_map_lookup_elem),
			jmpImm(linux.BPF_JNE, linux.BPF_REG_0, 0, 1),
			exitInsn(),
			ldxMem(linux.BPF_DW, linux.BPF_REG_0, linux.BPF_REG_0, 0),
			exitInsn(),
		},
		MapResolver: func(fd int32) (*Map, error) {
			if fd != 7 {
				t.Fatalf("MapResolver(%d), want 7", fd)
			}
			mp.IncRef()
			return mp, nil
		},
	})
	if err != nil {
		t.Fatalf("ProgramLoad() failed: %v", err)
	}
	r0, err := mgr.ProgramTestRun(prog, &SyscallEnterContext{}, TaskInfo{})
	if err != nil {
		t.Fatalf("ProgramTestRun() failed: %v", err)
	}
	if r0 != 99 {
		t.Fatalf("ProgramTestRun() = %d, want 99", r0)
	}
}
