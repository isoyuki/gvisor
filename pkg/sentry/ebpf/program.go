package ebpf

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
)

// Program is a verified sandbox-local eBPF program.
type Program struct {
	objectBase

	typ                linux.BPFProgramType
	attachType         linux.BPFAttachType
	expectedAttachType linux.BPFAttachType
	license            string
	insns              []Insn
	maps               []*Map
	aux                map[int]*Map
	verified           *VerifiedProgram
	ctxAccesses        []ContextAccess
	helperCalls        map[linux.BPFHelperID]struct{}
}

// Type returns the program type.
func (p *Program) Type() linux.BPFProgramType {
	return p.typ
}

// Instructions returns a copy of the program instructions.
func (p *Program) Instructions() []Insn {
	return append([]Insn(nil), p.insns...)
}

func (p *Program) releaseRefs(ctx context.Context) {
	for _, mp := range p.maps {
		mp.DecRef(ctx)
	}
}

// InsnAux contains verifier/runtime metadata for an instruction.
type InsnAux struct {
	Map *Map
}

// ContextAccess is a verifier-validated load/store against the program context.
type ContextAccess struct {
	Offset int32
	Size   uint32
	Write  bool
}

// VerifiedProgram is the verifier output consumed by the VM.
type VerifiedProgram struct {
	insns       []Insn
	aux         []InsnAux
	progType    linux.BPFProgramType
	ctxSpec     *ContextSpec
	maxStack    uint32
	maySleep    bool
	mayWrite    bool
	helpersOK   func(linux.BPFHelperID) bool
	ctxAccesses []ContextAccess
	helperCalls map[linux.BPFHelperID]struct{}
}

func cloneHelperCalls(in map[linux.BPFHelperID]struct{}) map[linux.BPFHelperID]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[linux.BPFHelperID]struct{}, len(in))
	for id := range in {
		out[id] = struct{}{}
	}
	return out
}
