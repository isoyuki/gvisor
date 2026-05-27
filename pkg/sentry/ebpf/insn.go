package ebpf

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// Insn is a decoded Linux struct bpf_insn.
type Insn struct {
	OpCode uint8
	Dst    uint8
	Src    uint8
	Off    int16
	Imm    int32
}

// DecodeInsns decodes raw Linux struct bpf_insn bytes.
func DecodeInsns(raw []byte) ([]Insn, error) {
	if len(raw) == 0 || len(raw)%8 != 0 {
		return nil, linuxerr.EINVAL
	}
	insns := make([]Insn, len(raw)/8)
	for i := range insns {
		buf := raw[i*8:]
		insns[i] = Insn{
			OpCode: buf[0],
			Dst:    buf[1] & 0xf,
			Src:    buf[1] >> 4,
			Off:    int16(hostarch.ByteOrder.Uint16(buf[2:])),
			Imm:    int32(hostarch.ByteOrder.Uint32(buf[4:])),
		}
		if insns[i].Dst > linux.BPF_REG_10 || insns[i].Src > linux.BPF_REG_10 {
			return nil, linuxerr.EINVAL
		}
	}
	return insns, nil
}

func (i Insn) String() string {
	return fmt.Sprintf("op=%#x dst=r%d src=r%d off=%d imm=%d", i.OpCode, i.Dst, i.Src, i.Off, i.Imm)
}

func insnClass(op uint8) uint8 {
	return op & 0x07
}

func insnSize(op uint8) uint8 {
	return op & 0x18
}

func insnMode(op uint8) uint8 {
	return op & 0xe0
}

func insnOp(op uint8) uint8 {
	return op & 0xf0
}

func insnSrc(op uint8) uint8 {
	return op & 0x08
}

func accessSize(op uint8) (uint32, bool) {
	switch insnSize(op) {
	case linux.BPF_B:
		return 1, true
	case linux.BPF_H:
		return 2, true
	case linux.BPF_W:
		return 4, true
	case linux.BPF_DW:
		return 8, true
	default:
		return 0, false
	}
}
