package ebpf

import "gvisor.dev/gvisor/pkg/abi/linux"

func mov64Imm(dst uint8, imm int32) Insn {
	return Insn{OpCode: linux.BPF_ALU64 | linux.BPF_MOV | linux.BPF_K, Dst: dst, Imm: imm}
}

func mov64Reg(dst, src uint8) Insn {
	return Insn{OpCode: linux.BPF_ALU64 | linux.BPF_MOV | linux.BPF_X, Dst: dst, Src: src}
}

func alu64Imm(op uint8, dst uint8, imm int32) Insn {
	return Insn{OpCode: linux.BPF_ALU64 | op | linux.BPF_K, Dst: dst, Imm: imm}
}

func stMem(size uint8, dst uint8, off int16, imm int32) Insn {
	return Insn{OpCode: linux.BPF_ST | size | linux.BPF_MEM, Dst: dst, Off: off, Imm: imm}
}

func stxMem(size uint8, dst, src uint8, off int16) Insn {
	return Insn{OpCode: linux.BPF_STX | size | linux.BPF_MEM, Dst: dst, Src: src, Off: off}
}

func ldxMem(size uint8, dst, src uint8, off int16) Insn {
	return Insn{OpCode: linux.BPF_LDX | size | linux.BPF_MEM, Dst: dst, Src: src, Off: off}
}

func callInsn(id linux.BPFHelperID) Insn {
	return Insn{OpCode: linux.BPF_JMP | linux.BPF_CALL, Imm: int32(id)}
}

func jmpImm(op uint8, dst uint8, imm int32, off int16) Insn {
	return Insn{OpCode: linux.BPF_JMP | op | linux.BPF_K, Dst: dst, Off: off, Imm: imm}
}

func exitInsn() Insn {
	return Insn{OpCode: linux.BPF_JMP | linux.BPF_EXIT}
}

func ldMapFD(dst uint8, fd int32) Insn {
	return Insn{OpCode: linux.BPF_LD | linux.BPF_DW | linux.BPF_IMM, Dst: dst, Src: linux.BPF_PSEUDO_MAP_FD, Imm: fd}
}
