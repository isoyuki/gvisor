package ebpf

import (
	"math/bits"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// RuntimePtrKind identifies a VM pointer kind.
type RuntimePtrKind uint8

const (
	// RuntimePtrNone is not a pointer.
	RuntimePtrNone RuntimePtrKind = iota
	// RuntimePtrCtx points into a RuntimeContext.
	RuntimePtrCtx
	// RuntimePtrStack points into the eBPF stack.
	RuntimePtrStack
	// RuntimePtrMap points to a map object.
	RuntimePtrMap
	// RuntimePtrMapValue points to a map value handle.
	RuntimePtrMapValue
	// RuntimePtrRingbufRecord points to a reserved ring-buffer record.
	RuntimePtrRingbufRecord
)

// RuntimePtr is pointer metadata for one VM register.
type RuntimePtr struct {
	Kind RuntimePtrKind
	Off  int64

	Ctx           RuntimeContext
	Stack         *[512]byte
	Map           *Map
	MapValue      *MapValue
	RingbufRecord *ringbufRecord
}

// RuntimeReg is a VM register.
type RuntimeReg struct {
	U64 uint64
	Ptr RuntimePtr
}

// TaskInfo is sandbox task metadata exposed to helpers.
type TaskInfo struct {
	PID  uint32
	TGID uint32
	UID  uint32
	GID  uint32
	Comm string
}

// ExecRequest describes one eBPF program invocation.
type ExecRequest struct {
	Program      *Program
	Context      RuntimeContext
	Task         TaskInfo
	MaxTailCalls uint32
}

// ExecResult is the result of one eBPF program invocation.
type ExecResult struct {
	R0 uint64
}

type vm struct {
	req   ExecRequest
	regs  [11]RuntimeReg
	stack [512]byte
	pc    int
}

// Execute runs a verified eBPF program in the pure-Go interpreter.
func Execute(req ExecRequest) (ExecResult, error) {
	if req.Program == nil || req.Program.verified == nil {
		return ExecResult{}, linuxerr.EINVAL
	}
	v := &vm{req: req}
	v.regs[linux.BPF_REG_1] = RuntimeReg{
		U64: 1,
		Ptr: RuntimePtr{Kind: RuntimePtrCtx, Ctx: req.Context},
	}
	v.regs[linux.BPF_REG_10] = RuntimeReg{
		U64: uint64(len(v.stack)),
		Ptr: RuntimePtr{Kind: RuntimePtrStack, Off: int64(len(v.stack)), Stack: &v.stack},
	}
	insns := req.Program.verified.insns
	for v.pc >= 0 && v.pc < len(insns) {
		ins := insns[v.pc]
		switch insnClass(ins.OpCode) {
		case linux.BPF_LD:
			if err := v.execLD(ins); err != nil {
				return ExecResult{}, err
			}
		case linux.BPF_LDX:
			if err := v.execLDX(ins); err != nil {
				return ExecResult{}, err
			}
		case linux.BPF_ST, linux.BPF_STX:
			if err := v.execSTX(ins); err != nil {
				return ExecResult{}, err
			}
		case linux.BPF_ALU, linux.BPF_ALU64:
			if err := v.execALU(ins); err != nil {
				return ExecResult{}, err
			}
		case linux.BPF_JMP, linux.BPF_JMP32:
			done, err := v.execJMP(ins)
			if err != nil {
				return ExecResult{}, err
			}
			if done {
				return ExecResult{R0: v.regs[linux.BPF_REG_0].U64}, nil
			}
		default:
			return ExecResult{}, linuxerr.EINVAL
		}
	}
	return ExecResult{}, linuxerr.EINVAL
}

func (v *vm) execLD(ins Insn) error {
	if ins.OpCode != linux.BPF_LD|linux.BPF_DW|linux.BPF_IMM || v.pc+1 >= len(v.req.Program.verified.insns) {
		return linuxerr.EINVAL
	}
	next := v.req.Program.verified.insns[v.pc+1]
	imm := uint64(uint32(ins.Imm)) | (uint64(uint32(next.Imm)) << 32)
	if mp := v.req.Program.aux[v.pc]; mp != nil {
		v.regs[ins.Dst] = RuntimeReg{U64: uint64(mp.ID()) + 1, Ptr: RuntimePtr{Kind: RuntimePtrMap, Map: mp}}
	} else {
		v.regs[ins.Dst] = RuntimeReg{U64: imm}
	}
	v.pc += 2
	return nil
}

func (v *vm) execLDX(ins Insn) error {
	size, ok := accessSize(ins.OpCode)
	if !ok {
		return linuxerr.EINVAL
	}
	value, err := v.load(v.regs[ins.Src].Ptr, int64(ins.Off), size)
	if err != nil {
		return err
	}
	v.regs[ins.Dst] = RuntimeReg{U64: value}
	v.pc++
	return nil
}

func (v *vm) execSTX(ins Insn) error {
	size, ok := accessSize(ins.OpCode)
	if !ok {
		return linuxerr.EINVAL
	}
	value := uint64(uint32(ins.Imm))
	if insnClass(ins.OpCode) == linux.BPF_STX {
		value = v.regs[ins.Src].U64
	}
	if err := v.store(v.regs[ins.Dst].Ptr, int64(ins.Off), size, value); err != nil {
		return err
	}
	v.pc++
	return nil
}

func (v *vm) execALU(ins Insn) error {
	dst := v.regs[ins.Dst]
	src := uint64(uint32(ins.Imm))
	srcPtr := RuntimePtr{}
	if insnSrc(ins.OpCode) == linux.BPF_X {
		src = v.regs[ins.Src].U64
		srcPtr = v.regs[ins.Src].Ptr
	}
	width32 := insnClass(ins.OpCode) == linux.BPF_ALU
	switch insnOp(ins.OpCode) {
	case linux.BPF_MOV:
		if insnSrc(ins.OpCode) == linux.BPF_X {
			dst = RuntimeReg{U64: src, Ptr: srcPtr}
		} else {
			dst = RuntimeReg{U64: src}
		}
	case linux.BPF_ADD:
		dst.U64 += src
		dst.Ptr.Off += int64(int32(src))
	case linux.BPF_SUB:
		dst.U64 -= src
		dst.Ptr.Off -= int64(int32(src))
	case linux.BPF_MUL:
		dst.U64 *= src
		dst.Ptr = RuntimePtr{}
	case linux.BPF_DIV:
		if src == 0 {
			return linuxerr.EINVAL
		}
		dst.U64 /= src
		dst.Ptr = RuntimePtr{}
	case linux.BPF_OR:
		dst.U64 |= src
		dst.Ptr = RuntimePtr{}
	case linux.BPF_AND:
		dst.U64 &= src
		dst.Ptr = RuntimePtr{}
	case linux.BPF_LSH:
		dst.U64 <<= (src & 63)
		dst.Ptr = RuntimePtr{}
	case linux.BPF_RSH:
		dst.U64 >>= (src & 63)
		dst.Ptr = RuntimePtr{}
	case linux.BPF_ARSH:
		dst.U64 = uint64(int64(dst.U64) >> (src & 63))
		dst.Ptr = RuntimePtr{}
	case linux.BPF_NEG:
		dst.U64 = uint64(-int64(dst.U64))
		dst.Ptr = RuntimePtr{}
	case linux.BPF_MOD:
		if src == 0 {
			return linuxerr.EINVAL
		}
		dst.U64 %= src
		dst.Ptr = RuntimePtr{}
	case linux.BPF_XOR:
		dst.U64 ^= src
		dst.Ptr = RuntimePtr{}
	case linux.BPF_END:
		switch ins.Imm {
		case 16:
			dst.U64 = uint64(bits.ReverseBytes16(uint16(dst.U64)))
		case 32:
			dst.U64 = uint64(bits.ReverseBytes32(uint32(dst.U64)))
		case 64:
			dst.U64 = bits.ReverseBytes64(dst.U64)
		default:
			return linuxerr.EINVAL
		}
		dst.Ptr = RuntimePtr{}
	default:
		return linuxerr.EINVAL
	}
	if width32 {
		dst.U64 = uint64(uint32(dst.U64))
	}
	v.regs[ins.Dst] = dst
	v.pc++
	return nil
}

func (v *vm) execJMP(ins Insn) (bool, error) {
	op := insnOp(ins.OpCode)
	switch op {
	case linux.BPF_EXIT:
		return true, nil
	case linux.BPF_CALL:
		if ins.Src != 0 {
			return false, linuxerr.EINVAL
		}
		if err := v.callHelper(linux.BPFHelperID(ins.Imm)); err != nil {
			return false, err
		}
		v.pc++
		return false, nil
	}
	dst := v.regs[ins.Dst].U64
	src := uint64(uint32(ins.Imm))
	if insnSrc(ins.OpCode) == linux.BPF_X {
		src = v.regs[ins.Src].U64
	}
	take := false
	switch op {
	case linux.BPF_JA:
		take = true
	case linux.BPF_JEQ:
		take = dst == src
	case linux.BPF_JNE:
		take = dst != src
	case linux.BPF_JGT:
		take = dst > src
	case linux.BPF_JGE:
		take = dst >= src
	case linux.BPF_JLT:
		take = dst < src
	case linux.BPF_JLE:
		take = dst <= src
	case linux.BPF_JSET:
		take = dst&src != 0
	case linux.BPF_JSGT:
		take = int64(dst) > int64(src)
	case linux.BPF_JSGE:
		take = int64(dst) >= int64(src)
	case linux.BPF_JSLT:
		take = int64(dst) < int64(src)
	case linux.BPF_JSLE:
		take = int64(dst) <= int64(src)
	default:
		return false, linuxerr.EINVAL
	}
	if take {
		v.pc += 1 + int(ins.Off)
	} else {
		v.pc++
	}
	return false, nil
}

func (v *vm) load(ptr RuntimePtr, extraOff int64, size uint32) (uint64, error) {
	off := ptr.Off + extraOff
	switch ptr.Kind {
	case RuntimePtrCtx:
		return ptr.Ctx.Load(int32(off), size)
	case RuntimePtrStack:
		return loadBytes(ptr.Stack[:], off, size)
	case RuntimePtrMapValue:
		return ptr.MapValue.load(off, size)
	case RuntimePtrRingbufRecord:
		return ptr.RingbufRecord.load(off, size)
	default:
		return 0, linuxerr.EFAULT
	}
}

func (v *vm) store(ptr RuntimePtr, extraOff int64, size uint32, value uint64) error {
	off := ptr.Off + extraOff
	switch ptr.Kind {
	case RuntimePtrCtx:
		return ptr.Ctx.Store(int32(off), size, value)
	case RuntimePtrStack:
		return storeBytes(ptr.Stack[:], off, size, value)
	case RuntimePtrMapValue:
		return ptr.MapValue.store(off, size, value)
	case RuntimePtrRingbufRecord:
		return ptr.RingbufRecord.store(off, size, value)
	default:
		return linuxerr.EFAULT
	}
}

func (v *vm) readMemory(reg RuntimeReg, size uint32) ([]byte, error) {
	out := make([]byte, size)
	for off := uint32(0); off < size; off++ {
		b, err := v.load(reg.Ptr, int64(off), 1)
		if err != nil {
			return nil, err
		}
		out[off] = byte(b)
	}
	return out, nil
}

func (v *vm) writeMemory(reg RuntimeReg, data []byte) error {
	for off, b := range data {
		if err := v.store(reg.Ptr, int64(off), 1, uint64(b)); err != nil {
			return err
		}
	}
	return nil
}

func scalarToBytes(value uint64, size uint32) []byte {
	out := make([]byte, size)
	switch size {
	case 1:
		out[0] = byte(value)
	case 2:
		hostarch.ByteOrder.PutUint16(out, uint16(value))
	case 4:
		hostarch.ByteOrder.PutUint32(out, uint32(value))
	case 8:
		hostarch.ByteOrder.PutUint64(out, value)
	}
	return out
}
