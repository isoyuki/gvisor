package ebpf

import (
	"fmt"
	"math"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// RegType is a verifier register type.
type RegType uint8

const (
	// RegNotInit is an unreadable register.
	RegNotInit RegType = iota
	// RegScalar is a scalar value.
	RegScalar
	// RegPtrToCtx is a context pointer.
	RegPtrToCtx
	// RegConstPtrToMap is a map pointer.
	RegConstPtrToMap
	// RegPtrToMapValue is a non-null map value pointer.
	RegPtrToMapValue
	// RegPtrToMapValueOrNull is a nullable map value pointer.
	RegPtrToMapValueOrNull
	// RegPtrToStack is a stack pointer.
	RegPtrToStack
	// RegPtrToRingbufMem is a ring-buffer reservation pointer.
	RegPtrToRingbufMem
)

// Tnum is a conservative tracked-number representation.
type Tnum struct {
	Value uint64
	Mask  uint64
}

// RegState is verifier state for one eBPF register.
type RegState struct {
	Type     RegType
	ID       uint32
	FixedOff int32
	VarOff   Tnum

	UMin uint64
	UMax uint64
	SMin int64
	SMax int64

	Map       *Map
	ValueSize uint32
	Readable  bool
	Precise   bool
}

type stackSlotKind uint8

const (
	stackInvalid stackSlotKind = iota
	stackScalar
	stackSpilledPtr
	stackMisc
)

type stackSlot struct {
	kind     stackSlotKind
	reg      RegState
	initMask uint8
}

type verifierState struct {
	pc     int
	regs   [11]RegState
	stack  [64]stackSlot
	nextID uint32
}

// VerifyRequest contains inputs to the verifier.
type VerifyRequest struct {
	Insns             []Insn
	ProgType          linux.BPFProgramType
	Context           *ContextSpec
	Maps              map[int]*Map
	MaxStates         uint32
	HelperAllowed     func(linux.BPFHelperID) bool
	MaxProgramInsns   uint32
	ExpectedAttachTyp linux.BPFAttachType
	Log               *Log

	recordContextAccess func(ContextAccess)
	recordHelperCall    func(linux.BPFHelperID)
}

// Log is a verifier log buffer.
type Log struct {
	enabled bool
	level   uint32
	b       strings.Builder
}

func newLog(level uint32) *Log {
	return &Log{enabled: level != 0, level: level}
}

func (l *Log) add(format string, args ...any) {
	if l == nil || !l.enabled {
		return
	}
	fmt.Fprintf(&l.b, format, args...)
	l.b.WriteByte('\n')
}

// String returns the verifier log.
func (l *Log) String() string {
	if l == nil {
		return ""
	}
	return l.b.String()
}

// Verify verifies an eBPF program conservatively.
func Verify(req VerifyRequest) (*VerifiedProgram, error) {
	if req.Log == nil {
		req.Log = newLog(0)
	}
	if req.HelperAllowed == nil {
		req.HelperAllowed = func(linux.BPFHelperID) bool { return true }
	}
	if req.MaxStates == 0 {
		req.MaxStates = 100000
	}
	if err := validateCFG(req.Insns, req.Log); err != nil {
		return nil, err
	}
	ctxAccessSeen := make(map[ContextAccess]struct{})
	var ctxAccesses []ContextAccess
	req.recordContextAccess = func(access ContextAccess) {
		if _, ok := ctxAccessSeen[access]; ok {
			return
		}
		ctxAccessSeen[access] = struct{}{}
		ctxAccesses = append(ctxAccesses, access)
	}
	helperCalls := make(map[linux.BPFHelperID]struct{})
	req.recordHelperCall = func(id linux.BPFHelperID) {
		helperCalls[id] = struct{}{}
	}

	aux := make([]InsnAux, len(req.Insns))
	for pc, mp := range req.Maps {
		if pc >= 0 && pc < len(aux) {
			aux[pc].Map = mp
		}
	}

	st := initialState(req.Context)
	work := []verifierState{st}
	states := uint32(0)
	exited := false
	for len(work) != 0 {
		st = work[len(work)-1]
		work = work[:len(work)-1]
		if st.pc < 0 || st.pc >= len(req.Insns) {
			req.Log.add("%d: pc out of range", st.pc)
			return nil, linuxerr.EINVAL
		}
		states++
		if states > req.MaxStates {
			req.Log.add("%d: verifier state limit exceeded", st.pc)
			return nil, linuxerr.E2BIG
		}
		next, didExit, err := stepVerify(req, aux, st)
		if err != nil {
			return nil, err
		}
		if didExit {
			exited = true
			continue
		}
		work = append(work, next...)
	}
	if !exited {
		req.Log.add("program has no exit")
		return nil, linuxerr.EINVAL
	}
	return &VerifiedProgram{
		insns:       append([]Insn(nil), req.Insns...),
		aux:         aux,
		progType:    req.ProgType,
		ctxSpec:     req.Context,
		maxStack:    maxStackDepth(req.Insns),
		helpersOK:   req.HelperAllowed,
		ctxAccesses: ctxAccesses,
		helperCalls: cloneHelperCalls(helperCalls),
	}, nil
}

func initialState(ctx *ContextSpec) verifierState {
	var st verifierState
	st.regs[linux.BPF_REG_1] = RegState{Type: RegPtrToCtx, Readable: true, ValueSize: ctx.Size}
	st.regs[linux.BPF_REG_10] = RegState{Type: RegPtrToStack, Readable: true}
	for i := range st.regs {
		if i != linux.BPF_REG_1 && i != linux.BPF_REG_10 {
			st.regs[i] = RegState{Type: RegNotInit}
		}
	}
	return st
}

func scalarUnknown() RegState {
	return RegState{Type: RegScalar, UMax: math.MaxUint64, SMin: math.MinInt64, SMax: math.MaxInt64, Readable: true}
}

func scalarConst(v uint64) RegState {
	return RegState{Type: RegScalar, UMin: v, UMax: v, SMin: int64(v), SMax: int64(v), Readable: true}
}

func validateCFG(insns []Insn, log *Log) error {
	if len(insns) == 0 {
		log.add("empty program")
		return linuxerr.EINVAL
	}
	secondHalf := make(map[int]bool)
	for pc, ins := range insns {
		if ins.OpCode == linux.BPF_LD|linux.BPF_DW|linux.BPF_IMM {
			if pc+1 >= len(insns) {
				log.add("%d: truncated ldimm64", pc)
				return linuxerr.EINVAL
			}
			secondHalf[pc+1] = true
		}
	}
	for pc, ins := range insns {
		if secondHalf[pc] {
			continue
		}
		if insnClass(ins.OpCode) != linux.BPF_JMP && insnClass(ins.OpCode) != linux.BPF_JMP32 {
			continue
		}
		op := insnOp(ins.OpCode)
		if op == linux.BPF_EXIT || op == linux.BPF_CALL {
			continue
		}
		target := pc + 1 + int(ins.Off)
		if op == linux.BPF_JA {
			target = pc + 1 + int(ins.Off)
		}
		if target < 0 || target >= len(insns) {
			log.add("%d: invalid jump target %d", pc, target)
			return linuxerr.EINVAL
		}
		if target <= pc {
			log.add("%d: backward jumps are not supported", pc)
			return linuxerr.EINVAL
		}
		if secondHalf[target] {
			log.add("%d: jump into ldimm64 second half", pc)
			return linuxerr.EINVAL
		}
	}
	return nil
}

func stepVerify(req VerifyRequest, aux []InsnAux, st verifierState) ([]verifierState, bool, error) {
	ins := req.Insns[st.pc]
	req.Log.add("%d: %s", st.pc, ins.String())
	switch insnClass(ins.OpCode) {
	case linux.BPF_LD:
		return verifyLD(req, aux, st, ins)
	case linux.BPF_LDX:
		return verifyLDX(req, st, ins)
	case linux.BPF_ST, linux.BPF_STX:
		return verifySTX(req, st, ins)
	case linux.BPF_ALU, linux.BPF_ALU64:
		return verifyALU(req, st, ins)
	case linux.BPF_JMP, linux.BPF_JMP32:
		return verifyJMP(req, st, ins)
	default:
		req.Log.add("%d: unsupported instruction class %#x", st.pc, insnClass(ins.OpCode))
		return nil, false, linuxerr.EINVAL
	}
}

func verifyLD(req VerifyRequest, aux []InsnAux, st verifierState, ins Insn) ([]verifierState, bool, error) {
	if ins.OpCode != linux.BPF_LD|linux.BPF_DW|linux.BPF_IMM {
		req.Log.add("%d: unsupported ld mode", st.pc)
		return nil, false, linuxerr.EINVAL
	}
	if st.pc+1 >= len(req.Insns) {
		req.Log.add("%d: truncated ldimm64", st.pc)
		return nil, false, linuxerr.EINVAL
	}
	if mp := aux[st.pc].Map; mp != nil {
		st.regs[ins.Dst] = RegState{Type: RegConstPtrToMap, Map: mp, Readable: true, ValueSize: mp.ValueSize()}
	} else {
		st.regs[ins.Dst] = RegState{Type: RegScalar, Readable: true}
	}
	st.pc += 2
	return []verifierState{st}, false, nil
}

func verifyLDX(req VerifyRequest, st verifierState, ins Insn) ([]verifierState, bool, error) {
	if insnMode(ins.OpCode) != linux.BPF_MEM {
		req.Log.add("%d: unsupported ldx mode", st.pc)
		return nil, false, linuxerr.EINVAL
	}
	size, ok := accessSize(ins.OpCode)
	if !ok {
		req.Log.add("%d: invalid ldx size", st.pc)
		return nil, false, linuxerr.EINVAL
	}
	src := st.regs[ins.Src]
	switch src.Type {
	case RegPtrToStack:
		off := src.FixedOff + int32(ins.Off)
		if !stackReadable(st, off, size) {
			req.Log.add("%d: invalid stack read off=%d size=%d", st.pc, off, size)
			return nil, false, linuxerr.EACCES
		}
		if spilled, ok := loadStackSpilledPtr(st, off, size); ok {
			st.regs[ins.Dst] = spilled
		} else {
			st.regs[ins.Dst] = scalarUnknown()
		}
	case RegPtrToMapValue, RegPtrToRingbufMem:
		if !valueBounds(src, int32(ins.Off), size) {
			req.Log.add("%d: invalid map value read off=%d size=%d", st.pc, int32(ins.Off), size)
			return nil, false, linuxerr.EACCES
		}
		st.regs[ins.Dst] = scalarUnknown()
	case RegPtrToCtx:
		reg, ok := req.Context.ValidAccess(src.FixedOff+int32(ins.Off), size, false)
		if !ok {
			req.Log.add("%d: invalid ctx access off=%d size=%d", st.pc, src.FixedOff+int32(ins.Off), size)
			return nil, false, linuxerr.EACCES
		}
		if req.recordContextAccess != nil {
			req.recordContextAccess(ContextAccess{Offset: src.FixedOff + int32(ins.Off), Size: size})
		}
		st.regs[ins.Dst] = reg
	default:
		req.Log.add("%d: R%d is not a readable pointer", st.pc, ins.Src)
		return nil, false, linuxerr.EACCES
	}
	st.pc++
	return []verifierState{st}, false, nil
}

func verifySTX(req VerifyRequest, st verifierState, ins Insn) ([]verifierState, bool, error) {
	if insnMode(ins.OpCode) != linux.BPF_MEM {
		req.Log.add("%d: unsupported store mode", st.pc)
		return nil, false, linuxerr.EINVAL
	}
	size, ok := accessSize(ins.OpCode)
	if !ok {
		req.Log.add("%d: invalid store size", st.pc)
		return nil, false, linuxerr.EINVAL
	}
	dst := st.regs[ins.Dst]
	if insnClass(ins.OpCode) == linux.BPF_STX && !st.regs[ins.Src].Readable {
		req.Log.add("%d: R%d !read_ok", st.pc, ins.Src)
		return nil, false, linuxerr.EACCES
	}
	switch dst.Type {
	case RegPtrToStack:
		off := dst.FixedOff + int32(ins.Off)
		if !validStack(off, size) {
			req.Log.add("%d: invalid stack write off=%d size=%d", st.pc, off, size)
			return nil, false, linuxerr.EACCES
		}
		markStackWritten(&st, off, size, insnClass(ins.OpCode) == linux.BPF_STX, st.regs[ins.Src])
	case RegPtrToMapValue, RegPtrToRingbufMem:
		if !valueBounds(dst, int32(ins.Off), size) {
			req.Log.add("%d: invalid map value write off=%d size=%d", st.pc, int32(ins.Off), size)
			return nil, false, linuxerr.EACCES
		}
	case RegPtrToCtx:
		off := dst.FixedOff + int32(ins.Off)
		if _, ok := req.Context.ValidAccess(off, size, true); !ok {
			req.Log.add("%d: invalid ctx write off=%d size=%d", st.pc, off, size)
			return nil, false, linuxerr.EACCES
		}
		if req.recordContextAccess != nil {
			req.recordContextAccess(ContextAccess{Offset: off, Size: size, Write: true})
		}
	default:
		req.Log.add("%d: R%d is not a writable pointer", st.pc, ins.Dst)
		return nil, false, linuxerr.EACCES
	}
	st.pc++
	return []verifierState{st}, false, nil
}

func verifyALU(req VerifyRequest, st verifierState, ins Insn) ([]verifierState, bool, error) {
	op := insnOp(ins.OpCode)
	dst := st.regs[ins.Dst]
	switch op {
	case linux.BPF_MOV:
		if insnSrc(ins.OpCode) == linux.BPF_X {
			if !st.regs[ins.Src].Readable {
				req.Log.add("%d: R%d !read_ok", st.pc, ins.Src)
				return nil, false, linuxerr.EACCES
			}
			st.regs[ins.Dst] = st.regs[ins.Src]
		} else {
			st.regs[ins.Dst] = scalarConst(uint64(uint32(ins.Imm)))
		}
	case linux.BPF_ADD, linux.BPF_SUB:
		if !dst.Readable {
			req.Log.add("%d: R%d !read_ok", st.pc, ins.Dst)
			return nil, false, linuxerr.EACCES
		}
		if insnSrc(ins.OpCode) == linux.BPF_X && !st.regs[ins.Src].Readable {
			req.Log.add("%d: R%d !read_ok", st.pc, ins.Src)
			return nil, false, linuxerr.EACCES
		}
		if dst.Type == RegPtrToStack && insnSrc(ins.OpCode) == linux.BPF_K {
			if op == linux.BPF_ADD {
				dst.FixedOff += ins.Imm
			} else {
				dst.FixedOff -= ins.Imm
			}
			st.regs[ins.Dst] = dst
		} else if (dst.Type == RegPtrToMapValue || dst.Type == RegPtrToRingbufMem) && insnSrc(ins.OpCode) == linux.BPF_K {
			if op == linux.BPF_ADD {
				dst.FixedOff += ins.Imm
			} else {
				dst.FixedOff -= ins.Imm
			}
			st.regs[ins.Dst] = dst
		} else {
			st.regs[ins.Dst] = scalarUnknown()
		}
	case linux.BPF_MUL, linux.BPF_OR, linux.BPF_AND, linux.BPF_LSH, linux.BPF_RSH, linux.BPF_ARSH, linux.BPF_NEG, linux.BPF_XOR, linux.BPF_END:
		if !dst.Readable {
			req.Log.add("%d: R%d !read_ok", st.pc, ins.Dst)
			return nil, false, linuxerr.EACCES
		}
		if insnSrc(ins.OpCode) == linux.BPF_X && !st.regs[ins.Src].Readable {
			req.Log.add("%d: R%d !read_ok", st.pc, ins.Src)
			return nil, false, linuxerr.EACCES
		}
		st.regs[ins.Dst] = scalarUnknown()
	case linux.BPF_DIV, linux.BPF_MOD:
		if !dst.Readable {
			req.Log.add("%d: R%d !read_ok", st.pc, ins.Dst)
			return nil, false, linuxerr.EACCES
		}
		if insnSrc(ins.OpCode) == linux.BPF_X && !st.regs[ins.Src].Readable {
			req.Log.add("%d: R%d !read_ok", st.pc, ins.Src)
			return nil, false, linuxerr.EACCES
		}
		if insnSrc(ins.OpCode) == linux.BPF_K && ins.Imm == 0 {
			req.Log.add("%d: division by zero", st.pc)
			return nil, false, linuxerr.EACCES
		}
		st.regs[ins.Dst] = scalarUnknown()
	default:
		req.Log.add("%d: unsupported alu op %#x", st.pc, op)
		return nil, false, linuxerr.EINVAL
	}
	st.pc++
	return []verifierState{st}, false, nil
}

func verifyJMP(req VerifyRequest, st verifierState, ins Insn) ([]verifierState, bool, error) {
	op := insnOp(ins.OpCode)
	switch op {
	case linux.BPF_EXIT:
		if !st.regs[linux.BPF_REG_0].Readable {
			req.Log.add("%d: R0 !read_ok", st.pc)
			return nil, false, linuxerr.EACCES
		}
		return nil, true, nil
	case linux.BPF_CALL:
		return verifyHelperCall(req, st, ins)
	case linux.BPF_JA:
		st.pc = st.pc + 1 + int(ins.Off)
		return []verifierState{st}, false, nil
	}

	if !st.regs[ins.Dst].Readable {
		req.Log.add("%d: R%d !read_ok", st.pc, ins.Dst)
		return nil, false, linuxerr.EACCES
	}
	if insnSrc(ins.OpCode) == linux.BPF_X && !st.regs[ins.Src].Readable {
		req.Log.add("%d: R%d !read_ok", st.pc, ins.Src)
		return nil, false, linuxerr.EACCES
	}
	taken := st
	notTaken := st
	taken.pc = st.pc + 1 + int(ins.Off)
	notTaken.pc = st.pc + 1
	refineNullBranches(ins, &taken, &notTaken)
	return []verifierState{taken, notTaken}, false, nil
}

func verifyHelperCall(req VerifyRequest, st verifierState, ins Insn) ([]verifierState, bool, error) {
	id := linux.BPFHelperID(ins.Imm)
	if !req.HelperAllowed(id) {
		req.Log.add("%d: helper %d is not enabled", st.pc, id)
		return nil, false, linuxerr.EACCES
	}
	if req.recordHelperCall != nil {
		req.recordHelperCall(id)
	}
	switch id {
	case linux.BPF_FUNC_map_lookup_elem:
		if err := checkMapLookupArgs(req, st); err != nil {
			return nil, false, err
		}
		mp := st.regs[linux.BPF_REG_1].Map
		st.nextID++
		st.regs[linux.BPF_REG_0] = RegState{Type: RegPtrToMapValueOrNull, ID: st.nextID, Map: mp, ValueSize: mp.ValueSize(), Readable: true}
	case linux.BPF_FUNC_map_update_elem:
		if err := checkMapKeyArg(req, st, linux.BPF_REG_1, linux.BPF_REG_2); err != nil {
			return nil, false, err
		}
		mp := st.regs[linux.BPF_REG_1].Map
		if !readableMemory(st, st.regs[linux.BPF_REG_3], mp.ValueSize()) {
			req.Log.add("%d: helper map_update_elem arg3 expected readable value", st.pc)
			return nil, false, linuxerr.EACCES
		}
		if !st.regs[linux.BPF_REG_4].Readable {
			req.Log.add("%d: helper map_update_elem arg4 !read_ok", st.pc)
			return nil, false, linuxerr.EACCES
		}
		st.regs[linux.BPF_REG_0] = RegState{Type: RegScalar, Readable: true}
	case linux.BPF_FUNC_map_delete_elem:
		if err := checkMapKeyArg(req, st, linux.BPF_REG_1, linux.BPF_REG_2); err != nil {
			return nil, false, err
		}
		st.regs[linux.BPF_REG_0] = RegState{Type: RegScalar, Readable: true}
	case linux.BPF_FUNC_ktime_get_ns, linux.BPF_FUNC_get_current_pid_tgid, linux.BPF_FUNC_get_current_uid_gid:
		st.regs[linux.BPF_REG_0] = RegState{Type: RegScalar, Readable: true}
	case linux.BPF_FUNC_get_current_comm:
		if !readableOrWritableMemory(st, st.regs[linux.BPF_REG_1], uint32(st.regs[linux.BPF_REG_2].UMax), true) {
			req.Log.add("%d: helper get_current_comm arg1 expected writable memory", st.pc)
			return nil, false, linuxerr.EACCES
		}
		st.regs[linux.BPF_REG_0] = RegState{Type: RegScalar, Readable: true}
	case linux.BPF_FUNC_ringbuf_output:
		if st.regs[linux.BPF_REG_1].Type != RegConstPtrToMap || st.regs[linux.BPF_REG_1].Map.Type() != linux.BPF_MAP_TYPE_RINGBUF {
			req.Log.add("%d: helper ringbuf_output arg1 expected ringbuf map", st.pc)
			return nil, false, linuxerr.EACCES
		}
		if !st.regs[linux.BPF_REG_3].Readable {
			req.Log.add("%d: helper ringbuf_output arg3 !read_ok", st.pc)
			return nil, false, linuxerr.EACCES
		}
		if st.regs[linux.BPF_REG_3].UMax > 1<<20 {
			req.Log.add("%d: helper ringbuf_output arg3 size too large or unknown", st.pc)
			return nil, false, linuxerr.EACCES
		}
		if !readableMemory(st, st.regs[linux.BPF_REG_2], uint32(st.regs[linux.BPF_REG_3].UMax)) {
			req.Log.add("%d: helper ringbuf_output arg2 expected readable record", st.pc)
			return nil, false, linuxerr.EACCES
		}
		st.regs[linux.BPF_REG_0] = RegState{Type: RegScalar, Readable: true}
	case linux.BPF_FUNC_ringbuf_reserve:
		if st.regs[linux.BPF_REG_1].Type != RegConstPtrToMap || st.regs[linux.BPF_REG_1].Map.Type() != linux.BPF_MAP_TYPE_RINGBUF {
			req.Log.add("%d: helper ringbuf_reserve arg1 expected ringbuf map", st.pc)
			return nil, false, linuxerr.EACCES
		}
		if !st.regs[linux.BPF_REG_2].Readable {
			req.Log.add("%d: helper ringbuf_reserve arg2 !read_ok", st.pc)
			return nil, false, linuxerr.EACCES
		}
		if st.regs[linux.BPF_REG_2].UMax > 1<<20 {
			req.Log.add("%d: helper ringbuf_reserve arg2 size too large or unknown", st.pc)
			return nil, false, linuxerr.EACCES
		}
		st.nextID++
		st.regs[linux.BPF_REG_0] = RegState{
			Type:      RegPtrToRingbufMem,
			ID:        st.nextID,
			Map:       st.regs[linux.BPF_REG_1].Map,
			ValueSize: uint32(st.regs[linux.BPF_REG_2].UMax),
			Readable:  true,
		}
	case linux.BPF_FUNC_ringbuf_submit, linux.BPF_FUNC_ringbuf_discard:
		if st.regs[linux.BPF_REG_1].Type != RegPtrToRingbufMem {
			req.Log.add("%d: helper ringbuf submit/discard arg1 expected ringbuf reservation", st.pc)
			return nil, false, linuxerr.EACCES
		}
		st.regs[linux.BPF_REG_0] = RegState{Type: RegScalar, Readable: true}
	case linux.BPF_FUNC_tail_call:
		st.regs[linux.BPF_REG_0] = RegState{Type: RegScalar, Readable: true}
	default:
		req.Log.add("%d: unsupported helper %d", st.pc, id)
		return nil, false, linuxerr.EACCES
	}
	for i := linux.BPF_REG_1; i <= linux.BPF_REG_5; i++ {
		st.regs[i] = RegState{Type: RegNotInit}
	}
	st.pc++
	return []verifierState{st}, false, nil
}

func checkMapLookupArgs(req VerifyRequest, st verifierState) error {
	return checkMapKeyArg(req, st, linux.BPF_REG_1, linux.BPF_REG_2)
}

func checkMapKeyArg(req VerifyRequest, st verifierState, mapReg, keyReg uint8) error {
	mpReg := st.regs[mapReg]
	if mpReg.Type != RegConstPtrToMap || mpReg.Map == nil {
		req.Log.add("%d: helper arg%d expected map pointer", st.pc, mapReg)
		return linuxerr.EACCES
	}
	if !readableMemory(st, st.regs[keyReg], mpReg.Map.KeySize()) {
		req.Log.add("%d: helper arg%d expected readable key", st.pc, keyReg)
		return linuxerr.EACCES
	}
	return nil
}

func refineNullBranches(ins Insn, taken, notTaken *verifierState) {
	if insnSrc(ins.OpCode) != linux.BPF_K || ins.Imm != 0 {
		return
	}
	dst := ins.Dst
	reg := taken.regs[dst]
	if reg.Type != RegPtrToMapValueOrNull {
		return
	}
	nonNull := reg
	nonNull.Type = RegPtrToMapValue
	null := scalarConst(0)
	switch insnOp(ins.OpCode) {
	case linux.BPF_JNE:
		promoteRegID(taken, reg.ID, nonNull)
		promoteRegID(notTaken, reg.ID, null)
	case linux.BPF_JEQ:
		promoteRegID(taken, reg.ID, null)
		promoteRegID(notTaken, reg.ID, nonNull)
	}
}

func promoteRegID(st *verifierState, id uint32, to RegState) {
	for i := range st.regs {
		if st.regs[i].ID == id && st.regs[i].Type == RegPtrToMapValueOrNull {
			st.regs[i] = to
		}
	}
}

func validStack(off int32, size uint32) bool {
	if off >= 0 || size == 0 {
		return false
	}
	start := int32(512) + off
	return start >= 0 && start+int32(size) <= 512
}

func stackReadable(st verifierState, off int32, size uint32) bool {
	if !validStack(off, size) {
		return false
	}
	start := int32(512) + off
	for i := uint32(0); i < size; i++ {
		idx := start + int32(i)
		slot := idx / 8
		bit := uint(idx % 8)
		if st.stack[slot].initMask&(1<<bit) == 0 {
			return false
		}
	}
	return true
}

func loadStackSpilledPtr(st verifierState, off int32, size uint32) (RegState, bool) {
	if size != 8 {
		return RegState{}, false
	}
	start := int32(512) + off
	if start < 0 || start%8 != 0 {
		return RegState{}, false
	}
	slot := start / 8
	if slot < 0 || slot >= int32(len(st.stack)) || st.stack[slot].kind != stackSpilledPtr {
		return RegState{}, false
	}
	return st.stack[slot].reg, true
}

func markStackWritten(st *verifierState, off int32, size uint32, spilled bool, reg RegState) {
	start := int32(512) + off
	for i := uint32(0); i < size; i++ {
		idx := start + int32(i)
		slot := idx / 8
		bit := uint(idx % 8)
		st.stack[slot].initMask |= 1 << bit
		st.stack[slot].kind = stackMisc
	}
	if spilled && size == 8 && reg.Type != RegScalar && reg.Type != RegNotInit {
		slot := start / 8
		st.stack[slot].kind = stackSpilledPtr
		st.stack[slot].reg = reg
	} else if size == 8 {
		slot := start / 8
		st.stack[slot].kind = stackScalar
	}
}

func valueBounds(reg RegState, off int32, size uint32) bool {
	total := int64(reg.FixedOff) + int64(off)
	return total >= 0 && uint64(total)+uint64(size) <= uint64(reg.ValueSize)
}

func readableMemory(st verifierState, reg RegState, size uint32) bool {
	return readableOrWritableMemory(st, reg, size, false)
}

func readableOrWritableMemory(st verifierState, reg RegState, size uint32, write bool) bool {
	switch reg.Type {
	case RegPtrToStack:
		if write {
			return validStack(reg.FixedOff, size)
		}
		return stackReadable(st, reg.FixedOff, size)
	case RegPtrToMapValue, RegPtrToRingbufMem:
		return valueBounds(reg, 0, size)
	default:
		return false
	}
}

func maxStackDepth(insns []Insn) uint32 {
	var max uint32
	for _, ins := range insns {
		if insnClass(ins.OpCode) != linux.BPF_ST && insnClass(ins.OpCode) != linux.BPF_STX && insnClass(ins.OpCode) != linux.BPF_LDX {
			continue
		}
		if ins.Dst == linux.BPF_REG_10 || ins.Src == linux.BPF_REG_10 {
			depth := uint32(-ins.Off)
			if depth > max {
				max = depth
			}
		}
	}
	return max
}
