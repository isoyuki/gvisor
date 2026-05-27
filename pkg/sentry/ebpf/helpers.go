package ebpf

import (
	"time"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

func (v *vm) callHelper(id linux.BPFHelperID) error {
	switch id {
	case linux.BPF_FUNC_map_lookup_elem:
		return v.helperMapLookupElem()
	case linux.BPF_FUNC_map_update_elem:
		return v.helperMapUpdateElem()
	case linux.BPF_FUNC_map_delete_elem:
		return v.helperMapDeleteElem()
	case linux.BPF_FUNC_ktime_get_ns:
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(time.Now().UnixNano())}
		return nil
	case linux.BPF_FUNC_get_current_pid_tgid:
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(v.req.Task.TGID)<<32 | uint64(v.req.Task.PID)}
		return nil
	case linux.BPF_FUNC_get_current_uid_gid:
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(v.req.Task.GID)<<32 | uint64(v.req.Task.UID)}
		return nil
	case linux.BPF_FUNC_get_current_comm:
		return v.helperGetCurrentComm()
	case linux.BPF_FUNC_ringbuf_output:
		return v.helperRingbufOutput()
	case linux.BPF_FUNC_ringbuf_reserve:
		return v.helperRingbufReserve()
	case linux.BPF_FUNC_ringbuf_submit:
		return v.helperRingbufSubmit()
	case linux.BPF_FUNC_ringbuf_discard:
		return v.helperRingbufDiscard()
	case linux.BPF_FUNC_tail_call:
		v.regs[linux.BPF_REG_0] = RuntimeReg{}
		return nil
	default:
		return linuxerr.EINVAL
	}
}

func (v *vm) helperMapLookupElem() error {
	mp := v.regs[linux.BPF_REG_1].Ptr.Map
	if mp == nil {
		return linuxerr.EFAULT
	}
	key, err := v.readMemory(v.regs[linux.BPF_REG_2], mp.KeySize())
	if err != nil {
		return err
	}
	value, err := mp.RuntimeLookup(key)
	if err != nil {
		v.regs[linux.BPF_REG_0] = RuntimeReg{}
		return nil
	}
	v.regs[linux.BPF_REG_0] = RuntimeReg{
		U64: uint64(mp.ID())<<32 | 1,
		Ptr: RuntimePtr{Kind: RuntimePtrMapValue, MapValue: value},
	}
	return nil
}

func (v *vm) helperMapUpdateElem() error {
	mp := v.regs[linux.BPF_REG_1].Ptr.Map
	if mp == nil {
		return linuxerr.EFAULT
	}
	key, err := v.readMemory(v.regs[linux.BPF_REG_2], mp.KeySize())
	if err != nil {
		return err
	}
	value, err := v.readMemory(v.regs[linux.BPF_REG_3], mp.ValueSize())
	if err != nil {
		return err
	}
	err = mp.Update(key, value, v.regs[linux.BPF_REG_4].U64)
	if err != nil {
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(uint32(1))}
		return nil
	}
	v.regs[linux.BPF_REG_0] = RuntimeReg{}
	return nil
}

func (v *vm) helperMapDeleteElem() error {
	mp := v.regs[linux.BPF_REG_1].Ptr.Map
	if mp == nil {
		return linuxerr.EFAULT
	}
	key, err := v.readMemory(v.regs[linux.BPF_REG_2], mp.KeySize())
	if err != nil {
		return err
	}
	err = mp.Delete(key)
	if err != nil {
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(uint32(1))}
		return nil
	}
	v.regs[linux.BPF_REG_0] = RuntimeReg{}
	return nil
}

func (v *vm) helperGetCurrentComm() error {
	size := v.regs[linux.BPF_REG_2].U64
	if size == 0 || size > 4096 {
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(uint32(1))}
		return nil
	}
	buf := make([]byte, size)
	copy(buf, v.req.Task.Comm)
	if len(buf) != 0 {
		buf[len(buf)-1] = 0
	}
	if err := v.writeMemory(v.regs[linux.BPF_REG_1], buf); err != nil {
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(uint32(1))}
		return nil
	}
	v.regs[linux.BPF_REG_0] = RuntimeReg{}
	return nil
}

func (v *vm) helperRingbufOutput() error {
	mp := v.regs[linux.BPF_REG_1].Ptr.Map
	if mp == nil || mp.Type() != linux.BPF_MAP_TYPE_RINGBUF {
		return linuxerr.EFAULT
	}
	size := v.regs[linux.BPF_REG_3].U64
	if size > 1<<20 {
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(uint32(1))}
		return nil
	}
	record, err := v.readMemory(v.regs[linux.BPF_REG_2], uint32(size))
	if err != nil {
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(uint32(1))}
		return nil
	}
	rb, ok := mp.ops.(*ringbufMap)
	if !ok {
		return linuxerr.EFAULT
	}
	if err := rb.Output(record); err != nil {
		v.regs[linux.BPF_REG_0] = RuntimeReg{U64: uint64(uint32(1))}
		return nil
	}
	v.regs[linux.BPF_REG_0] = RuntimeReg{}
	return nil
}

func (v *vm) helperRingbufReserve() error {
	mp := v.regs[linux.BPF_REG_1].Ptr.Map
	if mp == nil || mp.Type() != linux.BPF_MAP_TYPE_RINGBUF {
		return linuxerr.EFAULT
	}
	rb, ok := mp.ops.(*ringbufMap)
	if !ok {
		return linuxerr.EFAULT
	}
	rec, err := rb.Reserve(v.regs[linux.BPF_REG_2].U64)
	if err != nil {
		v.regs[linux.BPF_REG_0] = RuntimeReg{}
		return nil
	}
	v.regs[linux.BPF_REG_0] = RuntimeReg{
		U64: uint64(mp.ID())<<32 | 1,
		Ptr: RuntimePtr{Kind: RuntimePtrRingbufRecord, RingbufRecord: rec},
	}
	return nil
}

func (v *vm) helperRingbufSubmit() error {
	rec := v.regs[linux.BPF_REG_1].Ptr.RingbufRecord
	if rec == nil {
		return linuxerr.EFAULT
	}
	_ = rec.Submit()
	v.regs[linux.BPF_REG_0] = RuntimeReg{}
	return nil
}

func (v *vm) helperRingbufDiscard() error {
	rec := v.regs[linux.BPF_REG_1].Ptr.RingbufRecord
	if rec == nil {
		return linuxerr.EFAULT
	}
	rec.Discard()
	v.regs[linux.BPF_REG_0] = RuntimeReg{}
	return nil
}

func readU32(buf []byte) uint32 {
	return hostarch.ByteOrder.Uint32(buf)
}
