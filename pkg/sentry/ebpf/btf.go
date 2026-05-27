package ebpf

import (
	"bytes"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// BTF is a sandbox-local BTF object.
type BTF struct {
	objectBase

	data []byte
}

func (b *BTF) releaseRefs(context.Context) {}

// Data returns a copy of the BTF blob.
func (b *BTF) Data() []byte {
	return append([]byte(nil), b.data...)
}

// BTFLoad validates and stores a user-provided BTF blob.
func (m *Manager) BTFLoad(data []byte, name string) (*BTF, error) {
	if err := validateBTF(data); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if uint64(len(m.btfs)) >= m.cfg.MaxBTFObjects {
		return nil, linuxerr.ENOMEM
	}
	m.nextBTFID++
	b := &BTF{
		objectBase: newObjectBase(m, ObjectBTF, m.nextBTFID, name),
		data:       append([]byte(nil), data...),
	}
	m.btfs[b.id] = b
	return b, nil
}

// BTFByID returns a new reference to the BTF object with id.
func (m *Manager) BTFByID(id uint32) (*BTF, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b := m.btfs[id]
	if b == nil {
		return nil, linuxerr.ENOENT
	}
	b.refs++
	return b, nil
}

func validateBTF(data []byte) error {
	if len(data) < 24 {
		return linuxerr.EINVAL
	}
	if hostarch.ByteOrder.Uint16(data[0:]) != linux.BTF_MAGIC || data[2] != linux.BTF_VERSION {
		return linuxerr.EINVAL
	}
	hdrLen := hostarch.ByteOrder.Uint32(data[4:])
	typeOff := hostarch.ByteOrder.Uint32(data[8:])
	typeLen := hostarch.ByteOrder.Uint32(data[12:])
	strOff := hostarch.ByteOrder.Uint32(data[16:])
	strLen := hostarch.ByteOrder.Uint32(data[20:])
	if hdrLen < 24 || uint64(hdrLen) > uint64(len(data)) {
		return linuxerr.EINVAL
	}
	typeEnd := uint64(hdrLen) + uint64(typeOff) + uint64(typeLen)
	strEnd := uint64(hdrLen) + uint64(strOff) + uint64(strLen)
	if typeEnd > uint64(len(data)) || strEnd > uint64(len(data)) {
		return linuxerr.EINVAL
	}
	if strLen == 0 || data[hdrLen+strOff] != 0 {
		return linuxerr.EINVAL
	}
	return nil
}

const (
	btfKindInt    = 1
	btfKindArray  = 3
	btfKindStruct = 4
	btfIntSigned  = 1 << 24
)

// SyntheticBTFBlob returns the sandbox kernel BTF used by CO-RE loaders.
func SyntheticBTFBlob() []byte {
	var enc btfEncoder
	u8 := enc.intType("__u8", 1, 8, false)
	u32 := enc.intType("__u32", 4, 32, false)
	u64 := enc.intType("__u64", 8, 64, false)
	s64 := enc.intType("__s64", 8, 64, true)
	char16 := enc.arrayType(u8, u32, 16)
	task := enc.structType("gvisor_task_ctx", 32, []btfMember{
		{"pid", u32, 0},
		{"tgid", u32, 32},
		{"uid", u32, 64},
		{"gid", u32, 96},
		{"comm", char16, 128},
	})
	args6 := enc.arrayType(u64, u32, 6)
	enc.structType("gvisor_sys_enter_ctx", 88, []btfMember{
		{"id", u64, 0},
		{"args", args6, 64},
		{"task", task, 448},
	})
	enc.structType("gvisor_sys_exit_ctx", 48, []btfMember{
		{"id", u64, 0},
		{"ret", s64, 64},
		{"task", task, 128},
	})
	addr16 := enc.arrayType(u8, u32, 16)
	enc.structType("gvisor_net_packet_ctx", 88, []btfMember{
		{"direction", u64, 0},
		{"nic_id", u64, 64},
		{"network_protocol", u64, 128},
		{"transport_protocol", u64, 192},
		{"total_len", u64, 256},
		{"src_port", u64, 320},
		{"dst_port", u64, 384},
		{"src_addr", addr16, 448},
		{"dst_addr", addr16, 576},
	})
	return enc.bytes()
}

type btfMember struct {
	name string
	typ  uint32
	off  uint32
}

type btfEncoder struct {
	types bytes.Buffer
	strs  bytes.Buffer
	ids   uint32
}

func (e *btfEncoder) str(s string) uint32 {
	if e.strs.Len() == 0 {
		e.strs.WriteByte(0)
	}
	off := uint32(e.strs.Len())
	e.strs.WriteString(s)
	e.strs.WriteByte(0)
	return off
}

func (e *btfEncoder) nextID() uint32 {
	// All generated entries are fixed-size except structs. Track by appending
	// IDs explicitly through calls rather than trying to parse e.types.
	if e.ids == 0 {
		e.ids = 1
		return 1
	}
	e.ids++
	return e.ids
}

func (e *btfEncoder) intType(name string, size uint32, bits uint32, signed bool) uint32 {
	id := e.nextID()
	e.u32(e.str(name))
	e.u32(btfKindInt << 24)
	e.u32(size)
	encoding := bits
	if signed {
		encoding |= btfIntSigned
	}
	e.u32(encoding)
	return id
}

func (e *btfEncoder) arrayType(elem, index, nelems uint32) uint32 {
	id := e.nextID()
	e.u32(0)
	e.u32(btfKindArray << 24)
	e.u32(0)
	e.u32(elem)
	e.u32(index)
	e.u32(nelems)
	return id
}

func (e *btfEncoder) structType(name string, size uint32, members []btfMember) uint32 {
	id := e.nextID()
	e.u32(e.str(name))
	e.u32(uint32(btfKindStruct<<24) | uint32(len(members)))
	e.u32(size)
	for _, m := range members {
		e.u32(e.str(m.name))
		e.u32(m.typ)
		e.u32(m.off)
	}
	return id
}

func (e *btfEncoder) bytes() []byte {
	if e.strs.Len() == 0 {
		e.strs.WriteByte(0)
	}
	typeLen := uint32(e.types.Len())
	strLen := uint32(e.strs.Len())
	out := make([]byte, 24+typeLen+strLen)
	hostarch.ByteOrder.PutUint16(out[0:], linux.BTF_MAGIC)
	out[2] = linux.BTF_VERSION
	out[3] = 0
	hostarch.ByteOrder.PutUint32(out[4:], 24)
	hostarch.ByteOrder.PutUint32(out[8:], 0)
	hostarch.ByteOrder.PutUint32(out[12:], typeLen)
	hostarch.ByteOrder.PutUint32(out[16:], typeLen)
	hostarch.ByteOrder.PutUint32(out[20:], strLen)
	copy(out[24:], e.types.Bytes())
	copy(out[24+typeLen:], e.strs.Bytes())
	return out
}

func (e *btfEncoder) u32(v uint32) {
	var buf [4]byte
	hostarch.ByteOrder.PutUint32(buf[:], v)
	e.types.Write(buf[:])
}
