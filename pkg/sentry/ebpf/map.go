package ebpf

import (
	"bytes"
	"io"
	"sort"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/waiter"
)

// MapOps is implemented by concrete eBPF map types.
type MapOps interface {
	Lookup(key []byte) ([]byte, error)
	Update(key, value []byte, flags uint64) error
	Delete(key []byte) error
	NextKey(key []byte) ([]byte, error)
	Freeze() error
	RuntimeLookup(key []byte) (*MapValue, error)
	MemoryUsage() uint64
}

// Map is a sandbox-local eBPF map.
type Map struct {
	objectBase

	typ        linux.BPFMapType
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	flags      uint32
	ops        MapOps
	memory     uint64
}

// Type returns the map type.
func (m *Map) Type() linux.BPFMapType {
	return m.typ
}

// KeySize returns the key size in bytes.
func (m *Map) KeySize() uint32 {
	return m.keySize
}

// ValueSize returns the value size in bytes.
func (m *Map) ValueSize() uint32 {
	return m.valueSize
}

// MaxEntries returns the maximum entry count.
func (m *Map) MaxEntries() uint32 {
	return m.maxEntries
}

// Flags returns map creation flags.
func (m *Map) Flags() uint32 {
	return m.flags
}

func (m *Map) releaseRefs(context.Context) {
	if rb, ok := m.ops.(*ringbufMap); ok {
		rb.releaseMMap()
	}
}

func validateKeyValue(mp *Map, key, value []byte) error {
	if uint32(len(key)) != mp.keySize {
		return linuxerr.EINVAL
	}
	if value != nil && uint32(len(value)) != mp.valueSize {
		return linuxerr.EINVAL
	}
	return nil
}

// Lookup returns a copy of the value associated with key.
func (m *Map) Lookup(key []byte) ([]byte, error) {
	if err := validateKeyValue(m, key, nil); err != nil {
		return nil, err
	}
	return m.ops.Lookup(key)
}

// Update updates the value associated with key.
func (m *Map) Update(key, value []byte, flags uint64) error {
	if err := validateKeyValue(m, key, value); err != nil {
		return err
	}
	return m.ops.Update(key, value, flags)
}

// Delete deletes the value associated with key.
func (m *Map) Delete(key []byte) error {
	if err := validateKeyValue(m, key, nil); err != nil {
		return err
	}
	return m.ops.Delete(key)
}

// NextKey returns the key following key in this map's deterministic iteration
// order. A nil key returns the first key.
func (m *Map) NextKey(key []byte) ([]byte, error) {
	if key != nil && uint32(len(key)) != m.keySize {
		return nil, linuxerr.EINVAL
	}
	return m.ops.NextKey(key)
}

// Freeze marks the map read-only for userspace update/delete operations.
func (m *Map) Freeze() error {
	return m.ops.Freeze()
}

// RuntimeLookup returns a runtime map-value handle for VM helper access.
func (m *Map) RuntimeLookup(key []byte) (*MapValue, error) {
	if err := validateKeyValue(m, key, nil); err != nil {
		return nil, err
	}
	return m.ops.RuntimeLookup(key)
}

// MapValue is an eBPF VM handle for a map value. It never exposes a Go pointer
// to eBPF-visible state.
type MapValue struct {
	load  func(off int64, size uint32) (uint64, error)
	store func(off int64, size uint32, value uint64) error
	size  uint32
}

func (v *MapValue) bounds(off int64, size uint32) error {
	if off < 0 || size == 0 || uint64(off)+uint64(size) > uint64(v.size) {
		return linuxerr.EFAULT
	}
	return nil
}

func loadBytes(buf []byte, off int64, size uint32) (uint64, error) {
	if off < 0 || size == 0 || uint64(off)+uint64(size) > uint64(len(buf)) {
		return 0, linuxerr.EFAULT
	}
	switch size {
	case 1:
		return uint64(buf[off]), nil
	case 2:
		return uint64(hostarch.ByteOrder.Uint16(buf[off:])), nil
	case 4:
		return uint64(hostarch.ByteOrder.Uint32(buf[off:])), nil
	case 8:
		return hostarch.ByteOrder.Uint64(buf[off:]), nil
	default:
		return 0, linuxerr.EINVAL
	}
}

func storeBytes(buf []byte, off int64, size uint32, value uint64) error {
	if off < 0 || size == 0 || uint64(off)+uint64(size) > uint64(len(buf)) {
		return linuxerr.EFAULT
	}
	switch size {
	case 1:
		buf[off] = byte(value)
	case 2:
		hostarch.ByteOrder.PutUint16(buf[off:], uint16(value))
	case 4:
		hostarch.ByteOrder.PutUint32(buf[off:], uint32(value))
	case 8:
		hostarch.ByteOrder.PutUint64(buf[off:], value)
	default:
		return linuxerr.EINVAL
	}
	return nil
}

type arrayMap struct {
	mu     sync.Mutex
	values [][]byte
	frozen bool
}

func newArrayMap(_, valueSize, maxEntries uint32) *arrayMap {
	values := make([][]byte, maxEntries)
	for i := range values {
		values[i] = make([]byte, valueSize)
	}
	return &arrayMap{values: values}
}

func (m *arrayMap) key(key []byte) (uint32, error) {
	if len(key) != 4 {
		return 0, linuxerr.EINVAL
	}
	k := hostarch.ByteOrder.Uint32(key)
	if k >= uint32(len(m.values)) {
		return 0, linuxerr.ENOENT
	}
	return k, nil
}

func (m *arrayMap) Lookup(key []byte) ([]byte, error) {
	k, err := m.key(key)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.values[k]...), nil
}

func (m *arrayMap) Update(key, value []byte, flags uint64) error {
	k, err := m.key(key)
	if err != nil {
		return err
	}
	if flags == linux.BPF_NOEXIST {
		return linuxerr.EEXIST
	}
	if flags != linux.BPF_ANY && flags != linux.BPF_EXIST {
		return linuxerr.EINVAL
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen {
		return linuxerr.EPERM
	}
	copy(m.values[k], value)
	return nil
}

func (m *arrayMap) Delete([]byte) error {
	return linuxerr.EINVAL
}

func (m *arrayMap) NextKey(key []byte) ([]byte, error) {
	var next uint32
	if key != nil {
		k, err := m.key(key)
		if err != nil {
			return nil, err
		}
		next = k + 1
	}
	if next >= uint32(len(m.values)) {
		return nil, linuxerr.ENOENT
	}
	out := make([]byte, 4)
	hostarch.ByteOrder.PutUint32(out, next)
	return out, nil
}

func (m *arrayMap) Freeze() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frozen = true
	return nil
}

func (m *arrayMap) RuntimeLookup(key []byte) (*MapValue, error) {
	k, err := m.key(key)
	if err != nil {
		return nil, err
	}
	return &MapValue{
		size: uint32(len(m.values[k])),
		load: func(off int64, size uint32) (uint64, error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			return loadBytes(m.values[k], off, size)
		},
		store: func(off int64, size uint32, value uint64) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.frozen {
				return linuxerr.EPERM
			}
			return storeBytes(m.values[k], off, size, value)
		},
	}, nil
}

func (m *arrayMap) MemoryUsage() uint64 {
	if len(m.values) == 0 {
		return 0
	}
	return uint64(len(m.values)) * uint64(len(m.values[0]))
}

type hashMap struct {
	mu         sync.Mutex
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	values     map[string][]byte
	frozen     bool
}

func newHashMap(keySize, valueSize, maxEntries uint32) *hashMap {
	return &hashMap{
		keySize:    keySize,
		valueSize:  valueSize,
		maxEntries: maxEntries,
		values:     make(map[string][]byte),
	}
}

func (m *hashMap) Lookup(key []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.values[string(key)]
	if !ok {
		return nil, linuxerr.ENOENT
	}
	return append([]byte(nil), value...), nil
}

func (m *hashMap) Update(key, value []byte, flags uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen {
		return linuxerr.EPERM
	}
	_, exists := m.values[string(key)]
	switch flags {
	case linux.BPF_ANY:
	case linux.BPF_NOEXIST:
		if exists {
			return linuxerr.EEXIST
		}
	case linux.BPF_EXIST:
		if !exists {
			return linuxerr.ENOENT
		}
	default:
		return linuxerr.EINVAL
	}
	if !exists && uint32(len(m.values)) >= m.maxEntries {
		return linuxerr.E2BIG
	}
	m.values[string(key)] = append([]byte(nil), value...)
	return nil
}

func (m *hashMap) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen {
		return linuxerr.EPERM
	}
	if _, ok := m.values[string(key)]; !ok {
		return linuxerr.ENOENT
	}
	delete(m.values, string(key))
	return nil
}

func (m *hashMap) NextKey(key []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.values) == 0 {
		return nil, linuxerr.ENOENT
	}
	keys := make([][]byte, 0, len(m.values))
	for k := range m.values {
		keys = append(keys, []byte(k))
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	if key == nil {
		return append([]byte(nil), keys[0]...), nil
	}
	for i, k := range keys {
		if bytes.Equal(k, key) {
			if i+1 == len(keys) {
				return nil, linuxerr.ENOENT
			}
			return append([]byte(nil), keys[i+1]...), nil
		}
	}
	return nil, linuxerr.ENOENT
}

func (m *hashMap) Freeze() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frozen = true
	return nil
}

func (m *hashMap) RuntimeLookup(key []byte) (*MapValue, error) {
	m.mu.Lock()
	if _, ok := m.values[string(key)]; !ok {
		m.mu.Unlock()
		return nil, linuxerr.ENOENT
	}
	keyCopy := append([]byte(nil), key...)
	m.mu.Unlock()
	return &MapValue{
		size: m.valueSize,
		load: func(off int64, size uint32) (uint64, error) {
			m.mu.Lock()
			defer m.mu.Unlock()
			value, ok := m.values[string(keyCopy)]
			if !ok {
				return 0, linuxerr.ENOENT
			}
			return loadBytes(value, off, size)
		},
		store: func(off int64, size uint32, value uint64) error {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.frozen {
				return linuxerr.EPERM
			}
			buf, ok := m.values[string(keyCopy)]
			if !ok {
				return linuxerr.ENOENT
			}
			return storeBytes(buf, off, size, value)
		},
	}, nil
}

func (m *hashMap) MemoryUsage() uint64 {
	return uint64(m.maxEntries) * (uint64(m.keySize) + uint64(m.valueSize) + 64)
}

type progArrayMap struct {
	mu     sync.Mutex
	progs  []*Program
	frozen bool
}

func newProgArrayMap(maxEntries uint32) *progArrayMap {
	return &progArrayMap{progs: make([]*Program, maxEntries)}
}

func (m *progArrayMap) key(key []byte) (uint32, error) {
	if len(key) != 4 {
		return 0, linuxerr.EINVAL
	}
	k := hostarch.ByteOrder.Uint32(key)
	if k >= uint32(len(m.progs)) {
		return 0, linuxerr.ENOENT
	}
	return k, nil
}

func (m *progArrayMap) Lookup(key []byte) ([]byte, error) {
	k, err := m.key(key)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.progs[k] == nil {
		return nil, linuxerr.ENOENT
	}
	value := make([]byte, 4)
	hostarch.ByteOrder.PutUint32(value, m.progs[k].ID())
	return value, nil
}

func (m *progArrayMap) Update(key, value []byte, flags uint64) error {
	return linuxerr.EOPNOTSUPP
}

func (m *progArrayMap) UpdateProgram(key []byte, prog *Program, flags uint64) (*Program, error) {
	k, err := m.key(key)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen {
		return nil, linuxerr.EPERM
	}
	exists := m.progs[k] != nil
	switch flags {
	case linux.BPF_ANY:
	case linux.BPF_NOEXIST:
		if exists {
			return nil, linuxerr.EEXIST
		}
	case linux.BPF_EXIST:
		if !exists {
			return nil, linuxerr.ENOENT
		}
	default:
		return nil, linuxerr.EINVAL
	}
	old := m.progs[k]
	m.progs[k] = prog
	return old, nil
}

func (m *progArrayMap) Delete(key []byte) error {
	_, err := m.DeleteProgram(key)
	return err
}

func (m *progArrayMap) DeleteProgram(key []byte) (*Program, error) {
	k, err := m.key(key)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen {
		return nil, linuxerr.EPERM
	}
	old := m.progs[k]
	m.progs[k] = nil
	return old, nil
}

func (m *progArrayMap) NextKey(key []byte) ([]byte, error) {
	var next uint32
	if key != nil {
		k, err := m.key(key)
		if err != nil {
			return nil, err
		}
		next = k + 1
	}
	if next >= uint32(len(m.progs)) {
		return nil, linuxerr.ENOENT
	}
	out := make([]byte, 4)
	hostarch.ByteOrder.PutUint32(out, next)
	return out, nil
}

func (m *progArrayMap) Freeze() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frozen = true
	return nil
}

func (m *progArrayMap) RuntimeLookup([]byte) (*MapValue, error) {
	return nil, linuxerr.EOPNOTSUPP
}

func (m *progArrayMap) MemoryUsage() uint64 {
	return uint64(len(m.progs)) * 16
}

type ringbufMap struct {
	memmap.MappableNoTrackMappings

	mu     sync.Mutex
	q      waiter.Queue
	limit  uint32
	used   uint32
	events [][]byte
	frozen bool

	mf             *pgalloc.MemoryFile
	fr             memmap.FileRange
	dataSize       uint64
	virtualMapSize uint64
}

func newRingbufMap(maxEntries uint32) *ringbufMap {
	return &ringbufMap{limit: maxEntries}
}

func (m *ringbufMap) Lookup([]byte) ([]byte, error)           { return nil, linuxerr.EINVAL }
func (m *ringbufMap) Update(_, _ []byte, _ uint64) error      { return linuxerr.EINVAL }
func (m *ringbufMap) Delete([]byte) error                     { return linuxerr.EINVAL }
func (m *ringbufMap) NextKey([]byte) ([]byte, error)          { return nil, linuxerr.EINVAL }
func (m *ringbufMap) RuntimeLookup([]byte) (*MapValue, error) { return nil, linuxerr.EINVAL }
func (m *ringbufMap) MemoryUsage() uint64                     { return uint64(m.limit) }
func (m *ringbufMap) Freeze() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frozen = true
	return nil
}
func (m *ringbufMap) Readiness(mask waiter.EventMask) waiter.EventMask {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) != 0 {
		return mask & waiter.ReadableEvents
	}
	return 0
}
func (m *ringbufMap) EventRegister(e *waiter.Entry) error {
	m.q.EventRegister(e)
	return nil
}
func (m *ringbufMap) EventUnregister(e *waiter.Entry) {
	m.q.EventUnregister(e)
}
func (m *ringbufMap) Output(record []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen {
		return linuxerr.EPERM
	}
	if uint64(len(record)) > uint64(m.limit) {
		return linuxerr.ENOSPC
	}
	if m.mf == nil && uint64(m.used)+uint64(len(record)) > uint64(m.limit) {
		return linuxerr.ENOSPC
	}
	if err := m.outputMMapLocked(record); err != nil {
		return err
	}
	if uint64(m.used)+uint64(len(record)) <= uint64(m.limit) {
		m.events = append(m.events, append([]byte(nil), record...))
		m.used += uint32(len(record))
	}
	m.q.Notify(waiter.ReadableEvents)
	return nil
}
func (m *ringbufMap) ReadRecord() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		return nil, linuxerr.ErrWouldBlock
	}
	record := m.events[0]
	copy(m.events, m.events[1:])
	m.events[len(m.events)-1] = nil
	m.events = m.events[:len(m.events)-1]
	m.used -= uint32(len(record))
	return record, nil
}

type ringbufRecord struct {
	rb   *ringbufMap
	data []byte
	done bool
}

func (m *ringbufMap) Reserve(size uint64) (*ringbufRecord, error) {
	if size > 1<<20 || size > uint64(m.limit) {
		return nil, linuxerr.ENOSPC
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.frozen {
		return nil, linuxerr.EPERM
	}
	return &ringbufRecord{rb: m, data: make([]byte, size)}, nil
}

func (r *ringbufRecord) load(off int64, size uint32) (uint64, error) {
	if r == nil || r.done {
		return 0, linuxerr.EFAULT
	}
	return loadBytes(r.data, off, size)
}

func (r *ringbufRecord) store(off int64, size uint32, value uint64) error {
	if r == nil || r.done {
		return linuxerr.EFAULT
	}
	return storeBytes(r.data, off, size, value)
}

func (r *ringbufRecord) Submit() error {
	if r == nil || r.done {
		return linuxerr.EINVAL
	}
	r.done = true
	return r.rb.Output(r.data)
}

func (r *ringbufRecord) Discard() {
	if r != nil {
		r.done = true
	}
}

func (m *ringbufMap) ensureMMap(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureMMapLocked(ctx)
}

func (m *ringbufMap) ensureMMapLocked(ctx context.Context) error {
	if m.mf != nil {
		return nil
	}
	mf := pgalloc.MemoryFileFromContext(ctx)
	if mf == nil {
		return linuxerr.ENOMEM
	}
	dataSize := uint64(m.limit)
	total := 2*uint64(hostarch.PageSize) + dataSize
	fr, err := mf.Allocate(total, pgalloc.AllocOpts{
		Kind:    usage.Anonymous,
		MemCgID: pgalloc.MemoryCgroupIDFromContext(ctx),
	})
	if err != nil {
		return err
	}
	m.mf = mf
	m.fr = fr
	m.dataSize = dataSize
	m.virtualMapSize = 2*uint64(hostarch.PageSize) + 2*dataSize
	return nil
}

func (m *ringbufMap) releaseMMap() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mf != nil {
		m.mf.DecRef(m.fr)
		m.mf = nil
	}
}

// Translate implements memmap.Mappable.Translate for the Linux ringbuf mmap
// ABI: consumer page at offset 0, producer page at page_size, followed by the
// data ring mapped twice.
func (m *ringbufMap) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureMMapLocked(ctx); err != nil {
		return nil, err
	}
	var err error
	if required.End > m.virtualMapSize {
		err = &memmap.BusError{Err: io.EOF}
	}
	if optional.End > m.virtualMapSize {
		optional.End = m.virtualMapSize
	}
	if optional.Start >= optional.End {
		return nil, err
	}
	var ts []memmap.Translation
	for off := optional.Start; off < optional.End; {
		fileOff, maxLen, perms, ok := m.translateOffsetLocked(off)
		if !ok {
			break
		}
		end := off + maxLen
		if end > optional.End {
			end = optional.End
		}
		ts = append(ts, memmap.Translation{
			Source: memmap.MappableRange{Start: off, End: end},
			File:   m.mf,
			Offset: fileOff,
			Perms:  perms,
		})
		off = end
	}
	if len(ts) == 0 && err == nil {
		err = linuxerr.EFAULT
	}
	return ts, err
}

func (m *ringbufMap) translateOffsetLocked(off uint64) (uint64, uint64, hostarch.AccessType, bool) {
	page := uint64(hostarch.PageSize)
	switch {
	case off < page:
		return m.fr.Start + off, page - off, hostarch.ReadWrite, true
	case off < 2*page:
		return m.fr.Start + off, 2*page - off, hostarch.Read, true
	case off < m.virtualMapSize:
		dataOff := (off - 2*page) % m.dataSize
		return m.fr.Start + 2*page + dataOff, m.dataSize - dataOff, hostarch.Read, true
	default:
		return 0, 0, hostarch.NoAccess, false
	}
}

func (m *ringbufMap) outputMMapLocked(record []byte) error {
	if m.mf == nil {
		return nil
	}
	total := ringbufRoundUp(uint64(len(record)) + 8)
	if total > m.dataSize {
		return linuxerr.E2BIG
	}
	consumer, err := m.loadU64Locked(0)
	if err != nil {
		return err
	}
	producer, err := m.loadU64Locked(uint64(hostarch.PageSize))
	if err != nil {
		return err
	}
	if producer < consumer || producer-consumer+total > m.dataSize {
		return linuxerr.ENOSPC
	}
	start := producer & (m.dataSize - 1)
	var hdr [8]byte
	hostarch.ByteOrder.PutUint32(hdr[0:], uint32(len(record)))
	if err := m.writeDataLocked(start, hdr[:]); err != nil {
		return err
	}
	if err := m.writeDataLocked(start+8, record); err != nil {
		return err
	}
	var prod [8]byte
	hostarch.ByteOrder.PutUint64(prod[:], producer+total)
	return m.writeMemoryLocked(uint64(hostarch.PageSize), prod[:])
}

func ringbufRoundUp(v uint64) uint64 {
	return (v + 7) &^ uint64(7)
}

func (m *ringbufMap) loadU64Locked(off uint64) (uint64, error) {
	var buf [8]byte
	if err := m.readMemoryLocked(off, buf[:]); err != nil {
		return 0, err
	}
	return hostarch.ByteOrder.Uint64(buf[:]), nil
}

func (m *ringbufMap) readMemoryLocked(off uint64, dst []byte) error {
	bs, err := m.mf.MapInternal(memmap.FileRange{Start: m.fr.Start + off, End: m.fr.Start + off + uint64(len(dst))}, hostarch.Read)
	if err != nil {
		return err
	}
	_, err = safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(dst)), bs)
	return err
}

func (m *ringbufMap) writeMemoryLocked(off uint64, src []byte) error {
	bs, err := m.mf.MapInternal(memmap.FileRange{Start: m.fr.Start + off, End: m.fr.Start + off + uint64(len(src))}, hostarch.Write)
	if err != nil {
		return err
	}
	_, err = safemem.CopySeq(bs, safemem.BlockSeqOf(safemem.BlockFromSafeSlice(src)))
	return err
}

func (m *ringbufMap) writeDataLocked(off uint64, src []byte) error {
	for len(src) != 0 {
		dataOff := off & (m.dataSize - 1)
		n := int(m.dataSize - dataOff)
		if n > len(src) {
			n = len(src)
		}
		if err := m.writeMemoryLocked(2*uint64(hostarch.PageSize)+dataOff, src[:n]); err != nil {
			return err
		}
		off += uint64(n)
		src = src[n:]
	}
	return nil
}
