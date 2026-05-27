package ebpf

import (
	"fmt"
	"path"
	"strings"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sync"
)

// Manager owns all sandbox-local eBPF objects for a sentry kernel.
type Manager struct {
	mu sync.Mutex

	cfg Config

	nextMapID  uint32
	nextProgID uint32
	nextLinkID uint32
	nextBTFID  uint32

	maps  map[uint32]*Map
	progs map[uint32]*Program
	links map[uint32]*Link
	btfs  map[uint32]*BTF
	pins  map[string]Object

	legacyLinks map[legacyAttachKey]*Link

	hookStates     map[string]*hookState
	netObserveMask atomic.Uint32

	mapMemoryBytes uint64
}

// NewManager returns a new sandbox-local eBPF manager.
func NewManager(cfg Config) *Manager {
	return &Manager{
		cfg:         cfg,
		maps:        make(map[uint32]*Map),
		progs:       make(map[uint32]*Program),
		links:       make(map[uint32]*Link),
		btfs:        make(map[uint32]*BTF),
		pins:        make(map[string]Object),
		legacyLinks: make(map[legacyAttachKey]*Link),
		hookStates:  newHookStates(),
	}
}

// Enabled returns true if this manager handles bpf(2) syscalls.
func (m *Manager) Enabled() bool {
	return m != nil && m.cfg.Enabled
}

// Config returns this manager's immutable configuration.
func (m *Manager) Config() Config {
	return m.cfg
}

// MapCreateAttrs contains arguments to BPF_MAP_CREATE.
type MapCreateAttrs struct {
	Type       linux.BPFMapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	Name       string
}

// ProgramLoadAttrs contains arguments to BPF_PROG_LOAD.
type ProgramLoadAttrs struct {
	Type               linux.BPFProgramType
	AttachType         linux.BPFAttachType
	ExpectedAttachType linux.BPFAttachType
	Name               string
	License            string
	Insns              []Insn
	LogLevel           uint32
	// MapResolver resolves a pseudo map FD and returns a map reference owned by
	// ProgramLoad.
	MapResolver func(fd int32) (*Map, error)
}

// MapCreate creates a sandbox-local eBPF map.
func (m *Manager) MapCreate(attrs MapCreateAttrs) (*Map, error) {
	if !m.cfg.mapTypeAllowed(attrs.Type) {
		return nil, linuxerr.EOPNOTSUPP
	}
	if attrs.MaxEntries == 0 {
		return nil, linuxerr.EINVAL
	}

	var ops MapOps
	var memory uint64
	switch attrs.Type {
	case linux.BPF_MAP_TYPE_ARRAY:
		if attrs.KeySize != 4 || attrs.ValueSize == 0 {
			return nil, linuxerr.EINVAL
		}
		ops = newArrayMap(attrs.KeySize, attrs.ValueSize, attrs.MaxEntries)
		memory = uint64(attrs.ValueSize) * uint64(attrs.MaxEntries)
	case linux.BPF_MAP_TYPE_HASH:
		if attrs.KeySize == 0 || attrs.ValueSize == 0 {
			return nil, linuxerr.EINVAL
		}
		ops = newHashMap(attrs.KeySize, attrs.ValueSize, attrs.MaxEntries)
		memory = uint64(attrs.MaxEntries) * (uint64(attrs.KeySize) + uint64(attrs.ValueSize) + 64)
	case linux.BPF_MAP_TYPE_PROG_ARRAY:
		if attrs.KeySize != 4 || attrs.ValueSize != 4 {
			return nil, linuxerr.EINVAL
		}
		ops = newProgArrayMap(attrs.MaxEntries)
		memory = uint64(attrs.MaxEntries) * 16
	case linux.BPF_MAP_TYPE_RINGBUF:
		if attrs.KeySize != 0 || attrs.ValueSize != 0 || attrs.MaxEntries == 0 ||
			attrs.MaxEntries&(attrs.MaxEntries-1) != 0 || attrs.MaxEntries%hostarch.PageSize != 0 {
			return nil, linuxerr.EINVAL
		}
		ops = newRingbufMap(attrs.MaxEntries)
		memory = uint64(attrs.MaxEntries)
	default:
		return nil, linuxerr.EOPNOTSUPP
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if uint64(len(m.maps)) >= m.cfg.MaxMaps {
		return nil, linuxerr.ENOMEM
	}
	if m.cfg.MaxMapMemoryBytes != 0 && m.mapMemoryBytes+memory > m.cfg.MaxMapMemoryBytes {
		return nil, linuxerr.ENOMEM
	}
	m.nextMapID++
	mp := &Map{
		objectBase: newObjectBase(m, ObjectMap, m.nextMapID, attrs.Name),
		typ:        attrs.Type,
		keySize:    attrs.KeySize,
		valueSize:  attrs.ValueSize,
		maxEntries: attrs.MaxEntries,
		flags:      attrs.Flags,
		ops:        ops,
		memory:     memory,
	}
	m.maps[mp.id] = mp
	m.mapMemoryBytes += memory
	return mp, nil
}

// ProgramLoad verifies and creates a sandbox-local eBPF program.
func (m *Manager) ProgramLoad(attrs ProgramLoadAttrs) (*Program, *Log, error) {
	log := newLog(attrs.LogLevel)
	if !m.cfg.programTypeAllowed(attrs.Type) {
		log.add("program type %d is not enabled", attrs.Type)
		return nil, log, linuxerr.EOPNOTSUPP
	}
	if len(attrs.Insns) == 0 || uint32(len(attrs.Insns)) > m.cfg.MaxProgramInsns {
		log.add("invalid instruction count %d", len(attrs.Insns))
		return nil, log, linuxerr.E2BIG
	}
	if attrs.MapResolver == nil {
		attrs.MapResolver = func(int32) (*Map, error) { return nil, linuxerr.EBADF }
	}
	resolved, err := resolveProgramMaps(attrs.Insns, attrs.MapResolver)
	if err != nil {
		log.add("map fd resolution failed: %v", err)
		return nil, log, err
	}
	releaseResolved := true
	defer func() {
		if !releaseResolved {
			return
		}
		for _, mp := range resolved {
			mp.DecRef(context.Background())
		}
	}()
	vp, err := Verify(VerifyRequest{
		Insns:             attrs.Insns,
		ProgType:          attrs.Type,
		Context:           contextSpecForProgramType(attrs.Type),
		Maps:              resolved,
		MaxStates:         m.cfg.MaxVerifierStates,
		HelperAllowed:     m.cfg.helperAllowed,
		MaxProgramInsns:   m.cfg.MaxProgramInsns,
		ExpectedAttachTyp: attrs.ExpectedAttachType,
		Log:               log,
	})
	if err != nil {
		return nil, log, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if uint64(len(m.progs)) >= m.cfg.MaxPrograms {
		return nil, log, linuxerr.ENOMEM
	}
	m.nextProgID++
	prog := &Program{
		objectBase:         newObjectBase(m, ObjectProgram, m.nextProgID, attrs.Name),
		typ:                attrs.Type,
		attachType:         attrs.AttachType,
		expectedAttachType: attrs.ExpectedAttachType,
		license:            attrs.License,
		insns:              append([]Insn(nil), attrs.Insns...),
		verified:           vp,
		maps:               mapsFromResolved(resolved),
		aux:                auxFromResolved(resolved),
		ctxAccesses:        append([]ContextAccess(nil), vp.ctxAccesses...),
		helperCalls:        cloneHelperCalls(vp.helperCalls),
	}
	m.progs[prog.id] = prog
	releaseResolved = false
	log.add("processed %d insns", len(attrs.Insns))
	return prog, log, nil
}

// ProgramTestRun runs prog once with the supplied context and returns R0.
func (m *Manager) ProgramTestRun(prog *Program, rtctx RuntimeContext, task TaskInfo) (uint64, error) {
	if prog == nil {
		return 0, linuxerr.EBADF
	}
	res, err := Execute(ExecRequest{
		Program:      prog,
		Context:      rtctx,
		Task:         task,
		MaxTailCalls: m.cfg.MaxTailCalls,
	})
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	return res.R0, nil
}

// ProgArrayUpdate updates a PROG_ARRAY map entry with prog.
func (m *Manager) ProgArrayUpdate(ctx context.Context, mp *Map, key []byte, prog *Program, flags uint64) error {
	if mp == nil || mp.Type() != linux.BPF_MAP_TYPE_PROG_ARRAY || prog == nil {
		return linuxerr.EINVAL
	}
	pa, ok := mp.ops.(*progArrayMap)
	if !ok {
		return linuxerr.EINVAL
	}
	m.mu.Lock()
	prog.refs++
	m.mu.Unlock()
	old, err := pa.UpdateProgram(key, prog, flags)
	if err != nil {
		prog.DecRef(ctx)
		return err
	}
	if old != nil {
		old.DecRef(ctx)
	}
	return nil
}

// ProgArrayDelete deletes a PROG_ARRAY entry and drops the stored program
// reference.
func (m *Manager) ProgArrayDelete(ctx context.Context, mp *Map, key []byte) error {
	if mp == nil || mp.Type() != linux.BPF_MAP_TYPE_PROG_ARRAY {
		return linuxerr.EINVAL
	}
	pa, ok := mp.ops.(*progArrayMap)
	if !ok {
		return linuxerr.EINVAL
	}
	old, err := pa.DeleteProgram(key)
	if err != nil {
		return err
	}
	if old != nil {
		old.DecRef(ctx)
	}
	return nil
}

// Pin pins obj at a sandbox-local bpffs path.
func (m *Manager) Pin(ctx context.Context, pathname string, obj Object) error {
	if err := validatePinPath(pathname); err != nil {
		return err
	}
	if obj == nil {
		return linuxerr.EBADF
	}
	obj.IncRef()
	m.mu.Lock()
	if _, ok := m.pins[pathname]; ok {
		m.mu.Unlock()
		obj.DecRef(ctx)
		return linuxerr.EEXIST
	}
	m.pins[pathname] = obj
	m.mu.Unlock()
	return nil
}

// GetPinned returns a new reference to the object pinned at pathname.
func (m *Manager) GetPinned(pathname string) (Object, error) {
	if err := validatePinPath(pathname); err != nil {
		return nil, err
	}
	m.mu.Lock()
	obj := m.pins[pathname]
	if obj != nil {
		obj.(object).base().incRefLocked()
	}
	m.mu.Unlock()
	if obj == nil {
		return nil, linuxerr.ENOENT
	}
	return obj, nil
}

// Unpin removes a sandbox-local bpffs pin.
func (m *Manager) Unpin(ctx context.Context, pathname string) error {
	if err := validatePinPath(pathname); err != nil {
		return err
	}
	m.mu.Lock()
	obj := m.pins[pathname]
	if obj != nil {
		delete(m.pins, pathname)
	}
	m.mu.Unlock()
	if obj == nil {
		return linuxerr.ENOENT
	}
	obj.DecRef(ctx)
	return nil
}

func validatePinPath(pathname string) error {
	clean := path.Clean(pathname)
	if clean != pathname || clean == "/sys/fs/bpf" || !strings.HasPrefix(clean, "/sys/fs/bpf/") {
		return linuxerr.EINVAL
	}
	return nil
}

// HasObjects returns true if this manager owns any live eBPF object.
func (m *Manager) HasObjects() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.maps) != 0 || len(m.progs) != 0 || len(m.links) != 0 || len(m.btfs) != 0
}

func (m *Manager) decRefBase(ctx context.Context, base *objectBase) {
	var obj object
	var release bool
	m.mu.Lock()
	obj = base.outerLocked()
	if obj == nil {
		m.mu.Unlock()
		panic(fmt.Sprintf("DecRef on unknown eBPF object id=%d kind=%d", base.id, base.kind))
	}
	if base.refs <= 0 {
		m.mu.Unlock()
		panic(fmt.Sprintf("DecRef on dead eBPF object id=%d kind=%d", base.id, base.kind))
	}
	base.refs--
	if base.refs == 0 {
		switch base.kind {
		case ObjectMap:
			delete(m.maps, base.id)
			m.mapMemoryBytes -= obj.(*Map).memory
		case ObjectProgram:
			delete(m.progs, base.id)
		case ObjectLink:
			delete(m.links, base.id)
		case ObjectBTF:
			delete(m.btfs, base.id)
		}
		release = true
	}
	m.mu.Unlock()
	if release {
		obj.releaseRefs(ctx)
	}
}

func (m *Manager) decRef(ctx context.Context, obj object) {
	m.decRefBase(ctx, obj.base())
}

func mapsFromResolved(resolved map[int]*Map) []*Map {
	if len(resolved) == 0 {
		return nil
	}
	maps := make([]*Map, 0, len(resolved))
	for _, mp := range resolved {
		maps = append(maps, mp)
	}
	return maps
}

func auxFromResolved(resolved map[int]*Map) map[int]*Map {
	if len(resolved) == 0 {
		return nil
	}
	aux := make(map[int]*Map, len(resolved))
	for pc, mp := range resolved {
		aux[pc] = mp
	}
	return aux
}

func resolveProgramMaps(insns []Insn, resolve func(fd int32) (*Map, error)) (map[int]*Map, error) {
	var out map[int]*Map
	for pc := 0; pc < len(insns); pc++ {
		ins := insns[pc]
		if ins.OpCode == linux.BPF_LD|linux.BPF_DW|linux.BPF_IMM {
			if pc+1 >= len(insns) {
				return nil, linuxerr.EINVAL
			}
			if ins.Src == linux.BPF_PSEUDO_MAP_FD {
				mp, err := resolve(ins.Imm)
				if err != nil {
					for _, existing := range out {
						existing.DecRef(context.Background())
					}
					return nil, err
				}
				if out == nil {
					out = make(map[int]*Map)
				}
				out[pc] = mp
			}
			pc++
		}
	}
	return out, nil
}
