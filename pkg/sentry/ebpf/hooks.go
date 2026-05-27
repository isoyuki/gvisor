package ebpf

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Link is an attachment between an eBPF program and a sentry hook.
type Link struct {
	objectBase

	prog     *Program
	hookName string
	flags    uint32
	detached bool
}

type legacyAttachKey struct {
	target int32
	attach linux.BPFAttachType
}

// HookKind identifies the runtime that emits a hook.
type HookKind uint8

const (
	HookRawTracepoint HookKind = iota
	HookNetworkPacket
	HookNetworkIngress
	HookNetworkEgress
)

// HookSpec describes a sentry eBPF hook and its stable virtual context.
type HookSpec struct {
	Name         string
	ProgramTypes map[linux.BPFProgramType]struct{}
	Context      *ContextSpec
	Helpers      map[linux.BPFHelperID]struct{}
	Kind         HookKind
}

func helperSet(ids ...linux.BPFHelperID) map[linux.BPFHelperID]struct{} {
	out := make(map[linux.BPFHelperID]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func programTypeSet(types ...linux.BPFProgramType) map[linux.BPFProgramType]struct{} {
	out := make(map[linux.BPFProgramType]struct{}, len(types))
	for _, typ := range types {
		out[typ] = struct{}{}
	}
	return out
}

var (
	rawTracepointProgramTypes = programTypeSet(
		linux.BPF_PROG_TYPE_RAW_TRACEPOINT,
		linux.BPF_PROG_TYPE_TRACEPOINT,
		linux.BPF_PROG_TYPE_PERF_EVENT,
	)
	networkAttachProgramTypes = programTypeSet(
		linux.BPF_PROG_TYPE_RAW_TRACEPOINT,
		linux.BPF_PROG_TYPE_TRACEPOINT,
		linux.BPF_PROG_TYPE_PERF_EVENT,
		linux.BPF_PROG_TYPE_XDP,
		linux.BPF_PROG_TYPE_SCHED_CLS,
		linux.BPF_PROG_TYPE_SCHED_ACT,
	)
	rawTracepointHelpers = helperSet(
		linux.BPF_FUNC_map_lookup_elem,
		linux.BPF_FUNC_map_update_elem,
		linux.BPF_FUNC_map_delete_elem,
		linux.BPF_FUNC_ktime_get_ns,
		linux.BPF_FUNC_get_current_pid_tgid,
		linux.BPF_FUNC_get_current_uid_gid,
		linux.BPF_FUNC_get_current_comm,
		linux.BPF_FUNC_ringbuf_output,
		linux.BPF_FUNC_ringbuf_reserve,
		linux.BPF_FUNC_ringbuf_submit,
		linux.BPF_FUNC_ringbuf_discard,
		linux.BPF_FUNC_tail_call,
	)
	networkPacketHelpers = helperSet(
		linux.BPF_FUNC_map_lookup_elem,
		linux.BPF_FUNC_map_update_elem,
		linux.BPF_FUNC_map_delete_elem,
		linux.BPF_FUNC_ktime_get_ns,
		linux.BPF_FUNC_ringbuf_output,
		linux.BPF_FUNC_ringbuf_reserve,
		linux.BPF_FUNC_ringbuf_submit,
		linux.BPF_FUNC_ringbuf_discard,
		linux.BPF_FUNC_tail_call,
	)
	hookSpecs = map[string]HookSpec{
		"raw_syscalls/sys_enter": {
			Name:         "raw_syscalls/sys_enter",
			ProgramTypes: rawTracepointProgramTypes,
			Context:      rawSyscallEnterContextSpec,
			Helpers:      rawTracepointHelpers,
			Kind:         HookRawTracepoint,
		},
		"raw_syscalls/sys_exit": {
			Name:         "raw_syscalls/sys_exit",
			ProgramTypes: rawTracepointProgramTypes,
			Context:      rawSyscallExitContextSpec,
			Helpers:      rawTracepointHelpers,
			Kind:         HookRawTracepoint,
		},
		"gvisor/net/packet": {
			Name:         "gvisor/net/packet",
			ProgramTypes: rawTracepointProgramTypes,
			Context:      networkPacketContextSpec,
			Helpers:      networkPacketHelpers,
			Kind:         HookNetworkPacket,
		},
		"gvisor/net/ingress": {
			Name:         "gvisor/net/ingress",
			ProgramTypes: networkAttachProgramTypes,
			Context:      networkPacketContextSpec,
			Helpers:      networkPacketHelpers,
			Kind:         HookNetworkIngress,
		},
		"gvisor/net/egress": {
			Name:         "gvisor/net/egress",
			ProgramTypes: networkAttachProgramTypes,
			Context:      networkPacketContextSpec,
			Helpers:      networkPacketHelpers,
			Kind:         HookNetworkEgress,
		},
	}
)

func lookupHookSpec(name string) (HookSpec, bool) {
	spec, ok := hookSpecs[name]
	return spec, ok
}

func (s HookSpec) allowsProgramType(typ linux.BPFProgramType) bool {
	if len(s.ProgramTypes) == 0 {
		return true
	}
	_, ok := s.ProgramTypes[typ]
	return ok
}

type hookState struct {
	programs atomic.Pointer[hookPrograms]
}

type hookPrograms struct {
	progs []*Program
}

func newHookStates() map[string]*hookState {
	states := make(map[string]*hookState, len(hookSpecs))
	for name := range hookSpecs {
		states[name] = &hookState{}
	}
	return states
}

func releaseHookPrograms(ctx context.Context, snap *hookPrograms) {
	if snap == nil {
		return
	}
	for _, prog := range snap.progs {
		prog.DecRef(ctx)
	}
}

func (l *Link) releaseRefs(ctx context.Context) {
	l.Detach()
	l.prog.DecRef(ctx)
}

// Detach detaches the link. It is idempotent.
func (l *Link) Detach() {
	m := l.mgr
	m.mu.Lock()
	if l.detached {
		m.mu.Unlock()
		return
	}
	l.detached = true
	old := m.removeLinkLocked(l)
	m.updateNetworkObserveMaskLocked()
	m.mu.Unlock()
	releaseHookPrograms(context.Background(), old)
}

// RawTracepointOpen creates a link for a raw syscall tracepoint hook.
func (m *Manager) RawTracepointOpen(name string, prog *Program, flags uint32) (*Link, error) {
	if prog == nil {
		return nil, linuxerr.EBADF
	}
	if prog.Type() != linux.BPF_PROG_TYPE_RAW_TRACEPOINT && prog.Type() != linux.BPF_PROG_TYPE_TRACEPOINT {
		return nil, linuxerr.EINVAL
	}
	return m.attachHook(name, prog, flags)
}

func (m *Manager) attachHook(name string, prog *Program, flags uint32) (*Link, error) {
	spec, ok := lookupHookSpec(name)
	if !ok {
		return nil, linuxerr.ENOENT
	}
	if !spec.allowsProgramType(prog.Type()) {
		return nil, linuxerr.EINVAL
	}
	if err := validateProgramForHook(prog, spec); err != nil {
		return nil, err
	}
	m.mu.Lock()
	if uint64(len(m.links)) >= m.cfg.MaxLinks {
		m.mu.Unlock()
		return nil, linuxerr.ENOMEM
	}
	m.nextLinkID++
	link := &Link{
		objectBase: newObjectBase(m, ObjectLink, m.nextLinkID, name),
		prog:       prog,
		hookName:   name,
		flags:      flags,
	}
	prog.refs++
	m.links[link.id] = link
	old := m.rebuildHookSnapshotLocked(name)
	m.updateNetworkObserveMaskLocked()
	m.mu.Unlock()
	releaseHookPrograms(context.Background(), old)
	return link, nil
}

// LinkCreate attaches prog using a Linux BPF attach type and returns a link.
func (m *Manager) LinkCreate(prog *Program, attach linux.BPFAttachType, flags uint32) (*Link, error) {
	if prog == nil {
		return nil, linuxerr.EBADF
	}
	name, err := hookForAttachType(attach)
	if err != nil {
		return nil, err
	}
	if !programTypeCanAttach(prog.Type(), attach) {
		return nil, linuxerr.EINVAL
	}
	return m.attachHook(name, prog, flags)
}

// ProgramAttach implements legacy BPF_PROG_ATTACH-style attach calls.
func (m *Manager) ProgramAttach(ctx context.Context, target int32, prog *Program, attach linux.BPFAttachType, flags uint32) error {
	link, err := m.LinkCreate(prog, attach, flags)
	if err != nil {
		return err
	}
	key := legacyAttachKey{target: target, attach: attach}
	m.mu.Lock()
	old := m.legacyLinks[key]
	m.legacyLinks[key] = link
	m.mu.Unlock()
	if old != nil {
		old.Detach()
		old.DecRef(ctx)
	}
	return nil
}

// ProgramDetach implements legacy BPF_PROG_DETACH-style detach calls.
func (m *Manager) ProgramDetach(ctx context.Context, target int32, attach linux.BPFAttachType) error {
	key := legacyAttachKey{target: target, attach: attach}
	m.mu.Lock()
	link := m.legacyLinks[key]
	if link != nil {
		delete(m.legacyLinks, key)
	}
	m.mu.Unlock()
	if link == nil {
		return linuxerr.ENOENT
	}
	link.Detach()
	link.DecRef(ctx)
	return nil
}

// UpdateLink replaces the program attached by link.
func (m *Manager) UpdateLink(ctx context.Context, link *Link, prog *Program, flags uint32, oldProg *Program) error {
	if link == nil || prog == nil {
		return linuxerr.EBADF
	}
	if flags&^linux.BPF_F_REPLACE != 0 {
		return linuxerr.EINVAL
	}
	spec, ok := lookupHookSpec(link.hookName)
	if !ok {
		return linuxerr.ENOENT
	}
	if !spec.allowsProgramType(prog.Type()) {
		return linuxerr.EINVAL
	}
	if err := validateProgramForHook(prog, spec); err != nil {
		return err
	}
	m.mu.Lock()
	if link.detached {
		m.mu.Unlock()
		return linuxerr.ENOENT
	}
	if flags&linux.BPF_F_REPLACE != 0 && oldProg != nil && link.prog != oldProg {
		m.mu.Unlock()
		return linuxerr.EPERM
	}
	prog.refs++
	prev := link.prog
	link.prog = prog
	old := m.rebuildHookSnapshotLocked(link.hookName)
	m.updateNetworkObserveMaskLocked()
	m.mu.Unlock()
	releaseHookPrograms(ctx, old)
	prev.DecRef(ctx)
	return nil
}

// TracepointOpen attaches prog to a synthetic tracefs/perf tracepoint ID.
func (m *Manager) TracepointOpen(id uint64, prog *Program, flags uint32) (*Link, error) {
	if prog == nil {
		return nil, linuxerr.EBADF
	}
	switch prog.Type() {
	case linux.BPF_PROG_TYPE_PERF_EVENT, linux.BPF_PROG_TYPE_TRACEPOINT, linux.BPF_PROG_TYPE_RAW_TRACEPOINT:
	default:
		return nil, linuxerr.EINVAL
	}
	hook, ok := TracepointHookByID(id)
	if !ok {
		return nil, linuxerr.ENOENT
	}
	return m.attachHook(hook, prog, flags)
}

func hookForAttachType(attach linux.BPFAttachType) (string, error) {
	switch attach {
	case linux.BPF_PERF_EVENT:
		return "", linuxerr.EINVAL
	case linux.BPF_XDP, linux.BPF_XDP_DEVMAP, linux.BPF_XDP_CPUMAP:
		return "gvisor/net/ingress", nil
	case linux.BPF_TCX_INGRESS:
		return "gvisor/net/ingress", nil
	case linux.BPF_TCX_EGRESS:
		return "gvisor/net/egress", nil
	default:
		return "", linuxerr.EOPNOTSUPP
	}
}

func programTypeCanAttach(typ linux.BPFProgramType, attach linux.BPFAttachType) bool {
	switch attach {
	case linux.BPF_XDP, linux.BPF_XDP_DEVMAP, linux.BPF_XDP_CPUMAP:
		return typ == linux.BPF_PROG_TYPE_XDP
	case linux.BPF_TCX_INGRESS, linux.BPF_TCX_EGRESS:
		return typ == linux.BPF_PROG_TYPE_SCHED_CLS || typ == linux.BPF_PROG_TYPE_SCHED_ACT
	default:
		return false
	}
}

func validateProgramForHook(prog *Program, spec HookSpec) error {
	if prog == nil || spec.Context == nil {
		return linuxerr.EINVAL
	}
	for _, access := range prog.ctxAccesses {
		if _, ok := spec.Context.ValidAccess(access.Offset, access.Size, access.Write); !ok {
			return linuxerr.EACCES
		}
	}
	for helper := range prog.helperCalls {
		if _, ok := spec.Helpers[helper]; !ok {
			return linuxerr.EACCES
		}
	}
	return nil
}

// RunSyscallEnter runs programs attached to raw_syscalls/sys_enter.
func (m *Manager) RunSyscallEnter(sysno uintptr, args [6]uint64, task TaskInfo) {
	if m == nil || !m.Enabled() {
		return
	}
	ctx := &SyscallEnterContext{Sysno: uint64(sysno), Args: args}
	m.runLinks("raw_syscalls/sys_enter", ctx, task)
}

// RunSyscallExit runs programs attached to raw_syscalls/sys_exit.
func (m *Manager) RunSyscallExit(sysno uintptr, rval uintptr, task TaskInfo) {
	if m == nil || !m.Enabled() {
		return
	}
	ctx := &SyscallExitContext{Sysno: uint64(sysno), Ret: uint64(rval)}
	m.runLinks("raw_syscalls/sys_exit", ctx, task)
}

// ObserveNetworkPacket runs programs attached to sandbox-local network packet
// observation hooks.
func (m *Manager) ObserveNetworkPacket(evt stack.NetworkPacketEvent) {
	if m == nil || !m.Enabled() || !m.IsObservingNetworkPackets(evt.Direction) {
		return
	}
	ctx := NewNetworkPacketContext(evt)
	m.runLinks("gvisor/net/packet", ctx, TaskInfo{})
	switch evt.Direction {
	case stack.NetworkPacketIngress:
		m.runLinks("gvisor/net/ingress", ctx, TaskInfo{})
	case stack.NetworkPacketEgress:
		m.runLinks("gvisor/net/egress", ctx, TaskInfo{})
	}
}

func (m *Manager) runLinks(name string, rtctx RuntimeContext, task TaskInfo) {
	state := m.hookStates[name]
	if state == nil {
		return
	}
	snapshot := state.programs.Load()
	if snapshot == nil {
		return
	}
	for _, prog := range snapshot.progs {
		_, _ = Execute(ExecRequest{
			Program:      prog,
			Context:      rtctx,
			Task:         task,
			MaxTailCalls: m.cfg.MaxTailCalls,
		})
	}
}

func (m *Manager) removeLinkLocked(link *Link) *hookPrograms {
	if link.hookName == "" {
		return nil
	}
	name := link.hookName
	for key, legacy := range m.legacyLinks {
		if legacy == link {
			delete(m.legacyLinks, key)
		}
	}
	link.hookName = ""
	return m.rebuildHookSnapshotLocked(name)
}

func (m *Manager) rebuildHookSnapshotLocked(name string) *hookPrograms {
	state := m.hookStates[name]
	if state == nil {
		return nil
	}
	var progs []*Program
	for _, link := range m.links {
		if link.hookName != name || link.detached {
			continue
		}
		link.prog.refs++
		progs = append(progs, link.prog)
	}
	var next *hookPrograms
	if len(progs) != 0 {
		next = &hookPrograms{progs: progs}
	}
	return state.programs.Swap(next)
}

const (
	observeNetPacket uint32 = 1 << iota
	observeNetIngress
	observeNetEgress
)

func (m *Manager) updateNetworkObserveMaskLocked() {
	var mask uint32
	for _, link := range m.links {
		if link.detached {
			continue
		}
		spec, ok := lookupHookSpec(link.hookName)
		if !ok {
			continue
		}
		switch spec.Kind {
		case HookNetworkPacket:
			mask |= observeNetPacket
		case HookNetworkIngress:
			mask |= observeNetIngress
		case HookNetworkEgress:
			mask |= observeNetEgress
		}
	}
	m.netObserveMask.Store(mask)
}

// IsObservingNetworkPackets returns true if at least one packet metadata hook
// for direction currently has attached programs.
func (m *Manager) IsObservingNetworkPackets(direction stack.NetworkPacketDirection) bool {
	if m == nil || !m.Enabled() {
		return false
	}
	mask := m.netObserveMask.Load()
	switch direction {
	case stack.NetworkPacketIngress:
		return mask&(observeNetPacket|observeNetIngress) != 0
	case stack.NetworkPacketEgress:
		return mask&(observeNetPacket|observeNetEgress) != 0
	default:
		return mask&observeNetPacket != 0
	}
}
