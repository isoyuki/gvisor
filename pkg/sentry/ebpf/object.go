package ebpf

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/context"
)

// ObjectKind identifies a kind of eBPF object.
type ObjectKind int

const (
	// ObjectMap identifies a BPF map.
	ObjectMap ObjectKind = iota

	// ObjectProgram identifies a BPF program.
	ObjectProgram

	// ObjectLink identifies a BPF link.
	ObjectLink

	// ObjectBTF identifies a BTF object.
	ObjectBTF
)

// Object is a sandbox-local eBPF object exposed through a virtual file
// descriptor.
type Object interface {
	Kind() ObjectKind
	ID() uint32
	Name() string
	IncRef()
	DecRef(ctx context.Context)
}

type object interface {
	Object
	base() *objectBase
	releaseRefs(ctx context.Context)
}

type objectBase struct {
	mgr  *Manager
	kind ObjectKind
	id   uint32
	name string
	refs int64
}

func newObjectBase(mgr *Manager, kind ObjectKind, id uint32, name string) objectBase {
	return objectBase{
		mgr:  mgr,
		kind: kind,
		id:   id,
		name: name,
		refs: 1,
	}
}

func (o *objectBase) Kind() ObjectKind {
	return o.kind
}

func (o *objectBase) ID() uint32 {
	return o.id
}

func (o *objectBase) Name() string {
	return o.name
}

func (o *objectBase) IncRef() {
	o.mgr.mu.Lock()
	defer o.mgr.mu.Unlock()
	o.incRefLocked()
}

func (o *objectBase) incRefLocked() {
	if o.refs <= 0 {
		panic(fmt.Sprintf("IncRef on dead eBPF object id=%d kind=%d", o.id, o.kind))
	}
	o.refs++
}

func (o *objectBase) DecRef(ctx context.Context) {
	o.mgr.decRefBase(ctx, o)
}

func (o *objectBase) base() *objectBase {
	return o
}

func (o *objectBase) outerLocked() object {
	switch o.kind {
	case ObjectMap:
		return o.mgr.maps[o.id]
	case ObjectProgram:
		return o.mgr.progs[o.id]
	case ObjectLink:
		return o.mgr.links[o.id]
	case ObjectBTF:
		return o.mgr.btfs[o.id]
	default:
		panic(fmt.Sprintf("unknown eBPF object kind %d", o.kind))
	}
}
