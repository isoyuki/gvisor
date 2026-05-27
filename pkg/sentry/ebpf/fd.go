package ebpf

import (
	"io"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

type objectFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	obj Object
}

// NewObjectFD returns a new anonymous file description for an eBPF object.
func NewObjectFD(ctx context.Context, vfsObj *vfs.VirtualFilesystem, obj Object, flags uint32) (*vfs.FileDescription, error) {
	vd := vfsObj.NewAnonVirtualDentry("[bpf]")
	defer vd.DecRef(ctx)
	return NewObjectFDAt(ctx, vd.Mount(), vd.Dentry(), obj, flags)
}

// NewObjectFDAt returns a new file description for an eBPF object at d.
func NewObjectFDAt(ctx context.Context, mnt *vfs.Mount, d *vfs.Dentry, obj Object, flags uint32) (*vfs.FileDescription, error) {
	fd := &objectFD{obj: obj}
	if err := fd.vfsfd.Init(fd, flags, auth.CredentialsFromContext(ctx), mnt, d, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// ObjectFromFile returns the eBPF object associated with f.
func ObjectFromFile(f *vfs.FileDescription) (Object, bool) {
	if f == nil {
		return nil, false
	}
	fd, ok := f.Impl().(*objectFD)
	if !ok {
		return nil, false
	}
	return fd.obj, true
}

// MapFromFile returns the map associated with f.
func MapFromFile(f *vfs.FileDescription) (*Map, bool) {
	obj, ok := ObjectFromFile(f)
	if !ok {
		return nil, false
	}
	mp, ok := obj.(*Map)
	return mp, ok
}

// ProgramFromFile returns the program associated with f.
func ProgramFromFile(f *vfs.FileDescription) (*Program, bool) {
	obj, ok := ObjectFromFile(f)
	if !ok {
		return nil, false
	}
	prog, ok := obj.(*Program)
	return prog, ok
}

// LinkFromFile returns the link associated with f.
func LinkFromFile(f *vfs.FileDescription) (*Link, bool) {
	obj, ok := ObjectFromFile(f)
	if !ok {
		return nil, false
	}
	link, ok := obj.(*Link)
	return link, ok
}

// BTFFromFile returns the BTF object associated with f.
func BTFFromFile(f *vfs.FileDescription) (*BTF, bool) {
	obj, ok := ObjectFromFile(f)
	if !ok {
		return nil, false
	}
	btf, ok := obj.(*BTF)
	return btf, ok
}

func (fd *objectFD) Release(ctx context.Context) {
	fd.obj.DecRef(ctx)
}

func (fd *objectFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	mp, ok := fd.obj.(*Map)
	if !ok || mp.Type() != linux.BPF_MAP_TYPE_RINGBUF {
		return 0, io.EOF
	}
	rb, ok := mp.ops.(*ringbufMap)
	if !ok {
		return 0, io.EOF
	}
	record, err := rb.ReadRecord()
	if err != nil {
		return 0, err
	}
	if dst.NumBytes() < int64(len(record)) {
		return 0, linuxerr.EINVAL
	}
	n, err := dst.CopyOut(ctx, record)
	return int64(n), err
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *objectFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	mp, ok := fd.obj.(*Map)
	if !ok || mp.Type() != linux.BPF_MAP_TYPE_RINGBUF {
		return fd.FileDescriptionDefaultImpl.ConfigureMMap(ctx, opts)
	}
	rb, ok := mp.ops.(*ringbufMap)
	if !ok {
		return linuxerr.EINVAL
	}
	if err := rb.ensureMMap(ctx); err != nil {
		return err
	}
	return vfs.GenericConfigureMMap(&fd.vfsfd, rb, opts)
}

func (fd *objectFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	mp, ok := fd.obj.(*Map)
	if !ok || mp.Type() != linux.BPF_MAP_TYPE_RINGBUF {
		return 0
	}
	rb, ok := mp.ops.(*ringbufMap)
	if !ok {
		return 0
	}
	return rb.Readiness(mask)
}

func (fd *objectFD) EventRegister(e *waiter.Entry) error {
	mp, ok := fd.obj.(*Map)
	if !ok || mp.Type() != linux.BPF_MAP_TYPE_RINGBUF {
		return nil
	}
	rb, ok := mp.ops.(*ringbufMap)
	if !ok {
		return nil
	}
	return rb.EventRegister(e)
}

func (fd *objectFD) EventUnregister(e *waiter.Entry) {
	mp, ok := fd.obj.(*Map)
	if !ok || mp.Type() != linux.BPF_MAP_TYPE_RINGBUF {
		return
	}
	rb, ok := mp.ops.(*ringbufMap)
	if !ok {
		return
	}
	rb.EventUnregister(e)
}

func (fd *objectFD) Epollable() bool {
	mp, ok := fd.obj.(*Map)
	return ok && mp.Type() == linux.BPF_MAP_TYPE_RINGBUF
}
