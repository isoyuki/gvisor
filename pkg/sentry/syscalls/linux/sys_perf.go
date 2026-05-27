package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/ebpf"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"
)

const maxPerfEventAttrSize = 4096

type perfEventFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	mgr          *ebpf.Manager
	tracepointID uint64

	mu      sync.Mutex `state:"nosave"`
	prog    *ebpf.Program
	link    *ebpf.Link
	enabled bool
}

// PerfEventOpen implements Linux syscall perf_event_open(2).
func PerfEventOpen(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	mgr := t.Kernel().EBPF()
	if mgr == nil || !mgr.Enabled() {
		return 0, nil, linuxerr.ENODEV
	}
	attrAddr := args[0].Pointer()
	var hdr [16]byte
	if _, err := t.CopyInBytes(attrAddr, hdr[:]); err != nil {
		return 0, nil, err
	}
	attrSize := hostarch.ByteOrder.Uint32(hdr[4:])
	if attrSize < 16 || attrSize > maxPerfEventAttrSize {
		return 0, nil, linuxerr.EINVAL
	}
	typ := hostarch.ByteOrder.Uint32(hdr[0:])
	config := hostarch.ByteOrder.Uint64(hdr[8:])
	if typ != linux.PERF_TYPE_TRACEPOINT {
		return 0, nil, linuxerr.ENODEV
	}
	if _, ok := ebpf.TracepointHookByID(config); !ok {
		return 0, nil, linuxerr.ENOENT
	}

	vd := t.Kernel().VFS().NewAnonVirtualDentry("[perf_event]")
	defer vd.DecRef(t)
	fd := &perfEventFD{
		mgr:          mgr,
		tracepointID: config,
	}
	if err := fd.vfsfd.Init(fd, linux.O_RDWR, t.Credentials(), vd.Mount(), vd.Dentry(), &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return 0, nil, err
	}
	defer fd.vfsfd.DecRef(t)
	newFD, err := t.NewFDFrom(0, &fd.vfsfd, kernel.FDFlags{
		CloseOnExec: args[4].Uint()&linux.PERF_FLAG_FD_CLOEXEC != 0,
	})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(newFD), nil, nil
}

func perfEventFromFile(file *vfs.FileDescription) (*perfEventFD, bool) {
	if file == nil {
		return nil, false
	}
	fd, ok := file.Impl().(*perfEventFD)
	return fd, ok
}

func (fd *perfEventFD) Release(ctx context.Context) {
	fd.disable(ctx)
	fd.mu.Lock()
	prog := fd.prog
	fd.prog = nil
	fd.mu.Unlock()
	if prog != nil {
		prog.DecRef(ctx)
	}
}

func (fd *perfEventFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	switch args[1].Uint() {
	case linux.PERF_EVENT_IOC_SET_BPF:
		file := kernel.TaskFromContext(ctx).GetFile(args[2].Int())
		if file == nil {
			return 0, linuxerr.EBADF
		}
		defer file.DecRef(ctx)
		prog, ok := ebpf.ProgramFromFile(file)
		if !ok {
			return 0, linuxerr.EINVAL
		}
		return 0, fd.setProgram(ctx, prog, 0, false)
	case linux.PERF_EVENT_IOC_ENABLE:
		return 0, fd.enable(ctx)
	case linux.PERF_EVENT_IOC_DISABLE:
		fd.disable(ctx)
		return 0, nil
	case linux.PERF_EVENT_IOC_RESET:
		return 0, nil
	default:
		return 0, linuxerr.ENOTTY
	}
}

func (fd *perfEventFD) attachProgram(ctx context.Context, prog *ebpf.Program, flags uint32) (*ebpf.Link, error) {
	return fd.mgr.TracepointOpen(fd.tracepointID, prog, flags)
}

func (fd *perfEventFD) setProgram(ctx context.Context, prog *ebpf.Program, flags uint32, enable bool) error {
	if prog == nil {
		return linuxerr.EBADF
	}
	prog.IncRef()
	fd.mu.Lock()
	oldProg := fd.prog
	oldLink := fd.link
	fd.prog = prog
	fd.link = nil
	if enable {
		fd.enabled = true
	}
	enabled := fd.enabled
	fd.mu.Unlock()

	if oldLink != nil {
		oldLink.Detach()
		oldLink.DecRef(ctx)
	}
	if oldProg != nil {
		oldProg.DecRef(ctx)
	}
	if enabled {
		return fd.enable(ctx)
	}
	_ = flags
	return nil
}

func (fd *perfEventFD) enable(ctx context.Context) error {
	fd.mu.Lock()
	if fd.enabled && fd.link != nil {
		fd.mu.Unlock()
		return nil
	}
	prog := fd.prog
	if prog == nil {
		fd.mu.Unlock()
		return linuxerr.EINVAL
	}
	prog.IncRef()
	fd.mu.Unlock()

	link, err := fd.mgr.TracepointOpen(fd.tracepointID, prog, 0)
	prog.DecRef(ctx)
	if err != nil {
		return err
	}

	fd.mu.Lock()
	old := fd.link
	fd.link = link
	fd.enabled = true
	fd.mu.Unlock()
	if old != nil {
		old.Detach()
		old.DecRef(ctx)
	}
	return nil
}

func (fd *perfEventFD) disable(ctx context.Context) {
	fd.mu.Lock()
	link := fd.link
	fd.link = nil
	fd.enabled = false
	fd.mu.Unlock()
	if link != nil {
		link.Detach()
		link.DecRef(ctx)
	}
}

func (*perfEventFD) StatFS(context.Context) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.ANON_INODE_FS_MAGIC), nil
}

func (*perfEventFD) SetStat(context.Context, vfs.SetStatOptions) error {
	return linuxerr.EPERM
}

func (*perfEventFD) Stat(context.Context, vfs.StatOptions) (linux.Statx, error) {
	var stat linux.Statx
	stat.Mask = linux.STATX_TYPE | linux.STATX_MODE
	stat.Mode = uint16(linux.ModeRegular | 0600)
	return stat, nil
}
