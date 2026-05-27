package linux

import (
	"bytes"
	"path"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/ebpf"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/bpffs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

const maxBPFAttrSize = 4096

// BPF implements Linux syscall bpf(2).
func BPF(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	cmd := linux.BPFCommand(args[0].Uint())
	attrAddr := args[1].Pointer()
	size := uint32(args[2].Uint())

	mgr := t.Kernel().EBPF()
	if mgr == nil || !mgr.Enabled() {
		if !t.HasRootCapability(linux.CAP_SYS_ADMIN) {
			return 0, nil, linuxerr.EPERM
		}
		t.Kernel().EmitUnimplementedEvent(t, sysno)
		return 0, nil, linuxerr.ENOSYS
	}
	cfg := mgr.Config()
	if !cfg.AllowUnprivileged && !t.HasRootCapability(linux.CAP_BPF) && !t.HasRootCapability(linux.CAP_SYS_ADMIN) {
		return 0, nil, linuxerr.EPERM
	}

	switch cmd {
	case linux.BPF_MAP_CREATE:
		return bpfMapCreate(t, mgr, attrAddr, size)
	case linux.BPF_MAP_LOOKUP_ELEM:
		return bpfMapLookupElem(t, attrAddr, size)
	case linux.BPF_MAP_UPDATE_ELEM:
		return bpfMapUpdateElem(t, mgr, attrAddr, size)
	case linux.BPF_MAP_DELETE_ELEM:
		return bpfMapDeleteElem(t, mgr, attrAddr, size)
	case linux.BPF_MAP_GET_NEXT_KEY:
		return bpfMapGetNextKey(t, attrAddr, size)
	case linux.BPF_MAP_FREEZE:
		return bpfMapFreeze(t, attrAddr, size)
	case linux.BPF_PROG_LOAD:
		return bpfProgLoad(t, mgr, attrAddr, size)
	case linux.BPF_PROG_TEST_RUN:
		return bpfProgTestRun(t, mgr, attrAddr, size)
	case linux.BPF_OBJ_GET_INFO_BY_FD:
		return bpfObjGetInfoByFD(t, attrAddr, size)
	case linux.BPF_RAW_TRACEPOINT_OPEN:
		return bpfRawTracepointOpen(t, mgr, attrAddr, size)
	case linux.BPF_LINK_CREATE:
		return bpfLinkCreate(t, mgr, attrAddr, size)
	case linux.BPF_LINK_UPDATE:
		return bpfLinkUpdate(t, mgr, attrAddr, size)
	case linux.BPF_LINK_DETACH:
		return bpfLinkDetach(t, attrAddr, size)
	case linux.BPF_PROG_ATTACH:
		return bpfProgAttach(t, mgr, attrAddr, size)
	case linux.BPF_PROG_DETACH:
		return bpfProgDetach(t, mgr, attrAddr, size)
	case linux.BPF_OBJ_PIN:
		return bpfObjPin(t, attrAddr, size)
	case linux.BPF_OBJ_GET:
		return bpfObjGet(t, attrAddr, size)
	case linux.BPF_BTF_LOAD:
		return bpfBTFLoad(t, mgr, attrAddr, size)
	case linux.BPF_BTF_GET_FD_BY_ID:
		return bpfBTFGetFDByID(t, mgr, attrAddr, size)
	default:
		return 0, nil, linuxerr.EINVAL
	}
}

func bpfMapCreate(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 20)
	if err != nil {
		return 0, nil, err
	}
	name := ""
	if len(attr) >= 44 {
		name = fixedBPFName(attr[28:44])
	}
	mp, err := mgr.MapCreate(ebpf.MapCreateAttrs{
		Type:       linux.BPFMapType(readAttrU32(attr, 0)),
		KeySize:    readAttrU32(attr, 4),
		ValueSize:  readAttrU32(attr, 8),
		MaxEntries: readAttrU32(attr, 12),
		Flags:      readAttrU32(attr, 16),
		Name:       name,
	})
	if err != nil {
		return 0, nil, err
	}
	fdfile, err := ebpf.NewObjectFD(t, t.Kernel().VFS(), mp, linux.O_RDWR)
	if err != nil {
		mp.DecRef(t)
		return 0, nil, err
	}
	defer fdfile.DecRef(t)
	fd, err := t.NewFDFrom(0, fdfile, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

func bpfMapLookupElem(t *kernel.Task, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 24)
	if err != nil {
		return 0, nil, err
	}
	mp, err := mapFromFD(t, int32(readAttrU32(attr, 0)))
	if err != nil {
		return 0, nil, err
	}
	defer mp.file.DecRef(t)
	key, err := copyBPFBytesIn(t, readAttrAddr(attr, 8), mp.mapObj.KeySize())
	if err != nil {
		return 0, nil, err
	}
	value, err := mp.mapObj.Lookup(key)
	if err != nil {
		return 0, nil, err
	}
	if _, err := t.CopyOutBytes(readAttrAddr(attr, 16), value); err != nil {
		return 0, nil, err
	}
	return 0, nil, nil
}

func bpfMapUpdateElem(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 32)
	if err != nil {
		return 0, nil, err
	}
	mp, err := mapFromFD(t, int32(readAttrU32(attr, 0)))
	if err != nil {
		return 0, nil, err
	}
	defer mp.file.DecRef(t)
	key, err := copyBPFBytesIn(t, readAttrAddr(attr, 8), mp.mapObj.KeySize())
	if err != nil {
		return 0, nil, err
	}
	value, err := copyBPFBytesIn(t, readAttrAddr(attr, 16), mp.mapObj.ValueSize())
	if err != nil {
		return 0, nil, err
	}
	flags := readAttrU64(attr, 24)
	if mp.mapObj.Type() == linux.BPF_MAP_TYPE_PROG_ARRAY {
		progFD := int32(hostarch.ByteOrder.Uint32(value))
		prog, err := programFromFD(t, progFD)
		if err != nil {
			return 0, nil, err
		}
		defer prog.file.DecRef(t)
		return 0, nil, mgr.ProgArrayUpdate(t, mp.mapObj, key, prog.progObj, flags)
	}
	return 0, nil, mp.mapObj.Update(key, value, flags)
}

func bpfMapDeleteElem(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 16)
	if err != nil {
		return 0, nil, err
	}
	mp, err := mapFromFD(t, int32(readAttrU32(attr, 0)))
	if err != nil {
		return 0, nil, err
	}
	defer mp.file.DecRef(t)
	key, err := copyBPFBytesIn(t, readAttrAddr(attr, 8), mp.mapObj.KeySize())
	if err != nil {
		return 0, nil, err
	}
	if mp.mapObj.Type() == linux.BPF_MAP_TYPE_PROG_ARRAY {
		return 0, nil, mgr.ProgArrayDelete(t, mp.mapObj, key)
	}
	return 0, nil, mp.mapObj.Delete(key)
}

func bpfMapGetNextKey(t *kernel.Task, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 24)
	if err != nil {
		return 0, nil, err
	}
	mp, err := mapFromFD(t, int32(readAttrU32(attr, 0)))
	if err != nil {
		return 0, nil, err
	}
	defer mp.file.DecRef(t)
	var key []byte
	keyAddr := readAttrAddr(attr, 8)
	if keyAddr != 0 {
		key, err = copyBPFBytesIn(t, keyAddr, mp.mapObj.KeySize())
		if err != nil {
			return 0, nil, err
		}
	}
	next, err := mp.mapObj.NextKey(key)
	if err != nil {
		return 0, nil, err
	}
	if _, err := t.CopyOutBytes(readAttrAddr(attr, 16), next); err != nil {
		return 0, nil, err
	}
	return 0, nil, nil
}

func bpfMapFreeze(t *kernel.Task, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 4)
	if err != nil {
		return 0, nil, err
	}
	mp, err := mapFromFD(t, int32(readAttrU32(attr, 0)))
	if err != nil {
		return 0, nil, err
	}
	defer mp.file.DecRef(t)
	return 0, nil, mp.mapObj.Freeze()
}

func bpfProgLoad(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 40)
	if err != nil {
		return 0, nil, err
	}
	insnCnt := readAttrU32(attr, 4)
	if insnCnt == 0 || insnCnt > mgr.Config().MaxProgramInsns {
		return 0, nil, linuxerr.E2BIG
	}
	raw, err := copyBPFBytesIn(t, readAttrAddr(attr, 8), insnCnt*8)
	if err != nil {
		return 0, nil, err
	}
	insns, err := ebpf.DecodeInsns(raw)
	if err != nil {
		return 0, nil, err
	}
	license := ""
	if licenseAddr := readAttrAddr(attr, 16); licenseAddr != 0 {
		license, err = t.CopyInString(licenseAddr, 4096)
		if err != nil {
			return 0, nil, err
		}
	}
	name := ""
	if len(attr) >= 64 {
		name = fixedBPFName(attr[48:64])
	}
	if progBTFID := readAttrU32(attr, 72); progBTFID != 0 {
		btf, err := btfFromFD(t, int32(progBTFID))
		if err != nil {
			return 0, nil, err
		}
		btf.file.DecRef(t)
	}
	prog, log, err := mgr.ProgramLoad(ebpf.ProgramLoadAttrs{
		Type:               linux.BPFProgramType(readAttrU32(attr, 0)),
		AttachType:         linux.BPFAttachType(readAttrU32(attr, 68)),
		ExpectedAttachType: linux.BPFAttachType(readAttrU32(attr, 68)),
		Name:               name,
		License:            license,
		Insns:              insns,
		LogLevel:           readAttrU32(attr, 24),
		MapResolver: func(fd int32) (*ebpf.Map, error) {
			mp, err := mapFromFD(t, fd)
			if err != nil {
				return nil, err
			}
			defer mp.file.DecRef(t)
			mp.mapObj.IncRef()
			return mp.mapObj, nil
		},
	})
	copyVerifierLog(t, attr, log)
	if err != nil {
		return 0, nil, err
	}
	fdfile, err := ebpf.NewObjectFD(t, t.Kernel().VFS(), prog, linux.O_RDWR)
	if err != nil {
		prog.DecRef(t)
		return 0, nil, err
	}
	defer fdfile.DecRef(t)
	fd, err := t.NewFDFrom(0, fdfile, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

func bpfProgTestRun(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 40)
	if err != nil {
		return 0, nil, err
	}
	prog, err := programFromFD(t, int32(readAttrU32(attr, 0)))
	if err != nil {
		return 0, nil, err
	}
	defer prog.file.DecRef(t)
	r0, err := mgr.ProgramTestRun(prog.progObj, &ebpf.SyscallEnterContext{}, taskInfo(t))
	if err != nil {
		return 0, nil, err
	}
	var out [4]byte
	hostarch.ByteOrder.PutUint32(out[:], uint32(r0))
	if _, err := t.CopyOutBytes(attrAddr+4, out[:]); err != nil {
		return 0, nil, err
	}
	return 0, nil, nil
}

func bpfObjGetInfoByFD(t *kernel.Task, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 16)
	if err != nil {
		return 0, nil, err
	}
	file := t.GetFile(int32(readAttrU32(attr, 0)))
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)
	obj, ok := ebpf.ObjectFromFile(file)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}
	var info []byte
	switch o := obj.(type) {
	case *ebpf.Map:
		info = mapInfo(o)
	case *ebpf.Program:
		info = programInfo(o)
	case *ebpf.Link:
		info = linkInfo(o)
	case *ebpf.BTF:
		info = btfInfo(o)
	default:
		return 0, nil, linuxerr.EINVAL
	}
	infoLen := readAttrU32(attr, 4)
	if infoLen > uint32(len(info)) {
		infoLen = uint32(len(info))
	}
	if _, err := t.CopyOutBytes(readAttrAddr(attr, 8), info[:infoLen]); err != nil {
		return 0, nil, err
	}
	var lenOut [4]byte
	hostarch.ByteOrder.PutUint32(lenOut[:], uint32(len(info)))
	if _, err := t.CopyOutBytes(attrAddr+4, lenOut[:]); err != nil {
		return 0, nil, err
	}
	return 0, nil, nil
}

func bpfRawTracepointOpen(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 12)
	if err != nil {
		return 0, nil, err
	}
	name, err := t.CopyInString(readAttrAddr(attr, 0), 256)
	if err != nil {
		return 0, nil, err
	}
	prog, err := programFromFD(t, int32(readAttrU32(attr, 8)))
	if err != nil {
		return 0, nil, err
	}
	defer prog.file.DecRef(t)
	link, err := mgr.RawTracepointOpen(name, prog.progObj, 0)
	if err != nil {
		return 0, nil, err
	}
	fdfile, err := ebpf.NewObjectFD(t, t.Kernel().VFS(), link, linux.O_RDWR)
	if err != nil {
		link.DecRef(t)
		return 0, nil, err
	}
	defer fdfile.DecRef(t)
	fd, err := t.NewFDFrom(0, fdfile, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

func bpfLinkCreate(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 16)
	if err != nil {
		return 0, nil, err
	}
	prog, err := programFromFD(t, int32(readAttrU32(attr, 0)))
	if err != nil {
		return 0, nil, err
	}
	defer prog.file.DecRef(t)
	target := int32(readAttrU32(attr, 4))
	attach := linux.BPFAttachType(readAttrU32(attr, 8))
	flags := readAttrU32(attr, 12)
	var link *ebpf.Link
	if attach == linux.BPF_PERF_EVENT {
		file := t.GetFile(target)
		if file == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer file.DecRef(t)
		perf, ok := perfEventFromFile(file)
		if !ok {
			return 0, nil, linuxerr.EINVAL
		}
		link, err = perf.attachProgram(t, prog.progObj, flags)
	} else {
		link, err = mgr.LinkCreate(prog.progObj, attach, flags)
	}
	if err != nil {
		return 0, nil, err
	}
	fdfile, err := ebpf.NewObjectFD(t, t.Kernel().VFS(), link, linux.O_RDWR)
	if err != nil {
		link.DecRef(t)
		return 0, nil, err
	}
	defer fdfile.DecRef(t)
	fd, err := t.NewFDFrom(0, fdfile, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

func bpfLinkUpdate(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 12)
	if err != nil {
		return 0, nil, err
	}
	linkFile, err := linkFromFD(t, int32(readAttrU32(attr, 0)))
	if err != nil {
		return 0, nil, err
	}
	defer linkFile.file.DecRef(t)
	prog, err := programFromFD(t, int32(readAttrU32(attr, 4)))
	if err != nil {
		return 0, nil, err
	}
	defer prog.file.DecRef(t)
	var oldProg *ebpf.Program
	if oldFD := int32(readAttrU32(attr, 12)); oldFD != 0 {
		old, err := programFromFD(t, oldFD)
		if err != nil {
			return 0, nil, err
		}
		defer old.file.DecRef(t)
		oldProg = old.progObj
	}
	return 0, nil, mgr.UpdateLink(t, linkFile.linkObj, prog.progObj, readAttrU32(attr, 8), oldProg)
}

func bpfLinkDetach(t *kernel.Task, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 4)
	if err != nil {
		return 0, nil, err
	}
	file := t.GetFile(int32(readAttrU32(attr, 0)))
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)
	link, ok := ebpf.LinkFromFile(file)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}
	link.Detach()
	return 0, nil, nil
}

func bpfProgAttach(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 16)
	if err != nil {
		return 0, nil, err
	}
	target := int32(readAttrU32(attr, 0))
	prog, err := programFromFD(t, int32(readAttrU32(attr, 4)))
	if err != nil {
		return 0, nil, err
	}
	defer prog.file.DecRef(t)
	attach := linux.BPFAttachType(readAttrU32(attr, 8))
	flags := readAttrU32(attr, 12)
	if attach == linux.BPF_PERF_EVENT {
		file := t.GetFile(target)
		if file == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer file.DecRef(t)
		perf, ok := perfEventFromFile(file)
		if !ok {
			return 0, nil, linuxerr.EINVAL
		}
		return 0, nil, perf.setProgram(t, prog.progObj, flags, true)
	}
	return 0, nil, mgr.ProgramAttach(t, target, prog.progObj, attach, flags)
}

func bpfProgDetach(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 12)
	if err != nil {
		return 0, nil, err
	}
	target := int32(readAttrU32(attr, 0))
	attach := linux.BPFAttachType(readAttrU32(attr, 8))
	if attach == linux.BPF_PERF_EVENT {
		file := t.GetFile(target)
		if file == nil {
			return 0, nil, linuxerr.EBADF
		}
		defer file.DecRef(t)
		perf, ok := perfEventFromFile(file)
		if !ok {
			return 0, nil, linuxerr.EINVAL
		}
		perf.disable(t)
		return 0, nil, nil
	}
	return 0, nil, mgr.ProgramDetach(t, target, attach)
}

func bpfObjPin(t *kernel.Task, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 16)
	if err != nil {
		return 0, nil, err
	}
	if readAttrU32(attr, 12) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	pathname, err := t.CopyInString(readAttrAddr(attr, 0), linux.PATH_MAX)
	if err != nil {
		return 0, nil, err
	}
	file := t.GetFile(int32(readAttrU32(attr, 8)))
	if file == nil {
		return 0, nil, linuxerr.EBADF
	}
	defer file.DecRef(t)
	obj, ok := ebpf.ObjectFromFile(file)
	if !ok {
		return 0, nil, linuxerr.EINVAL
	}
	if err := checkBPFFSParent(t, pathname); err != nil {
		return 0, nil, err
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, fspath.Parse(pathname), disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)
	pinCtx := bpffs.WithPinnedObject(t, obj)
	pinFile, err := t.Kernel().VFS().OpenAt(pinCtx, t.Credentials(), &tpop.pop, &vfs.OpenOptions{
		Flags: linux.O_CREAT | linux.O_EXCL | linux.O_RDWR,
		Mode:  0600,
	})
	if err != nil {
		return 0, nil, err
	}
	pinFile.DecRef(pinCtx)
	return 0, nil, nil
}

func bpfObjGet(t *kernel.Task, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 16)
	if err != nil {
		return 0, nil, err
	}
	pathname, err := t.CopyInString(readAttrAddr(attr, 0), linux.PATH_MAX)
	if err != nil {
		return 0, nil, err
	}
	if readAttrU32(attr, 12) != 0 {
		return 0, nil, linuxerr.EINVAL
	}
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, fspath.Parse(pathname), disallowEmptyPath, nofollowFinalSymlink)
	if err != nil {
		return 0, nil, err
	}
	defer tpop.Release(t)
	file, err := t.Kernel().VFS().OpenAt(t, t.Credentials(), &tpop.pop, &vfs.OpenOptions{
		Flags: linux.O_RDWR,
	})
	if err != nil {
		return 0, nil, err
	}
	defer file.DecRef(t)
	if _, ok := ebpf.ObjectFromFile(file); !ok {
		return 0, nil, linuxerr.EINVAL
	}
	fd, err := t.NewFDFrom(0, file, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

func bpfBTFLoad(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 20)
	if err != nil {
		return 0, nil, err
	}
	data, err := copyBPFBytesIn(t, readAttrAddr(attr, 0), readAttrU32(attr, 16))
	if err != nil {
		return 0, nil, err
	}
	btf, err := mgr.BTFLoad(data, "btf")
	if err != nil {
		return 0, nil, err
	}
	fdfile, err := ebpf.NewObjectFD(t, t.Kernel().VFS(), btf, linux.O_RDWR)
	if err != nil {
		btf.DecRef(t)
		return 0, nil, err
	}
	defer fdfile.DecRef(t)
	fd, err := t.NewFDFrom(0, fdfile, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

func bpfBTFGetFDByID(t *kernel.Task, mgr *ebpf.Manager, attrAddr hostarch.Addr, size uint32) (uintptr, *kernel.SyscallControl, error) {
	attr, err := copyBPFAttr(t, attrAddr, size, 4)
	if err != nil {
		return 0, nil, err
	}
	btf, err := mgr.BTFByID(readAttrU32(attr, 0))
	if err != nil {
		return 0, nil, err
	}
	fdfile, err := ebpf.NewObjectFD(t, t.Kernel().VFS(), btf, linux.O_RDWR)
	if err != nil {
		btf.DecRef(t)
		return 0, nil, err
	}
	defer fdfile.DecRef(t)
	fd, err := t.NewFDFrom(0, fdfile, kernel.FDFlags{CloseOnExec: true})
	if err != nil {
		return 0, nil, err
	}
	return uintptr(fd), nil, nil
}

func checkBPFFSParent(t *kernel.Task, pathname string) error {
	parent := path.Dir(pathname)
	tpop, err := getTaskPathOperation(t, linux.AT_FDCWD, fspath.Parse(parent), disallowEmptyPath, followFinalSymlink)
	if err != nil {
		return err
	}
	defer tpop.Release(t)
	vd, err := t.Kernel().VFS().GetDentryAt(t, t.Credentials(), &tpop.pop, &vfs.GetDentryOptions{})
	if err != nil {
		return err
	}
	defer vd.DecRef(t)
	if vd.Mount().Filesystem().FilesystemType().Name() != bpffs.Name {
		return linuxerr.EINVAL
	}
	return nil
}

type mapFile struct {
	file   *vfs.FileDescription
	mapObj *ebpf.Map
}

type progFile struct {
	file    *vfs.FileDescription
	progObj *ebpf.Program
}

type linkFile struct {
	file    *vfs.FileDescription
	linkObj *ebpf.Link
}

type btfFile struct {
	file   *vfs.FileDescription
	btfObj *ebpf.BTF
}

func mapFromFD(t *kernel.Task, fd int32) (*mapFile, error) {
	file := t.GetFile(fd)
	if file == nil {
		return nil, linuxerr.EBADF
	}
	mp, ok := ebpf.MapFromFile(file)
	if !ok {
		file.DecRef(t)
		return nil, linuxerr.EINVAL
	}
	return &mapFile{file: file, mapObj: mp}, nil
}

func programFromFD(t *kernel.Task, fd int32) (*progFile, error) {
	file := t.GetFile(fd)
	if file == nil {
		return nil, linuxerr.EBADF
	}
	prog, ok := ebpf.ProgramFromFile(file)
	if !ok {
		file.DecRef(t)
		return nil, linuxerr.EINVAL
	}
	return &progFile{file: file, progObj: prog}, nil
}

func linkFromFD(t *kernel.Task, fd int32) (*linkFile, error) {
	file := t.GetFile(fd)
	if file == nil {
		return nil, linuxerr.EBADF
	}
	link, ok := ebpf.LinkFromFile(file)
	if !ok {
		file.DecRef(t)
		return nil, linuxerr.EINVAL
	}
	return &linkFile{file: file, linkObj: link}, nil
}

func btfFromFD(t *kernel.Task, fd int32) (*btfFile, error) {
	file := t.GetFile(fd)
	if file == nil {
		return nil, linuxerr.EBADF
	}
	btf, ok := ebpf.BTFFromFile(file)
	if !ok {
		file.DecRef(t)
		return nil, linuxerr.EINVAL
	}
	return &btfFile{file: file, btfObj: btf}, nil
}

func copyBPFAttr(t *kernel.Task, addr hostarch.Addr, size uint32, minSize uint32) ([]byte, error) {
	if size == 0 {
		return nil, linuxerr.EINVAL
	}
	if size < minSize {
		return nil, linuxerr.EINVAL
	}
	if size > maxBPFAttrSize {
		return nil, linuxerr.E2BIG
	}
	buf := make([]byte, size)
	if _, err := t.CopyInBytes(addr, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func copyBPFBytesIn(t *kernel.Task, addr hostarch.Addr, size uint32) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if _, err := t.CopyInBytes(addr, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func copyVerifierLog(t *kernel.Task, attr []byte, log *ebpf.Log) {
	if log == nil || len(attr) < 40 {
		return
	}
	logSize := readAttrU32(attr, 28)
	logAddr := readAttrAddr(attr, 32)
	if logSize == 0 || logAddr == 0 {
		return
	}
	out := []byte(log.String())
	if uint32(len(out)) >= logSize {
		out = out[:logSize-1]
	}
	out = append(out, 0)
	_, _ = t.CopyOutBytes(logAddr, out)
}

func readAttrU32(buf []byte, off int) uint32 {
	if off+4 > len(buf) {
		return 0
	}
	return hostarch.ByteOrder.Uint32(buf[off:])
}

func readAttrU64(buf []byte, off int) uint64 {
	if off+8 > len(buf) {
		return 0
	}
	return hostarch.ByteOrder.Uint64(buf[off:])
}

func readAttrAddr(buf []byte, off int) hostarch.Addr {
	return hostarch.Addr(readAttrU64(buf, off))
}

func fixedBPFName(buf []byte) string {
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf)
}

func mapInfo(mp *ebpf.Map) []byte {
	info := make([]byte, 128)
	hostarch.ByteOrder.PutUint32(info[0:], uint32(mp.Type()))
	hostarch.ByteOrder.PutUint32(info[4:], mp.ID())
	hostarch.ByteOrder.PutUint32(info[8:], mp.KeySize())
	hostarch.ByteOrder.PutUint32(info[12:], mp.ValueSize())
	hostarch.ByteOrder.PutUint32(info[16:], mp.MaxEntries())
	hostarch.ByteOrder.PutUint32(info[20:], mp.Flags())
	copy(info[32:48], mp.Name())
	return info
}

func programInfo(prog *ebpf.Program) []byte {
	info := make([]byte, 128)
	hostarch.ByteOrder.PutUint32(info[0:], uint32(prog.Type()))
	hostarch.ByteOrder.PutUint32(info[4:], prog.ID())
	copy(info[16:32], prog.Name())
	return info
}

func linkInfo(link *ebpf.Link) []byte {
	info := make([]byte, 64)
	hostarch.ByteOrder.PutUint32(info[0:], link.ID())
	copy(info[16:32], link.Name())
	return info
}

func btfInfo(btf *ebpf.BTF) []byte {
	info := make([]byte, 64)
	hostarch.ByteOrder.PutUint32(info[0:], btf.ID())
	hostarch.ByteOrder.PutUint32(info[4:], uint32(len(btf.Data())))
	copy(info[16:32], btf.Name())
	return info
}

func taskInfo(t *kernel.Task) ebpf.TaskInfo {
	creds := t.Credentials()
	pid := uint32(t.ThreadID())
	tgid := uint32(t.ThreadGroup().ID())
	return ebpf.TaskInfo{
		PID:  pid,
		TGID: tgid,
		UID:  uint32(creds.EffectiveKUID.In(creds.UserNamespace).OrOverflow()),
		GID:  uint32(creds.EffectiveKGID.In(creds.UserNamespace).OrOverflow()),
		Comm: t.Name(),
	}
}
