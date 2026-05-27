// Package bpffs implements a sandbox-local bpf filesystem.
package bpffs

import (
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/ebpf"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Name is the filesystem name used by mount(2).
const Name = "bpf"

const (
	defaultDirMode  = linux.FileMode(0755)
	defaultFileMode = linux.FileMode(0600)
)

type pinnedObjectContextKey struct{}

// WithPinnedObject returns a context that allows creating one bpffs pin.
func WithPinnedObject(ctx context.Context, obj ebpf.Object) context.Context {
	return context.WithValue(ctx, pinnedObjectContextKey{}, obj)
}

func pinnedObjectFromContext(ctx context.Context) ebpf.Object {
	obj, _ := ctx.Value(pinnedObjectContextKey{}).(ebpf.Object)
	return obj
}

// FilesystemType implements vfs.FilesystemType.
//
// +stateify savable
type FilesystemType struct{}

// Name implements vfs.FilesystemType.Name.
func (FilesystemType) Name() string {
	return Name
}

// Release implements vfs.FilesystemType.Release.
func (FilesystemType) Release(ctx context.Context) {}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (fsType FilesystemType) GetFilesystem(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, source string, opts vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, nil, err
	}
	fs := &filesystem{devMinor: devMinor}
	fs.VFSFilesystem().Init(vfsObj, &fsType, fs)
	root := fs.newDir(ctx, creds, defaultDirMode, nil)
	var rootD kernfs.Dentry
	rootD.InitRoot(&fs.Filesystem, root)
	return fs.VFSFilesystem(), rootD.VFSDentry(), nil
}

// Release implements vfs.FilesystemImpl.Release.
func (fs *filesystem) Release(ctx context.Context) {
	fs.Filesystem.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}

// dir implements kernfs.Inode.
//
// +stateify savable
type dir struct {
	dirRefs
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeNotAnonymous
	kernfs.InodeNotSymlink
	kernfs.InodeTemporary
	kernfs.InodeWatches
	kernfs.InodeFSOwned
	kernfs.OrderedChildren

	fs    *filesystem
	locks vfs.FileLocks
}

func (fs *filesystem) newDir(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, contents map[string]kernfs.Inode) *dir {
	d := &dir{fs: fs}
	d.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|mode.Permissions())
	d.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})
	d.InitRefs()
	d.IncLinks(d.OrderedChildren.Populate(contents))
	return d
}

// Open implements kernfs.Inode.Open.
func (d *dir) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	opts.Flags &= linux.O_ACCMODE | linux.O_CREAT | linux.O_EXCL | linux.O_TRUNC |
		linux.O_DIRECTORY | linux.O_NOFOLLOW | linux.O_NONBLOCK | linux.O_NOCTTY
	fd, err := kernfs.NewGenericDirectoryFD(rp.Mount(), kd, rp.Credentials(), &d.OrderedChildren, &d.locks, &opts, kernfs.GenericDirectoryFDOptions{
		SeekEnd: kernfs.SeekEndStaticEntries,
	})
	if err != nil {
		return nil, err
	}
	return fd.VFSFileDescription(), nil
}

// DecRef implements kernfs.Inode.DecRef.
func (d *dir) DecRef(ctx context.Context) {
	d.dirRefs.DecRef(func() { d.Destroy(ctx) })
}

// NewFile implements kernfs.Inode.NewFile.
func (d *dir) NewFile(ctx context.Context, name string, opts vfs.OpenOptions) (kernfs.Inode, error) {
	obj := pinnedObjectFromContext(ctx)
	if obj == nil {
		return nil, linuxerr.EPERM
	}
	f := d.fs.newPinnedFile(ctx, auth.CredentialsFromContext(ctx), opts.Mode, obj)
	if err := d.OrderedChildren.Insert(name, f); err != nil {
		f.DecRef(ctx)
		return nil, err
	}
	d.TouchCMtime(ctx)
	return f, nil
}

// NewDir implements kernfs.Inode.NewDir.
func (d *dir) NewDir(ctx context.Context, name string, opts vfs.MkdirOptions) (kernfs.Inode, error) {
	child := d.fs.newDir(ctx, auth.CredentialsFromContext(ctx), opts.Mode, nil)
	if err := d.OrderedChildren.Insert(name, child); err != nil {
		child.DecRef(ctx)
		return nil, err
	}
	d.TouchCMtime(ctx)
	d.IncLinks(1)
	return child, nil
}

// NewLink implements kernfs.Inode.NewLink.
func (*dir) NewLink(context.Context, string, kernfs.Inode) (kernfs.Inode, error) {
	return nil, linuxerr.EPERM
}

// NewSymlink implements kernfs.Inode.NewSymlink.
func (*dir) NewSymlink(context.Context, string, string) (kernfs.Inode, error) {
	return nil, linuxerr.EPERM
}

// NewNode implements kernfs.Inode.NewNode.
func (*dir) NewNode(context.Context, string, vfs.MknodOptions) (kernfs.Inode, error) {
	return nil, linuxerr.EPERM
}

// RmDir implements kernfs.Inode.RmDir.
func (d *dir) RmDir(ctx context.Context, name string, child kernfs.Inode) error {
	if err := d.OrderedChildren.RmDir(ctx, name, child); err != nil {
		return err
	}
	d.DecLinks()
	d.TouchCMtime(ctx)
	return nil
}

// Unlink implements kernfs.Inode.Unlink.
func (d *dir) Unlink(ctx context.Context, name string, child kernfs.Inode) error {
	if err := d.OrderedChildren.Unlink(ctx, name, child); err != nil {
		return err
	}
	d.TouchCMtime(ctx)
	return nil
}

// Rename implements kernfs.Inode.Rename.
func (d *dir) Rename(ctx context.Context, oldname, newname string, child, dstDir kernfs.Inode) error {
	if err := d.OrderedChildren.Rename(ctx, oldname, newname, child, dstDir); err != nil {
		return err
	}
	d.TouchCMtime(ctx)
	return nil
}

// StatFS implements kernfs.Inode.StatFS.
func (*dir) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.BPF_FS_MAGIC), nil
}

// pinnedFile is a bpffs inode holding one pinned eBPF object reference.
//
// +stateify savable
type pinnedFile struct {
	pinnedFileRefs
	kernfs.InodeAlwaysValid
	kernfs.InodeAttrs
	kernfs.InodeNotDirectory
	kernfs.InodeNotAnonymous
	kernfs.InodeNotSymlink
	kernfs.InodeTemporary
	kernfs.InodeWatches
	kernfs.InodeFSOwned

	obj ebpf.Object
}

func (fs *filesystem) newPinnedFile(ctx context.Context, creds *auth.Credentials, mode linux.FileMode, obj ebpf.Object) *pinnedFile {
	if obj == nil {
		panic("bpffs.newPinnedFile called with nil object")
	}
	obj.IncRef()
	f := &pinnedFile{obj: obj}
	if mode.Permissions() == 0 {
		mode = defaultFileMode
	}
	f.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeRegular|mode.Permissions())
	f.InitRefs()
	return f
}

// DecRef implements kernfs.Inode.DecRef.
func (f *pinnedFile) DecRef(ctx context.Context) {
	f.pinnedFileRefs.DecRef(func() {
		f.obj.DecRef(ctx)
	})
}

// Open implements kernfs.Inode.Open.
func (f *pinnedFile) Open(ctx context.Context, rp *vfs.ResolvingPath, kd *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	f.obj.IncRef()
	fd, err := ebpf.NewObjectFDAt(ctx, rp.Mount(), kd.VFSDentry(), f.obj, opts.Flags)
	if err != nil {
		f.obj.DecRef(ctx)
		return nil, err
	}
	return fd, nil
}

// StatFS implements kernfs.Inode.StatFS.
func (*pinnedFile) StatFS(context.Context, *vfs.Filesystem) (linux.Statfs, error) {
	return vfs.GenericStatFS(linux.BPF_FS_MAGIC), nil
}

func (f *pinnedFile) String() string {
	return fmt.Sprintf("bpffs pinned object %d", f.obj.ID())
}
