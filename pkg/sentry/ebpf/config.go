package ebpf

import "gvisor.dev/gvisor/pkg/abi/linux"

// Config controls the sandbox-local sentry eBPF subsystem.
type Config struct {
	// Enabled indicates whether bpf(2) is handled by the sentry eBPF manager.
	Enabled bool

	// AllowUnprivileged permits bpf(2) without CAP_BPF/CAP_SYS_ADMIN. This is
	// false by default.
	AllowUnprivileged bool

	// MaxPrograms is the maximum number of live programs in the sandbox.
	MaxPrograms uint64

	// MaxMaps is the maximum number of live maps in the sandbox.
	MaxMaps uint64

	// MaxLinks is the maximum number of live links in the sandbox.
	MaxLinks uint64

	// MaxBTFObjects is reserved for future BTF support.
	MaxBTFObjects uint64

	// MaxMapMemoryBytes is the maximum charged map memory in the sandbox.
	MaxMapMemoryBytes uint64

	// MaxProgramInsns is the maximum instruction count accepted at load time.
	MaxProgramInsns uint32

	// MaxVerifierStates is the verifier complexity limit.
	MaxVerifierStates uint32

	// MaxTailCalls is the maximum number of tail calls per invocation.
	MaxTailCalls uint32

	// AllowedProgramTypes restricts program types accepted by BPF_PROG_LOAD.
	AllowedProgramTypes []linux.BPFProgramType

	// AllowedMapTypes restricts map types accepted by BPF_MAP_CREATE.
	AllowedMapTypes []linux.BPFMapType

	// AllowedHelpers restricts helper calls accepted by the verifier.
	AllowedHelpers []linux.BPFHelperID
}

// DefaultConfig returns default sentry eBPF limits.
func DefaultConfig(enabled bool) Config {
	return Config{
		Enabled:           enabled,
		MaxPrograms:       1024,
		MaxMaps:           4096,
		MaxLinks:          4096,
		MaxBTFObjects:     1024,
		MaxMapMemoryBytes: 256 << 20,
		MaxProgramInsns:   4096,
		MaxVerifierStates: 100000,
		MaxTailCalls:      32,
		AllowedProgramTypes: []linux.BPFProgramType{
			linux.BPF_PROG_TYPE_SOCKET_FILTER,
			linux.BPF_PROG_TYPE_SCHED_CLS,
			linux.BPF_PROG_TYPE_SCHED_ACT,
			linux.BPF_PROG_TYPE_TRACEPOINT,
			linux.BPF_PROG_TYPE_XDP,
			linux.BPF_PROG_TYPE_PERF_EVENT,
			linux.BPF_PROG_TYPE_RAW_TRACEPOINT,
			linux.BPF_PROG_TYPE_SYSCALL,
		},
		AllowedMapTypes: []linux.BPFMapType{
			linux.BPF_MAP_TYPE_ARRAY,
			linux.BPF_MAP_TYPE_HASH,
			linux.BPF_MAP_TYPE_PROG_ARRAY,
			linux.BPF_MAP_TYPE_RINGBUF,
		},
		AllowedHelpers: []linux.BPFHelperID{
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
		},
	}
}

func (c Config) programTypeAllowed(typ linux.BPFProgramType) bool {
	if len(c.AllowedProgramTypes) == 0 {
		return true
	}
	for _, allowed := range c.AllowedProgramTypes {
		if typ == allowed {
			return true
		}
	}
	return false
}

func (c Config) mapTypeAllowed(typ linux.BPFMapType) bool {
	if len(c.AllowedMapTypes) == 0 {
		return true
	}
	for _, allowed := range c.AllowedMapTypes {
		if typ == allowed {
			return true
		}
	}
	return false
}

func (c Config) helperAllowed(id linux.BPFHelperID) bool {
	if len(c.AllowedHelpers) == 0 {
		return true
	}
	for _, allowed := range c.AllowedHelpers {
		if id == allowed {
			return true
		}
	}
	return false
}
