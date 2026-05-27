package linux

// perf_event_open(2) event types.
const (
	PERF_TYPE_HARDWARE   = 0
	PERF_TYPE_SOFTWARE   = 1
	PERF_TYPE_TRACEPOINT = 2
	PERF_TYPE_HW_CACHE   = 3
	PERF_TYPE_RAW        = 4
	PERF_TYPE_BREAKPOINT = 5
)

// perf_event_open(2) flags.
const (
	PERF_FLAG_FD_CLOEXEC = 1 << 3
)

// perf event ioctls used by BPF loaders.
const (
	PERF_EVENT_IOC_ENABLE  = 0x2400
	PERF_EVENT_IOC_DISABLE = 0x2401
	PERF_EVENT_IOC_RESET   = 0x2403
	PERF_EVENT_IOC_SET_BPF = 0x40042408
)
