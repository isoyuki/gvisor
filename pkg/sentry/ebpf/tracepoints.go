package ebpf

// TracepointEvent describes a synthetic tracefs event.
type TracepointEvent struct {
	Group string
	Name  string
	ID    uint64
	Hook  string
}

var tracepointEvents = []TracepointEvent{
	{Group: "raw_syscalls", Name: "sys_enter", ID: 1000, Hook: "raw_syscalls/sys_enter"},
	{Group: "raw_syscalls", Name: "sys_exit", ID: 1001, Hook: "raw_syscalls/sys_exit"},
	{Group: "syscalls", Name: "sys_enter_openat", ID: 1010, Hook: "raw_syscalls/sys_enter"},
	{Group: "syscalls", Name: "sys_exit_openat", ID: 1011, Hook: "raw_syscalls/sys_exit"},
	{Group: "gvisor_net", Name: "packet", ID: 1100, Hook: "gvisor/net/packet"},
	{Group: "gvisor_net", Name: "ingress", ID: 1101, Hook: "gvisor/net/ingress"},
	{Group: "gvisor_net", Name: "egress", ID: 1102, Hook: "gvisor/net/egress"},
}

// TracepointEvents returns synthetic tracefs events supported by eBPF.
func TracepointEvents() []TracepointEvent {
	return append([]TracepointEvent(nil), tracepointEvents...)
}

// TracepointHookByID resolves a synthetic tracefs ID to a hook name.
func TracepointHookByID(id uint64) (string, bool) {
	for _, ev := range tracepointEvents {
		if ev.ID == id {
			return ev.Hook, true
		}
	}
	return "", false
}
