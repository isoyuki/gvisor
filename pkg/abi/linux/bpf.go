// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linux

import (
	"structs"
)

// BPFCommand is a command passed to bpf(2).
type BPFCommand uint32

// bpf(2) command values.
const (
	BPF_MAP_CREATE BPFCommand = iota
	BPF_MAP_LOOKUP_ELEM
	BPF_MAP_UPDATE_ELEM
	BPF_MAP_DELETE_ELEM
	BPF_MAP_GET_NEXT_KEY
	BPF_PROG_LOAD
	BPF_OBJ_PIN
	BPF_OBJ_GET
	BPF_PROG_ATTACH
	BPF_PROG_DETACH
	BPF_PROG_TEST_RUN
	BPF_PROG_GET_NEXT_ID
	BPF_MAP_GET_NEXT_ID
	BPF_PROG_GET_FD_BY_ID
	BPF_MAP_GET_FD_BY_ID
	BPF_OBJ_GET_INFO_BY_FD
	BPF_PROG_QUERY
	BPF_RAW_TRACEPOINT_OPEN
	BPF_BTF_LOAD
	BPF_BTF_GET_FD_BY_ID
	BPF_TASK_FD_QUERY
	BPF_MAP_LOOKUP_AND_DELETE_ELEM
	BPF_MAP_FREEZE
	BPF_BTF_GET_NEXT_ID
	BPF_MAP_LOOKUP_BATCH
	BPF_MAP_LOOKUP_AND_DELETE_BATCH
	BPF_MAP_UPDATE_BATCH
	BPF_MAP_DELETE_BATCH
	BPF_LINK_CREATE
	BPF_LINK_UPDATE
	BPF_LINK_GET_FD_BY_ID
	BPF_LINK_GET_NEXT_ID
	BPF_ENABLE_STATS
	BPF_ITER_CREATE
	BPF_LINK_DETACH
	BPF_PROG_BIND_MAP
)

// BPFMapType is an eBPF map type.
type BPFMapType uint32

// eBPF map types.
const (
	BPF_MAP_TYPE_UNSPEC BPFMapType = iota
	BPF_MAP_TYPE_HASH
	BPF_MAP_TYPE_ARRAY
	BPF_MAP_TYPE_PROG_ARRAY
	BPF_MAP_TYPE_PERF_EVENT_ARRAY
	BPF_MAP_TYPE_PERCPU_HASH
	BPF_MAP_TYPE_PERCPU_ARRAY
	BPF_MAP_TYPE_STACK_TRACE
	BPF_MAP_TYPE_CGROUP_ARRAY
	BPF_MAP_TYPE_LRU_HASH
	BPF_MAP_TYPE_LRU_PERCPU_HASH
	BPF_MAP_TYPE_LPM_TRIE
	BPF_MAP_TYPE_ARRAY_OF_MAPS
	BPF_MAP_TYPE_HASH_OF_MAPS
	BPF_MAP_TYPE_DEVMAP
	BPF_MAP_TYPE_SOCKMAP
	BPF_MAP_TYPE_CPUMAP
	BPF_MAP_TYPE_XSKMAP
	BPF_MAP_TYPE_SOCKHASH
	BPF_MAP_TYPE_CGROUP_STORAGE
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE
	BPF_MAP_TYPE_QUEUE
	BPF_MAP_TYPE_STACK
	BPF_MAP_TYPE_SK_STORAGE
	BPF_MAP_TYPE_DEVMAP_HASH
	BPF_MAP_TYPE_STRUCT_OPS
	BPF_MAP_TYPE_RINGBUF
	BPF_MAP_TYPE_INODE_STORAGE
	BPF_MAP_TYPE_TASK_STORAGE
	BPF_MAP_TYPE_BLOOM_FILTER
	BPF_MAP_TYPE_USER_RINGBUF
	BPF_MAP_TYPE_CGRP_STORAGE
	BPF_MAP_TYPE_ARENA
)

// BPFProgramType is an eBPF program type.
type BPFProgramType uint32

// eBPF program types.
const (
	BPF_PROG_TYPE_UNSPEC BPFProgramType = iota
	BPF_PROG_TYPE_SOCKET_FILTER
	BPF_PROG_TYPE_KPROBE
	BPF_PROG_TYPE_SCHED_CLS
	BPF_PROG_TYPE_SCHED_ACT
	BPF_PROG_TYPE_TRACEPOINT
	BPF_PROG_TYPE_XDP
	BPF_PROG_TYPE_PERF_EVENT
	BPF_PROG_TYPE_CGROUP_SKB
	BPF_PROG_TYPE_CGROUP_SOCK
	BPF_PROG_TYPE_LWT_IN
	BPF_PROG_TYPE_LWT_OUT
	BPF_PROG_TYPE_LWT_XMIT
	BPF_PROG_TYPE_SOCK_OPS
	BPF_PROG_TYPE_SK_SKB
	BPF_PROG_TYPE_CGROUP_DEVICE
	BPF_PROG_TYPE_SK_MSG
	BPF_PROG_TYPE_RAW_TRACEPOINT
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR
	BPF_PROG_TYPE_LWT_SEG6LOCAL
	BPF_PROG_TYPE_LIRC_MODE2
	BPF_PROG_TYPE_SK_REUSEPORT
	BPF_PROG_TYPE_FLOW_DISSECTOR
	BPF_PROG_TYPE_CGROUP_SYSCTL
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE
	BPF_PROG_TYPE_CGROUP_SOCKOPT
	BPF_PROG_TYPE_TRACING
	BPF_PROG_TYPE_STRUCT_OPS
	BPF_PROG_TYPE_EXT
	BPF_PROG_TYPE_LSM
	BPF_PROG_TYPE_SK_LOOKUP
	BPF_PROG_TYPE_SYSCALL
	BPF_PROG_TYPE_NETFILTER
)

// BPFAttachType is an eBPF attach type.
type BPFAttachType uint32

// eBPF attach types used by the sentry eBPF implementation.
const (
	BPF_CGROUP_INET_INGRESS BPFAttachType = iota
	BPF_CGROUP_INET_EGRESS
	BPF_CGROUP_INET_SOCK_CREATE
	BPF_CGROUP_SOCK_OPS
	BPF_SK_SKB_STREAM_PARSER
	BPF_SK_SKB_STREAM_VERDICT
	BPF_CGROUP_DEVICE
	BPF_SK_MSG_VERDICT
	BPF_CGROUP_INET4_BIND
	BPF_CGROUP_INET6_BIND
	BPF_CGROUP_INET4_CONNECT
	BPF_CGROUP_INET6_CONNECT
	BPF_CGROUP_INET4_POST_BIND
	BPF_CGROUP_INET6_POST_BIND
	BPF_CGROUP_UDP4_SENDMSG
	BPF_CGROUP_UDP6_SENDMSG
	BPF_LIRC_MODE2
	BPF_FLOW_DISSECTOR
	BPF_CGROUP_SYSCTL
	BPF_CGROUP_UDP4_RECVMSG
	BPF_CGROUP_UDP6_RECVMSG
	BPF_CGROUP_GETSOCKOPT
	BPF_CGROUP_SETSOCKOPT
	BPF_TRACE_RAW_TP
	BPF_TRACE_FENTRY
	BPF_TRACE_FEXIT
	BPF_MODIFY_RETURN
	BPF_LSM_MAC
	BPF_TRACE_ITER
	BPF_CGROUP_INET4_GETPEERNAME
	BPF_CGROUP_INET6_GETPEERNAME
	BPF_CGROUP_INET4_GETSOCKNAME
	BPF_CGROUP_INET6_GETSOCKNAME
	BPF_XDP_DEVMAP
	BPF_CGROUP_INET_SOCK_RELEASE
	BPF_XDP_CPUMAP
	BPF_SK_LOOKUP
	BPF_XDP
	BPF_SK_SKB_VERDICT
	BPF_SK_REUSEPORT_SELECT
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE
	BPF_PERF_EVENT
	BPF_TRACE_KPROBE_MULTI
	BPF_LSM_CGROUP
	BPF_STRUCT_OPS
	BPF_NETFILTER
	BPF_TCX_INGRESS
	BPF_TCX_EGRESS
	BPF_TRACE_UPROBE_MULTI
	BPF_CGROUP_UNIX_CONNECT
	BPF_CGROUP_UNIX_SENDMSG
	BPF_CGROUP_UNIX_RECVMSG
	BPF_CGROUP_UNIX_GETPEERNAME
	BPF_CGROUP_UNIX_GETSOCKNAME
	BPF_NETKIT_PRIMARY
	BPF_NETKIT_PEER
	BPF_TRACE_KPROBE_SESSION
)

// eBPF map update flags.
const (
	BPF_ANY     = 0
	BPF_NOEXIST = 1
	BPF_EXIST   = 2
)

// eBPF link update flags.
const (
	BPF_F_REPLACE = 1 << 2
)

// eBPF object flags.
const (
	BPF_F_RDONLY      = 1 << 3
	BPF_F_WRONLY      = 1 << 4
	BPF_F_MMAPABLE    = 1 << 10
	BPF_F_RDONLY_PROG = 1 << 7
	BPF_F_WRONLY_PROG = 1 << 8
	BPF_F_SLEEPABLE   = 1 << 4
)

// BPFHelperID is an eBPF helper function ID.
type BPFHelperID uint32

// eBPF helper IDs used by the sentry eBPF implementation.
const (
	BPF_FUNC_unspec BPFHelperID = iota
	BPF_FUNC_map_lookup_elem
	BPF_FUNC_map_update_elem
	BPF_FUNC_map_delete_elem
	BPF_FUNC_probe_read
	BPF_FUNC_ktime_get_ns
	BPF_FUNC_trace_printk
	BPF_FUNC_get_prandom_u32
	BPF_FUNC_get_smp_processor_id
	BPF_FUNC_skb_store_bytes
	BPF_FUNC_l3_csum_replace
	BPF_FUNC_l4_csum_replace
	BPF_FUNC_tail_call
	BPF_FUNC_clone_redirect
	BPF_FUNC_get_current_pid_tgid
	BPF_FUNC_get_current_uid_gid
	BPF_FUNC_get_current_comm
	BPF_FUNC_get_cgroup_classid
	BPF_FUNC_skb_vlan_push
	BPF_FUNC_skb_vlan_pop
	BPF_FUNC_skb_get_tunnel_key
	BPF_FUNC_skb_set_tunnel_key
	BPF_FUNC_perf_event_read
	BPF_FUNC_redirect
	BPF_FUNC_get_route_realm
	BPF_FUNC_perf_event_output
	BPF_FUNC_skb_load_bytes
	BPF_FUNC_get_stackid
	BPF_FUNC_csum_diff
	BPF_FUNC_skb_get_tunnel_opt
	BPF_FUNC_skb_set_tunnel_opt
	BPF_FUNC_skb_change_proto
	BPF_FUNC_skb_change_type
	BPF_FUNC_skb_under_cgroup
	BPF_FUNC_get_hash_recalc
	BPF_FUNC_get_current_task
	BPF_FUNC_probe_write_user
	BPF_FUNC_current_task_under_cgroup
	BPF_FUNC_skb_change_tail
	BPF_FUNC_skb_pull_data
	BPF_FUNC_csum_update
	BPF_FUNC_set_hash_invalid
	BPF_FUNC_get_numa_node_id
	BPF_FUNC_skb_change_head
	BPF_FUNC_xdp_adjust_head
	BPF_FUNC_probe_read_str
	BPF_FUNC_get_socket_cookie
	BPF_FUNC_get_socket_uid
	BPF_FUNC_set_hash
	BPF_FUNC_setsockopt
	BPF_FUNC_skb_adjust_room
	BPF_FUNC_redirect_map
	BPF_FUNC_sk_redirect_map
	BPF_FUNC_sock_map_update
	BPF_FUNC_xdp_adjust_meta
	BPF_FUNC_perf_event_read_value
	BPF_FUNC_perf_prog_read_value
	BPF_FUNC_getsockopt
	BPF_FUNC_override_return
	BPF_FUNC_sock_ops_cb_flags_set
	BPF_FUNC_msg_redirect_map
	BPF_FUNC_msg_apply_bytes
	BPF_FUNC_msg_cork_bytes
	BPF_FUNC_msg_pull_data
	BPF_FUNC_bind
	BPF_FUNC_xdp_adjust_tail
	BPF_FUNC_skb_get_xfrm_state
	BPF_FUNC_get_stack
	BPF_FUNC_skb_load_bytes_relative
	BPF_FUNC_fib_lookup
	BPF_FUNC_sock_hash_update
	BPF_FUNC_msg_redirect_hash
	BPF_FUNC_sk_redirect_hash
	BPF_FUNC_lwt_push_encap
	BPF_FUNC_lwt_seg6_store_bytes
	BPF_FUNC_lwt_seg6_adjust_srh
	BPF_FUNC_lwt_seg6_action
	BPF_FUNC_rc_repeat
	BPF_FUNC_rc_keydown
	BPF_FUNC_skb_cgroup_id
	BPF_FUNC_get_current_cgroup_id
	BPF_FUNC_get_local_storage
	BPF_FUNC_sk_select_reuseport
	BPF_FUNC_skb_ancestor_cgroup_id
	BPF_FUNC_sk_lookup_tcp
	BPF_FUNC_sk_lookup_udp
	BPF_FUNC_sk_release
	BPF_FUNC_map_push_elem
	BPF_FUNC_map_pop_elem
	BPF_FUNC_map_peek_elem
	BPF_FUNC_msg_push_data
	BPF_FUNC_msg_pop_data
	BPF_FUNC_rc_pointer_rel
	BPF_FUNC_spin_lock
	BPF_FUNC_spin_unlock
	BPF_FUNC_sk_fullsock
	BPF_FUNC_tcp_sock
	BPF_FUNC_skb_ecn_set_ce
	BPF_FUNC_get_listener_sock
	BPF_FUNC_skc_lookup_tcp
	BPF_FUNC_tcp_check_syncookie
	BPF_FUNC_sysctl_get_name
	BPF_FUNC_sysctl_get_current_value
	BPF_FUNC_sysctl_get_new_value
	BPF_FUNC_sysctl_set_new_value
	BPF_FUNC_strtol
	BPF_FUNC_strtoul
	BPF_FUNC_sk_storage_get
	BPF_FUNC_sk_storage_delete
	BPF_FUNC_send_signal
	BPF_FUNC_tcp_gen_syncookie
	BPF_FUNC_skb_output
	BPF_FUNC_probe_read_user
	BPF_FUNC_probe_read_kernel
	BPF_FUNC_probe_read_user_str
	BPF_FUNC_probe_read_kernel_str
	BPF_FUNC_tcp_send_ack
	BPF_FUNC_send_signal_thread
	BPF_FUNC_jiffies64
	BPF_FUNC_read_branch_records
	BPF_FUNC_get_ns_current_pid_tgid
	BPF_FUNC_xdp_output
	BPF_FUNC_get_netns_cookie
	BPF_FUNC_get_current_ancestor_cgroup_id
	BPF_FUNC_sk_assign
	BPF_FUNC_ktime_get_boot_ns
	BPF_FUNC_seq_printf
	BPF_FUNC_seq_write
	BPF_FUNC_sk_cgroup_id
	BPF_FUNC_sk_ancestor_cgroup_id
	BPF_FUNC_ringbuf_output
	BPF_FUNC_ringbuf_reserve
	BPF_FUNC_ringbuf_submit
	BPF_FUNC_ringbuf_discard
)

// eBPF instruction classes and mode bits.
const (
	BPF_LD    = 0x00
	BPF_LDX   = 0x01
	BPF_ST    = 0x02
	BPF_STX   = 0x03
	BPF_ALU   = 0x04
	BPF_JMP   = 0x05
	BPF_JMP32 = 0x06
	BPF_ALU64 = 0x07

	BPF_W  = 0x00
	BPF_H  = 0x08
	BPF_B  = 0x10
	BPF_DW = 0x18

	BPF_IMM = 0x00
	BPF_ABS = 0x20
	BPF_IND = 0x40
	BPF_MEM = 0x60
	BPF_LEN = 0x80
	BPF_MSH = 0xa0

	BPF_K = 0x00
	BPF_X = 0x08
)

// eBPF ALU/JMP operations.
const (
	BPF_ADD  = 0x00
	BPF_SUB  = 0x10
	BPF_MUL  = 0x20
	BPF_DIV  = 0x30
	BPF_OR   = 0x40
	BPF_AND  = 0x50
	BPF_LSH  = 0x60
	BPF_RSH  = 0x70
	BPF_NEG  = 0x80
	BPF_MOD  = 0x90
	BPF_XOR  = 0xa0
	BPF_MOV  = 0xb0
	BPF_ARSH = 0xc0
	BPF_END  = 0xd0

	BPF_JA   = 0x00
	BPF_JEQ  = 0x10
	BPF_JGT  = 0x20
	BPF_JGE  = 0x30
	BPF_JSET = 0x40
	BPF_JNE  = 0x50
	BPF_JSGT = 0x60
	BPF_JSGE = 0x70
	BPF_CALL = 0x80
	BPF_EXIT = 0x90
	BPF_JLT  = 0xa0
	BPF_JLE  = 0xb0
	BPF_JSLT = 0xc0
	BPF_JSLE = 0xd0
)

// eBPF pseudo source registers for LD_IMM_DW.
const (
	BPF_PSEUDO_MAP_FD = 1
	BPF_PSEUDO_CALL   = 1
)

// eBPF register numbers.
const (
	BPF_REG_0  = 0
	BPF_REG_1  = 1
	BPF_REG_2  = 2
	BPF_REG_3  = 3
	BPF_REG_4  = 4
	BPF_REG_5  = 5
	BPF_REG_6  = 6
	BPF_REG_7  = 7
	BPF_REG_8  = 8
	BPF_REG_9  = 9
	BPF_REG_10 = 10
)

// BPF object name lengths.
const (
	BPF_OBJ_NAME_LEN = 16
)

// BTF format constants.
const (
	BTF_MAGIC   = 0xeb9f
	BTF_VERSION = 1
)

// BPFInstruction is a raw BPF virtual machine instruction.
//
// +marshal slice:BPFInstructionSlice
// +stateify savable
type BPFInstruction struct {
	_ structs.HostLayout
	// OpCode is the operation to execute.
	OpCode uint16

	// JumpIfTrue is the number of instructions to skip if OpCode is a
	// conditional instruction and the condition is true.
	JumpIfTrue uint8

	// JumpIfFalse is the number of instructions to skip if OpCode is a
	// conditional instruction and the condition is false.
	JumpIfFalse uint8

	// K is a constant parameter. The meaning depends on the value of OpCode.
	K uint32
}
