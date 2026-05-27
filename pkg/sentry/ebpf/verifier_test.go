package ebpf

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

func TestVerifierAcceptsReturnImmediate(t *testing.T) {
	_, err := Verify(VerifyRequest{
		Insns: []Insn{
			mov64Imm(linux.BPF_REG_0, 0),
			exitInsn(),
		},
		ProgType:      linux.BPF_PROG_TYPE_SYSCALL,
		Context:       rawSyscallEnterContextSpec,
		HelperAllowed: func(linux.BPFHelperID) bool { return true },
	})
	if err != nil {
		t.Fatalf("Verify() failed: %v", err)
	}
}

func TestVerifierRejectsUnreadRegister(t *testing.T) {
	_, err := Verify(VerifyRequest{
		Insns: []Insn{
			mov64Reg(linux.BPF_REG_0, linux.BPF_REG_2),
			exitInsn(),
		},
		ProgType:      linux.BPF_PROG_TYPE_SYSCALL,
		Context:       rawSyscallEnterContextSpec,
		HelperAllowed: func(linux.BPFHelperID) bool { return true },
	})
	if err == nil {
		t.Fatalf("Verify() succeeded, want unread register rejection")
	}
}

func TestVerifierRejectsInvalidStackRead(t *testing.T) {
	_, err := Verify(VerifyRequest{
		Insns: []Insn{
			ldxMem(linux.BPF_DW, linux.BPF_REG_0, linux.BPF_REG_10, -8),
			exitInsn(),
		},
		ProgType:      linux.BPF_PROG_TYPE_SYSCALL,
		Context:       rawSyscallEnterContextSpec,
		HelperAllowed: func(linux.BPFHelperID) bool { return true },
	})
	if err == nil {
		t.Fatalf("Verify() succeeded, want invalid stack read rejection")
	}
}
