load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "ebpf",
    srcs = [
        "config.go",
        "context.go",
        "btf.go",
        "fd.go",
        "helpers.go",
        "hooks.go",
        "insn.go",
        "manager.go",
        "map.go",
        "object.go",
        "program.go",
        "tracepoints.go",
        "verifier.go",
        "vm.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/safemem",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/memmap",
        "//pkg/sentry/pgalloc",
        "//pkg/sentry/usage",
        "//pkg/sentry/vfs",
        "//pkg/sync",
        "//pkg/tcpip/stack",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)

go_test(
    name = "ebpf_test",
    size = "small",
    srcs = [
        "insn_test.go",
        "manager_test.go",
        "verifier_test.go",
        "vm_test.go",
    ],
    library = ":ebpf",
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/hostarch",
        "//pkg/tcpip/stack",
    ],
)
