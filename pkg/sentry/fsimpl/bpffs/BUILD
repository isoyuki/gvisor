load("//tools:defs.bzl", "go_library")
load("//tools/go_generics:defs.bzl", "go_template_instance")

package(default_applicable_licenses = ["//:license"])

licenses(["notice"])

go_template_instance(
    name = "dir_refs",
    out = "dir_refs.go",
    package = "bpffs",
    prefix = "dir",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "dir",
    },
)

go_template_instance(
    name = "pinned_file_refs",
    out = "pinned_file_refs.go",
    package = "bpffs",
    prefix = "pinnedFile",
    template = "//pkg/refs:refs_template",
    types = {
        "T": "pinnedFile",
    },
)

go_library(
    name = "bpffs",
    srcs = [
        "bpffs.go",
        "dir_refs.go",
        "pinned_file_refs.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/refs",
        "//pkg/sentry/ebpf",
        "//pkg/sentry/fsimpl/kernfs",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
    ],
)
