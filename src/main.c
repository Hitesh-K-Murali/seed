#include <stdio.h>
#include <stdlib.h>

/* Include our SELinux validator module */
#include "selinux_validator.h"

int main(int argc, char *argv[])
{
    int ret;

    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║         SELinux & eBPF Environment Validation Tool             ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    /* Initialize the SELinux validator */
    ret = selinux_validator_init();
    if (ret != SELINUX_STATUS_SUCCESS)
    {
        fprintf(stderr, "[ERROR] Failed to initialize SELinux validator\n");
        return EXIT_FAILURE;
    }

    /* Run complete validation */
    ret = selinux_validate_ebpf_environment();

    /* Display final verdict */
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                      Final Assessment                          ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    switch (ret)
    {
    case SELINUX_STATUS_SUCCESS:
        printf("✓ \033[1;32mSYSTEM READY\033[0m: eBPF programs can be loaded and run\n");
        printf("  You can proceed with eBPF development on this system.\n");
        break;

    case SELINUX_STATUS_NOT_ENABLED:
        printf("⚠ \033[1;33mSELINUX DISABLED\033[0m: SELinux is not enabled\n");
        printf("  eBPF operations should work if you have proper capabilities.\n");
        break;

    case SELINUX_STATUS_PERMISSION_DENIED:
        printf("⚠ \033[1;33mPERMISSION ISSUES\033[0m: SELinux may block eBPF operations\n");
        printf("  Recommended actions:\n");
        printf("  - Run as root or with proper capabilities (CAP_BPF, CAP_PERFMON)\n");
        printf("  - Set SELinux to permissive mode (for testing): setenforce 0\n");
        printf("  - Create custom SELinux policy module for your application\n");
        break;

    case SELINUX_STATUS_NOT_SUPPORTED:
        printf("✗ \033[1;31mNOT SUPPORTED\033[0m: eBPF is not available on this system\n");
        printf("  Possible causes:\n");
        printf("  - Kernel not compiled with CONFIG_BPF=y\n");
        printf("  - BPF syscall disabled\n");
        printf("  - Kernel version too old (requires 4.x or later for full support)\n");
        break;

    default:
        printf("✗ \033[1;31mERROR\033[0m: Unknown error occurred during validation\n");
        break;
    }

    printf("\n");

    /* Display usage hints */
    if (ret == SELINUX_STATUS_SUCCESS || ret == SELINUX_STATUS_PERMISSION_DENIED)
    {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║                    Example: Monitor Syscalls                   ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        printf("\n");
        printf("To attach an eBPF program to a syscall tracepoint:\n\n");
        printf("1. Load your eBPF program:\n");
        printf("   bpf_prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));\n\n");
        printf("2. Attach to tracepoint (e.g., sys_enter_open):\n");
        printf("   perf_event_open(..., \"syscalls/sys_enter_open\", ...);\n");
        printf("   ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, bpf_prog_fd);\n\n");
        printf("SELinux requirements for tracepoint monitoring:\n");
        printf("  - bpf { prog_load, prog_run, map_create, map_read, map_write }\n");
        printf("  - perf_event { open, kernel }\n");
        printf("  - capability { bpf, perfmon }\n");
        printf("\n");
    }

    /* Cleanup */
    selinux_validator_cleanup();

    printf("Validation complete.\n\n");

    return (ret == SELINUX_STATUS_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}
