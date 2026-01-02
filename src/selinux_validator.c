#include "selinux_validator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/bpf.h>

/* SELinux library headers */
#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/context.h>
#endif

/* Color codes for terminal output */
#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[1;31m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_BLUE "\033[1;34m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_BOLD "\033[1m"

/* ============================================
 * Initialization and Cleanup
 * ============================================ */

int selinux_validator_init(void)
{
    printf("%s[*] Initializing SELinux Validator...%s\n", COLOR_CYAN, COLOR_RESET);
    return SELINUX_STATUS_SUCCESS;
}

void selinux_validator_cleanup(void)
{
    printf("%s[*] Cleaning up SELinux Validator...%s\n", COLOR_CYAN, COLOR_RESET);
}

/* ============================================
 * SELinux Status Functions
 * ============================================ */

bool selinux_check_enabled(void)
{
#ifdef HAVE_SELINUX
    return is_selinux_enabled() == 1;
#else
    /* Check if /sys/fs/selinux exists as fallback */
    return access("/sys/fs/selinux", F_OK) == 0;
#endif
}

selinux_mode_t selinux_get_mode(void)
{
#ifdef HAVE_SELINUX
    int mode = security_getenforce();
    if (mode < 0)
    {
        return SELINUX_MODE_UNKNOWN;
    }
    return (selinux_mode_t)mode;
#else
    FILE *fp = fopen("/sys/fs/selinux/enforce", "r");
    if (!fp)
    {
        return SELINUX_MODE_DISABLED;
    }

    int mode;
    if (fscanf(fp, "%d", &mode) != 1)
    {
        fclose(fp);
        return SELINUX_MODE_UNKNOWN;
    }
    fclose(fp);

    return (mode == 1) ? SELINUX_MODE_ENFORCING : SELINUX_MODE_PERMISSIVE;
#endif
}

int selinux_get_status(selinux_status_t *status)
{
    if (!status)
    {
        return SELINUX_STATUS_ERROR;
    }

    memset(status, 0, sizeof(selinux_status_t));

    /* Check if SELinux is enabled */
    status->enabled = selinux_check_enabled();

    if (!status->enabled)
    {
        status->mode = SELINUX_MODE_DISABLED;
        snprintf(status->policy_type, sizeof(status->policy_type), "N/A");
        snprintf(status->current_context, sizeof(status->current_context), "N/A");
        return SELINUX_STATUS_NOT_ENABLED;
    }

    /* Get enforcement mode */
    status->mode = selinux_get_mode();

#ifdef HAVE_SELINUX
    /* Get policy type */
    char *policy = NULL;
    if (selinux_getpolicytype(&policy) == 0 && policy)
    {
        snprintf(status->policy_type, sizeof(status->policy_type), "%s", policy);
        free(policy);
    }
    else
    {
        snprintf(status->policy_type, sizeof(status->policy_type), "unknown");
    }

    /* Get current context */
    char *context = NULL;
    if (getcon(&context) == 0 && context)
    {
        snprintf(status->current_context, sizeof(status->current_context), "%s", context);
        freecon(context);
    }
    else
    {
        snprintf(status->current_context, sizeof(status->current_context), "unknown");
    }

    /* Check MLS support */
    status->mls_enabled = is_selinux_mls_enabled();
#else
    /* Fallback: try to read policy from files */
    FILE *fp = fopen("/etc/selinux/config", "r");
    if (fp)
    {
        char line[256];
        while (fgets(line, sizeof(line), fp))
        {
            if (strstr(line, "SELINUXTYPE="))
            {
                char *policy_start = strchr(line, '=');
                if (policy_start)
                {
                    policy_start++;
                    /* Remove newline */
                    char *newline = strchr(policy_start, '\n');
                    if (newline)
                        *newline = '\0';
                    snprintf(status->policy_type, sizeof(status->policy_type), "%s", policy_start);
                }
            }
        }
        fclose(fp);
    }

    if (strlen(status->policy_type) == 0)
    {
        snprintf(status->policy_type, sizeof(status->policy_type), "targeted");
    }

    snprintf(status->current_context, sizeof(status->current_context),
             "unavailable (libselinux not linked)");
    status->mls_enabled = 0;
#endif

    return SELINUX_STATUS_SUCCESS;
}

void selinux_display_status(const selinux_status_t *status)
{
    if (!status)
    {
        return;
    }

    printf("\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("%s                    SELinux Status Report                    %s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n",
           COLOR_BOLD, COLOR_RESET);

    /* SELinux Enabled Status */
    printf("%s%-25s:%s ", COLOR_CYAN, "SELinux Status", COLOR_RESET);
    if (status->enabled)
    {
        printf("%s✓ Enabled%s\n", COLOR_GREEN, COLOR_RESET);
    }
    else
    {
        printf("%s✗ Disabled%s\n", COLOR_RED, COLOR_RESET);
    }

    if (!status->enabled)
    {
        printf("\n%s⚠ SELinux is not enabled on this system%s\n",
               COLOR_YELLOW, COLOR_RESET);
        return;
    }

    /* Enforcement Mode */
    printf("%s%-25s:%s ", COLOR_CYAN, "Enforcement Mode", COLOR_RESET);
    switch (status->mode)
    {
    case SELINUX_MODE_ENFORCING:
        printf("%sEnforcing%s\n", COLOR_GREEN, COLOR_RESET);
        break;
    case SELINUX_MODE_PERMISSIVE:
        printf("%sPermissive%s\n", COLOR_YELLOW, COLOR_RESET);
        break;
    case SELINUX_MODE_DISABLED:
        printf("%sDisabled%s\n", COLOR_RED, COLOR_RESET);
        break;
    default:
        printf("%sUnknown%s\n", COLOR_RED, COLOR_RESET);
    }

    /* Policy Type */
    printf("%s%-25s:%s %s\n",
           COLOR_CYAN, "Policy Type", COLOR_RESET, status->policy_type);

    /* Current Context */
    printf("%s%-25s:%s %s\n",
           COLOR_CYAN, "Current Context", COLOR_RESET, status->current_context);

    /* MLS Status */
    printf("%s%-25s:%s ", COLOR_CYAN, "MLS Support", COLOR_RESET);
    if (status->mls_enabled)
    {
        printf("%s✓ Enabled%s\n", COLOR_GREEN, COLOR_RESET);
    }
    else
    {
        printf("%s✗ Disabled%s\n", COLOR_YELLOW, COLOR_RESET);
    }

    printf("\n");
}

int selinux_set_mode(selinux_mode_t mode)
{
    if (geteuid() != 0)
    {
        fprintf(stderr, "%s[ERROR] Setting SELinux mode requires root privileges%s\n",
                COLOR_RED, COLOR_RESET);
        return SELINUX_STATUS_PERMISSION_DENIED;
    }

#ifdef HAVE_SELINUX
    int target_mode;
    if (mode == SELINUX_MODE_ENFORCING)
    {
        target_mode = 1;
    }
    else if (mode == SELINUX_MODE_PERMISSIVE)
    {
        target_mode = 0;
    }
    else
    {
        return SELINUX_STATUS_ERROR;
    }

    if (security_setenforce(target_mode) == 0)
    {
        printf("%s[✓] SELinux mode set to %s%s\n",
               COLOR_GREEN,
               (mode == SELINUX_MODE_ENFORCING) ? "Enforcing" : "Permissive",
               COLOR_RESET);
        return SELINUX_STATUS_SUCCESS;
    }
    else
    {
        fprintf(stderr, "%s[ERROR] Failed to set SELinux mode: %s%s\n",
                COLOR_RED, strerror(errno), COLOR_RESET);
        return SELINUX_STATUS_ERROR;
    }
#else
    fprintf(stderr, "%s[ERROR] libselinux not available%s\n",
            COLOR_RED, COLOR_RESET);
    return SELINUX_STATUS_NOT_SUPPORTED;
#endif
}

int selinux_get_context(char *context, size_t context_len)
{
    if (!context || context_len == 0)
    {
        return SELINUX_STATUS_ERROR;
    }

#ifdef HAVE_SELINUX
    char *ctx = NULL;
    if (getcon(&ctx) == 0 && ctx)
    {
        snprintf(context, context_len, "%s", ctx);
        freecon(ctx);
        return SELINUX_STATUS_SUCCESS;
    }
    return SELINUX_STATUS_ERROR;
#else
    snprintf(context, context_len, "unavailable");
    return SELINUX_STATUS_NOT_SUPPORTED;
#endif
}

/* ============================================
 * Policy Management Functions
 * ============================================ */

int selinux_display_policies(void)
{
    printf("\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("%s                 SELinux Policy Information                 %s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n",
           COLOR_BOLD, COLOR_RESET);

    if (!selinux_check_enabled())
    {
        printf("%s⚠ SELinux is not enabled - no policies to display%s\n",
               COLOR_YELLOW, COLOR_RESET);
        return SELINUX_STATUS_NOT_ENABLED;
    }

    /* Read policy version */
    FILE *fp = fopen("/sys/fs/selinux/policyvers", "r");
    if (fp)
    {
        int version;
        if (fscanf(fp, "%d", &version) == 1)
        {
            printf("%s%-25s:%s %d\n",
                   COLOR_CYAN, "Policy Version", COLOR_RESET, version);
        }
        fclose(fp);
    }

    /* Check if policy includes BPF class */
    printf("\n%sChecking for BPF-related policies...%s\n", COLOR_CYAN, COLOR_RESET);

    if (selinux_check_bpf_policy())
    {
        printf("%s  ✓ BPF security class found in policy%s\n",
               COLOR_GREEN, COLOR_RESET);
    }
    else
    {
        printf("%s  ⚠ BPF security class not found (may not be supported)%s\n",
               COLOR_YELLOW, COLOR_RESET);
    }

    printf("\n");
    return SELINUX_STATUS_SUCCESS;
}

bool selinux_check_bpf_policy(void)
{
    /* Check if /sys/fs/selinux/class/bpf exists */
    return access("/sys/fs/selinux/class/bpf", F_OK) == 0;
}

int selinux_query_policy(const char *source_type, const char *target_type,
                         const char *class_name, policy_query_result_t *result)
{
    if (!result)
    {
        return SELINUX_STATUS_ERROR;
    }

    memset(result, 0, sizeof(policy_query_result_t));

    /* This is a simplified implementation - full implementation would use
     * libsepol to query the binary policy */
    printf("%s[INFO] Policy query: %s -> %s : %s%s\n",
           COLOR_CYAN, source_type, target_type, class_name, COLOR_RESET);

    return SELINUX_STATUS_SUCCESS;
}

void selinux_free_policy_result(policy_query_result_t *result)
{
    if (!result)
    {
        return;
    }

    if (result->rules)
    {
        for (int i = 0; i < result->rule_count; i++)
        {
            free(result->rules[i]);
        }
        free(result->rules);
    }

    result->rules = NULL;
    result->rule_count = 0;
}

int selinux_fetch_policies(void)
{
    return selinux_display_policies();
}

/* ============================================
 * eBPF Capability Functions
 * ============================================ */

bool ebpf_validate_bpf_syscall(void)
{
    /* Try to make a BPF syscall with invalid parameters
     * If we get EINVAL or EPERM, the syscall exists
     * If we get ENOSYS, the syscall doesn't exist */

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    long ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));

    if (ret < 0)
    {
        if (errno == ENOSYS)
        {
            return false; /* Syscall not implemented */
        }
        /* EINVAL, EPERM, etc. mean the syscall exists */
        return true;
    }

    /* Unexpected success? Close and return true */
    if (ret >= 0)
    {
        close((int)ret);
        return true;
    }

    return false;
}

bool ebpf_check_kernel_config(void)
{
    /* Check for BPF support in multiple ways */

    /* Method 1: Check if /sys/kernel/btf/vmlinux exists (indicates BPF+BTF support) */
    if (access("/sys/kernel/btf/vmlinux", F_OK) == 0)
    {
        return true;
    }

    /* Method 2: Check if /proc/sys/kernel/unprivileged_bpf_disabled exists */
    if (access("/proc/sys/kernel/unprivileged_bpf_disabled", F_OK) == 0)
    {
        return true;
    }

    /* Method 3: Try to read kernel config */
    const char *config_paths[] = {
        "/proc/config.gz",
        "/boot/config-" /* would need to append kernel version */,
        NULL};

    for (int i = 0; config_paths[i] != NULL; i++)
    {
        if (access(config_paths[i], R_OK) == 0)
        {
            /* File exists - in a full implementation we would parse it */
            return true;
        }
    }

    /* If we can make a BPF syscall, kernel supports it */
    return ebpf_validate_bpf_syscall();
}

bool ebpf_check_selinux_permissions(void)
{
    if (!selinux_check_enabled())
    {
        /* SELinux disabled means it won't block BPF */
        return true;
    }

    /* Check if BPF class exists in policy */
    bool has_bpf_class = selinux_check_bpf_policy();

    if (!has_bpf_class)
    {
        /* No BPF class in policy - older policy, may allow by default */
        return true;
    }

    /* In permissive mode, operations are allowed but logged */
    selinux_mode_t mode = selinux_get_mode();
    if (mode == SELINUX_MODE_PERMISSIVE)
    {
        return true;
    }

    /* For enforcing mode, we'd need to check actual permissions
     * This requires querying the policy with current context */

#ifdef HAVE_SELINUX
    char *context = NULL;
    if (getcon(&context) == 0 && context)
    {
        /* Check if context has BPF permissions
         * This is a simplified check - full implementation would use
         * selinux_check_access() or similar */

        /* For now, assume if we're running as unconfined_t or similar,
         * we have permissions */
        bool has_permission = (strstr(context, "unconfined") != NULL);
        freecon(context);
        return has_permission;
    }
#endif

    /* If we can't determine, be conservative */
    return false;
}

int ebpf_check_capability(ebpf_capability_t *capability)
{
    if (!capability)
    {
        return SELINUX_STATUS_ERROR;
    }

    memset(capability, 0, sizeof(ebpf_capability_t));

    /* Check BPF syscall availability */
    capability->bpf_syscall_available = ebpf_validate_bpf_syscall();

    /* Check kernel BPF support */
    capability->kernel_bpf_support = ebpf_check_kernel_config();

    /* Check SELinux permissions */
    capability->selinux_allows_bpf = ebpf_check_selinux_permissions();

    /* Check capabilities - note: checking capabilities properly requires libcap
     * For now, we'll check if we're root as a proxy */
    uid_t uid = geteuid();
    capability->has_cap_sys_admin = (uid == 0);
    capability->has_cap_bpf = (uid == 0);
    capability->has_cap_perfmon = (uid == 0);

    /* Generate summary message */
    if (capability->bpf_syscall_available &&
        capability->kernel_bpf_support &&
        capability->selinux_allows_bpf)
    {

        if (capability->has_cap_bpf || capability->has_cap_sys_admin)
        {
            snprintf(capability->error_message, sizeof(capability->error_message),
                     "System is ready for eBPF operations");
        }
        else
        {
            snprintf(capability->error_message, sizeof(capability->error_message),
                     "eBPF supported but requires elevated privileges");
        }
    }
    else
    {
        char *msg = capability->error_message;
        size_t remaining = sizeof(capability->error_message);

        if (!capability->bpf_syscall_available)
        {
            snprintf(msg, remaining, "BPF syscall not available");
        }
        else if (!capability->kernel_bpf_support)
        {
            snprintf(msg, remaining, "Kernel BPF support not detected");
        }
        else if (!capability->selinux_allows_bpf)
        {
            snprintf(msg, remaining, "SELinux may block BPF operations");
        }
        else
        {
            snprintf(msg, remaining, "Unknown eBPF capability issue");
        }
    }

    return SELINUX_STATUS_SUCCESS;
}

void ebpf_display_capabilities(const ebpf_capability_t *capability)
{
    if (!capability)
    {
        return;
    }

    printf("\n%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("%s                  eBPF Capability Report                    %s\n",
           COLOR_BOLD, COLOR_RESET);
    printf("%s━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━%s\n\n",
           COLOR_BOLD, COLOR_RESET);

    /* Kernel Support */
    printf("%s%-30s:%s ", COLOR_CYAN, "BPF Syscall Available", COLOR_RESET);
    printf("%s%s%s\n",
           capability->bpf_syscall_available ? COLOR_GREEN : COLOR_RED,
           capability->bpf_syscall_available ? "✓ Yes" : "✗ No",
           COLOR_RESET);

    printf("%s%-30s:%s ", COLOR_CYAN, "Kernel BPF Support", COLOR_RESET);
    printf("%s%s%s\n",
           capability->kernel_bpf_support ? COLOR_GREEN : COLOR_RED,
           capability->kernel_bpf_support ? "✓ Yes" : "✗ No",
           COLOR_RESET);

    /* SELinux */
    printf("%s%-30s:%s ", COLOR_CYAN, "SELinux Allows BPF", COLOR_RESET);
    printf("%s%s%s\n",
           capability->selinux_allows_bpf ? COLOR_GREEN : COLOR_YELLOW,
           capability->selinux_allows_bpf ? "✓ Yes" : "⚠ Maybe Blocked",
           COLOR_RESET);

    /* Capabilities */
    printf("\n%sRequired Capabilities:%s\n", COLOR_CYAN, COLOR_RESET);

    printf("  %s%-26s:%s ", COLOR_CYAN, "CAP_BPF", COLOR_RESET);
    printf("%s%s%s\n",
           capability->has_cap_bpf ? COLOR_GREEN : COLOR_YELLOW,
           capability->has_cap_bpf ? "✓ Available" : "✗ Not Available",
           COLOR_RESET);

    printf("  %s%-26s:%s ", COLOR_CYAN, "CAP_PERFMON", COLOR_RESET);
    printf("%s%s%s\n",
           capability->has_cap_perfmon ? COLOR_GREEN : COLOR_YELLOW,
           capability->has_cap_perfmon ? "✓ Available" : "✗ Not Available",
           COLOR_RESET);

    printf("  %s%-26s:%s ", COLOR_CYAN, "CAP_SYS_ADMIN", COLOR_RESET);
    printf("%s%s%s\n",
           capability->has_cap_sys_admin ? COLOR_GREEN : COLOR_YELLOW,
           capability->has_cap_sys_admin ? "✓ Available" : "✗ Not Available",
           COLOR_RESET);

    /* Summary */
    printf("\n%sSummary:%s %s\n", COLOR_BOLD, COLOR_RESET, capability->error_message);
    printf("\n");
}

int selinux_validate_ebpf_environment(void)
{
    int status = SELINUX_STATUS_SUCCESS;

    /* Get SELinux status */
    selinux_status_t selinux_status;
    if (selinux_get_status(&selinux_status) != SELINUX_STATUS_SUCCESS)
    {
        fprintf(stderr, "%s[ERROR] Failed to get SELinux status%s\n",
                COLOR_RED, COLOR_RESET);
        return SELINUX_STATUS_ERROR;
    }

    /* Display SELinux status */
    selinux_display_status(&selinux_status);

    /* Fetch and display policies */
    selinux_fetch_policies();

    /* Check eBPF capabilities */
    ebpf_capability_t ebpf_cap;
    if (ebpf_check_capability(&ebpf_cap) != SELINUX_STATUS_SUCCESS)
    {
        fprintf(stderr, "%s[ERROR] Failed to check eBPF capabilities%s\n",
                COLOR_RED, COLOR_RESET);
        return SELINUX_STATUS_ERROR;
    }

    /* Display eBPF capabilities */
    ebpf_display_capabilities(&ebpf_cap);

    /* Determine overall status */
    if (!ebpf_cap.bpf_syscall_available || !ebpf_cap.kernel_bpf_support)
    {
        status = SELINUX_STATUS_NOT_SUPPORTED;
    }
    else if (!ebpf_cap.selinux_allows_bpf)
    {
        status = SELINUX_STATUS_PERMISSION_DENIED;
    }

    return status;
}
