#ifndef SELINUX_VALIDATOR_H
#define SELINUX_VALIDATOR_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* Status codes for operations */
    typedef enum
    {
        SELINUX_STATUS_SUCCESS = 0,
        SELINUX_STATUS_ERROR = -1,
        SELINUX_STATUS_NOT_ENABLED = -2,
        SELINUX_STATUS_PERMISSION_DENIED = -3,
        SELINUX_STATUS_NOT_SUPPORTED = -4
    } selinux_status_code_t;

    /* SELinux enforcement modes */
    typedef enum
    {
        SELINUX_MODE_DISABLED = 0,
        SELINUX_MODE_PERMISSIVE = 1,
        SELINUX_MODE_ENFORCING = 2,
        SELINUX_MODE_UNKNOWN = -1
    } selinux_mode_t;

    /* Structure to hold SELinux status information */
    typedef struct
    {
        bool enabled;
        selinux_mode_t mode;
        char policy_type[256];
        char current_context[512];
        int mls_enabled;
    } selinux_status_t;

    /* Structure to hold eBPF capability information */
    typedef struct
    {
        bool bpf_syscall_available;
        bool kernel_bpf_support;
        bool selinux_allows_bpf;
        bool has_cap_bpf;
        bool has_cap_perfmon;
        bool has_cap_sys_admin;
        char error_message[512];
    } ebpf_capability_t;

    /* Structure for policy query results */
    typedef struct
    {
        char **rules;
        int rule_count;
    } policy_query_result_t;

    /* ============================================
 * Initialization and Cleanup
 * ============================================ */

    /**
 * Initialize the SELinux validator
 * Returns: SELINUX_STATUS_SUCCESS on success, error code otherwise
 */
    int selinux_validator_init(void);

    /**
 * Cleanup resources used by the validator
 */
    void selinux_validator_cleanup(void);

    /* ============================================
 * SELinux Status Functions
 * ============================================ */

    /**
 * Check if SELinux is enabled on the system
 * Returns: true if enabled, false otherwise
 */
    bool selinux_check_enabled(void);

    /**
 * Get the current SELinux enforcement mode
 * Returns: selinux_mode_t enum value
 */
    selinux_mode_t selinux_get_mode(void);

    /**
 * Get comprehensive SELinux status
 * Parameters:
 *   status: Pointer to selinux_status_t structure to fill
 * Returns: SELINUX_STATUS_SUCCESS on success, error code otherwise
 */
    int selinux_get_status(selinux_status_t *status);

    /**
 * Display SELinux status in human-readable format
 * Parameters:
 *   status: Pointer to selinux_status_t structure
 */
    void selinux_display_status(const selinux_status_t *status);

    /**
 * Set SELinux enforcement mode (requires root)
 * Parameters:
 *   mode: Target mode (SELINUX_MODE_ENFORCING or SELINUX_MODE_PERMISSIVE)
 * Returns: SELINUX_STATUS_SUCCESS on success, error code otherwise
 */
    int selinux_set_mode(selinux_mode_t mode);

    /**
 * Get security context of the current process
 * Parameters:
 *   context: Buffer to store context string
 *   context_len: Size of context buffer
 * Returns: SELINUX_STATUS_SUCCESS on success, error code otherwise
 */
    int selinux_get_context(char *context, size_t context_len);

    /* ============================================
 * Policy Management Functions
 * ============================================ */

    /**
 * Display current SELinux policies
 * Returns: SELINUX_STATUS_SUCCESS on success, error code otherwise
 */
    int selinux_display_policies(void);

    /**
 * Check for BPF-related policies
 * Returns: true if BPF policies exist, false otherwise
 */
    bool selinux_check_bpf_policy(void);

    /**
 * Query specific policy rules
 * Parameters:
 *   source_type: Source type (e.g., "unconfined_t")
 *   target_type: Target type (e.g., "self")
 *   class_name: Object class (e.g., "bpf")
 *   result: Pointer to store query results
 * Returns: SELINUX_STATUS_SUCCESS on success, error code otherwise
 */
    int selinux_query_policy(const char *source_type, const char *target_type,
                             const char *class_name, policy_query_result_t *result);

    /**
 * Free policy query results
 * Parameters:
 *   result: Pointer to policy_query_result_t to free
 */
    void selinux_free_policy_result(policy_query_result_t *result);

    /**
 * Fetch and display all policy information
 * Returns: SELINUX_STATUS_SUCCESS on success, error code otherwise
 */
    int selinux_fetch_policies(void);

    /* ============================================
 * eBPF Capability Functions
 * ============================================ */

    /**
 * Check comprehensive eBPF capabilities
 * Parameters:
 *   capability: Pointer to ebpf_capability_t structure to fill
 * Returns: SELINUX_STATUS_SUCCESS on success, error code otherwise
 */
    int ebpf_check_capability(ebpf_capability_t *capability);

    /**
 * Check if SELinux allows BPF operations for current context
 * Returns: true if allowed, false otherwise
 */
    bool ebpf_check_selinux_permissions(void);

    /**
 * Validate that the BPF syscall is available
 * Returns: true if available, false otherwise
 */
    bool ebpf_validate_bpf_syscall(void);

    /**
 * Check kernel BPF configuration
 * Returns: true if kernel supports BPF, false otherwise
 */
    bool ebpf_check_kernel_config(void);

    /**
 * Display comprehensive eBPF capability report
 * Parameters:
 *   capability: Pointer to ebpf_capability_t structure
 */
    void ebpf_display_capabilities(const ebpf_capability_t *capability);

    /**
 * Run complete validation: SELinux status + eBPF capabilities
 * Returns: SELINUX_STATUS_SUCCESS if system is ready for eBPF, error code otherwise
 */
    int selinux_validate_ebpf_environment(void);

#ifdef __cplusplus
}
#endif

#endif /* SELINUX_VALIDATOR_H */
