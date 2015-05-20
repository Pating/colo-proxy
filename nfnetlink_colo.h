#ifndef _UAPI_NFNL_COLO_H_
#define _UAPI_NFNL_COLO_H_
#include "xt_COLO.h"

#define NFNL_SUBSYS_COLO		12

enum nfnl_colo_msg_types {
	NFCOLO_KERNEL_NOTIFY, /* Used by proxy module to notify qemu some info*/

	NFCOLO_DO_CHECKPOINT, /*Used by qemu to notify proxy module to do checkpoint */
	NFCOLO_DO_FAILOVER, /* Used by qemu to notify proxy module to do failer */
	NFCOLO_PROXY_INIT, /* Used by qemu to notify proxy module to do init work */
	NFCOLO_PROXY_RESET,

	NFCOLO_MSG_MAX
};

enum nfnl_colo_common_attributes {
    NFNL_COLO_UNSPEC,
    NFNL_COLO_MODE,
    __NFNL_COLO_MAX
};

#define NFNL_COLO_MAX  (__NFNL_COLO_MAX - 1)

enum colo_mode {
    COLO_UNPROTECTED_MODE = 0,
    COLO_PRIMARY_MODE,
    COLO_SECONDARY_MODE,
    COLO_MODE_MAX
};

struct nfcolo_packet_compare {
    int32_t different;
};

enum nfnl_colo_kernel_notify_attributes {
    NFNL_COLO_KERNEL_NOTIFY_UNSPEC,
    NFNL_COLO_COMPARE_RESULT,
    __NFNL_COLO_KERNEL_NOTIFY_MAX
};

#define NFNL_COLO_KERNEL_NOTIFY_MAX  (__NFNL_COLO_KERNEL_NOTIFY_MAX - 1)

int colo_send_checkpoint_req(struct colo_primary *colo);
struct colo_node *colo_node_get(u32 vm_pid);
void colo_node_put(struct colo_node *node);
static inline void colo_node_destroy(struct colo_node *node) {
    /* Do something else ? */
    colo_node_put(node);
}

#endif
