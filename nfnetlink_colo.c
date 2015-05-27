 /*
 * This is a module which is used for COLO FT related communication between userspace and
 * modules in kernel via nfetlink.
 *
 *  (C) 2015 by Zhang Hailiang <zhang.zhanghailiang@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/
#include <linux/module.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <net/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/kernel.h>
#include <net/sock.h>
#include "nfnetlink_colo.h"
#include "nf_conntrack_colo.h"

static LIST_HEAD(master_nodes_head); /* Be Array with slave_nodes_head ? */
static LIST_HEAD(slave_nodes_head);

static struct colo_node *colo_find_node(pid_t pid)
{
	struct colo_node *node;

	list_for_each_entry_rcu (node, &master_nodes_head, list) {
		if (node->vm_pid == pid) {
			return rcu_dereference(node);
		}
	}
	list_for_each_entry_rcu (node, &slave_nodes_head, list) {
		if (node->vm_pid == pid) {
			return rcu_dereference(node);
		}
	}

	return NULL;
}

/* Use toghter with colo_node_put*/
struct colo_node *colo_node_get(u32 vm_pid)
{
	struct colo_node *node = NULL;

	rcu_read_lock();
	node = colo_find_node(vm_pid);
	if (node)
		kref_get (&node->refcnt);
	rcu_read_unlock();

	return node;
}

EXPORT_SYMBOL_GPL(colo_node_get);

static void colo_node_release(struct kref *kref)
{
	struct colo_node *node = container_of(kref, struct colo_node, refcnt);

	pr_dbg("%s, destroy node:%d\n", __func__, node->vm_pid);
	list_del_rcu (&node->list);
	synchronize_rcu();
	kfree (node);
	node = NULL;
}

void colo_node_put(struct colo_node *node)
{
	if (node)
		kref_put(&node->refcnt, colo_node_release);
}

EXPORT_SYMBOL_GPL(colo_node_put);

static const struct nla_policy nfnl_colo_policy[NFNL_COLO_MAX + 1] = {
	[NFNL_COLO_MODE]   = { .type = NLA_U8 },
};

static int colo_init_proxy(struct sock *nl, struct sk_buff *skb,
		    const struct nlmsghdr *nlh,
		    const struct nlattr * const cda[])
{
	struct colo_node *node;
	enum colo_mode mode;

	if (!cda[NFNL_COLO_MODE]) {
		return -EINVAL;
	}
	mode = nla_get_u8(cda[NFNL_COLO_MODE]);
	if (mode >= COLO_MODE_MAX) {
		printk(KERN_ERR "colo mode only can be 1 or 2\n");
		return -EINVAL;
	}
	rcu_read_lock();
	node = colo_find_node(nlh->nlmsg_pid);
	if (node) {
		rcu_read_unlock();
		pr_dbg("node %d exist\n", nlh->nlmsg_pid);
		return -EEXIST;
	}
	rcu_read_unlock();

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		return -ENOMEM;

	node->vm_pid = nlh->nlmsg_pid;
	node->mode = mode;
	node->net = sock_net(nl);
	kref_init(&node->refcnt);
	INIT_LIST_HEAD(&node->conn_list);
	INIT_LIST_HEAD(&node->wait_list);
	spin_lock_init(&node->lock);
	node->destroy_notify_cb = NULL;
	node->do_checkpoint_cb = NULL;
	pr_dbg("%s: node %d init\n", __func__, nlh->nlmsg_pid);
	if (mode == COLO_PRIMARY_MODE)
		list_add_rcu(&node->list, &master_nodes_head);
	else
		list_add_rcu(&node->list, &slave_nodes_head);
	return 0;
}

/*
 * guest has stopped now. no network output now.
 */
static int colo_do_checkpoint(struct sock *nl, struct sk_buff *skb,
		    const struct nlmsghdr *nlh,
		    const struct nlattr * const cda[])
{
	struct colo_node *node;
	enum colo_mode mode;

	if(!cda[NFNL_COLO_MODE]) {
		return -EINVAL;
	}

	mode = nla_get_u8(cda[NFNL_COLO_MODE]);
	if (mode >= COLO_MODE_MAX) {
		printk(KERN_ERR "mode only can be 1 or 2\n");
		return -EINVAL;
	}

	node = colo_node_get(nlh->nlmsg_pid);
	if (!node) {
		printk(KERN_ERR "Do checkpoint: node %d not exist\n", nlh->nlmsg_pid);
		return -EEXIST;
	}

	BUG_ON(mode != node->mode);

	if (node->do_checkpoint_cb)
		node->do_checkpoint_cb(node);
	colo_node_put (node);
	return 0;
}

static int colo_do_failover(struct sock *nl, struct sk_buff *skb,
		    const struct nlmsghdr *nlh,
		    const struct nlattr * const cda[])
{
	struct colo_node *node;
	enum colo_mode mode;

	if (!cda[NFNL_COLO_MODE]) {
		return -EINVAL;
	}
	mode = nla_get_u8 (cda[NFNL_COLO_MODE]);
	if (mode >= COLO_MODE_MAX) {
		return -EINVAL;
	}

	node = colo_node_get(nlh->nlmsg_pid);
	if (!node) {
		return -EEXIST;
	}

	if (mode == COLO_SECONDARY_MODE) {
		node->u.s.failover = true;
	} else {
	     colo_node_put(node);
	     /* For PVM, if failover happens, should do some clean work? */
            return -EINVAL;
        }
        colo_node_put(node);
	return 0;
}

static int colo_reset_proxy(struct sock *nl, struct sk_buff *skb,
		    const struct nlmsghdr *nlh,
		    const struct nlattr * const cda[])
{
	struct colo_node *node;
	enum colo_mode mode;

	if (!cda[NFNL_COLO_MODE]) {
		return -EINVAL;
	}
	mode = nla_get_u8 (cda[NFNL_COLO_MODE]);
	if (mode >= COLO_MODE_MAX) {
		return -EINVAL;
	}

	node = colo_node_get (nlh->nlmsg_pid);
	if (!node) {
		printk(KERN_ERR "Node %d not exist\n", nlh->nlmsg_pid);
		return -EEXIST;
	}

	INIT_LIST_HEAD(&node->conn_list);
	node->destroy_notify_cb = NULL;
	colo_node_put(node);

	return 0;
}

static const struct nfnl_callback nfnl_colo_cb[NFCOLO_MSG_MAX] = {
	[NFCOLO_KERNEL_NOTIFY] = { .call   = NULL,
		.policy = NULL,
		.attr_count = 0, },
	[NFCOLO_DO_CHECKPOINT] = { .call   = colo_do_checkpoint,
		.policy = nfnl_colo_policy,
		.attr_count = NFNL_COLO_MAX, },
	[NFCOLO_DO_FAILOVER] = { .call   = colo_do_failover,
		.policy = nfnl_colo_policy,
		.attr_count = NFNL_COLO_MAX, },
	[NFCOLO_PROXY_INIT] = { .call   = colo_init_proxy,
		.policy = nfnl_colo_policy,
		.attr_count = NFNL_COLO_MAX, },
	[NFCOLO_PROXY_RESET] = { .call   = colo_reset_proxy,
		.policy = nfnl_colo_policy,
		.attr_count = NFNL_COLO_MAX,},
};

int colo_send_checkpoint_req(struct colo_primary *colo)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	struct nfcolo_packet_compare nfcm;
	int portid, ret;
	struct colo_node *node = container_of(colo, struct colo_node, u.p);
	struct nfgenmsg *nfmsg;

	colo->checkpoint = true;

	portid = node->vm_pid;
	skb = nfnetlink_alloc_skb(&init_net,
				nlmsg_total_size(sizeof(struct nfgenmsg)) +
				nla_total_size(sizeof(int32_t)), portid, GFP_ATOMIC);
	if (skb == NULL)
		return -ENOMEM;

	nlh = nlmsg_put(skb, portid, 0, NFNL_SUBSYS_COLO << 8 | NFCOLO_KERNEL_NOTIFY,
					sizeof(struct nfgenmsg), 0);
	if (!nlh)
		goto nla_put_failure;

	nfmsg = nlmsg_data(nlh);
	nfmsg->nfgen_family = AF_UNSPEC;
	nfmsg->version = NFNETLINK_V0;
	nfmsg->res_id = 0;

	nfcm.different = 1;
	if (nla_put_s32(skb, NFNL_COLO_COMPARE_RESULT,
					 htonl(nfcm.different))) {
		goto nla_put_failure;
	}
	nlh->nlmsg_len = skb->len; /* Don't forget to update this value */

	ret = nfnetlink_unicast(skb, node->net, portid, MSG_DONTWAIT);
	return ret;

nla_put_failure:
	printk("Error: colo_send_checkpoint_req failed\n");
	skb_tx_error(skb);
	kfree_skb(skb);
	return -1;
}

EXPORT_SYMBOL_GPL(colo_send_checkpoint_req);

static const struct nfnetlink_subsystem nfulnl_subsys = {
	.name		= "colo",
	.subsys_id	= NFNL_SUBSYS_COLO,
	.cb_count	 = NFCOLO_MSG_MAX,
	.cb		= nfnl_colo_cb,
};

static int colonl_close_event(struct notifier_block *nb,
			unsigned long event, void *ptr)
{
	struct netlink_notify *n = ptr;
	struct colo_node *node;

	if (event != NETLINK_URELEASE || !n->portid ||
	    n->protocol != NETLINK_NETFILTER)
		return NOTIFY_DONE;

	rcu_read_lock();
	node = colo_find_node(n->portid); /* Should this be changed to colo_node_get ? */
	if (node == NULL) {
		rcu_read_unlock();
		return NOTIFY_DONE;
	}
	if (node->destroy_notify_cb)
		node->destroy_notify_cb(node);
	rcu_read_unlock();

	colo_node_destroy(node);
	return NOTIFY_DONE;
}

static struct notifier_block colonl_notifier = {
	.notifier_call	= colonl_close_event,
};
static int __init nfnetlink_colo_init(void)
{
	int status = -ENOMEM;

	netlink_register_notifier(&colonl_notifier);
	status = nfnetlink_subsys_register(&nfulnl_subsys);
	if (status < 0) {
		pr_err("log: failed to create netlink socket\n");
		goto cleanup_netlink_notifier;
	}
        return status;

cleanup_netlink_notifier:
	netlink_unregister_notifier(&colonl_notifier);
	return status;
}
static void __exit nfnetlink_colo_fini(void)
{
	nfnetlink_subsys_unregister(&nfulnl_subsys);
	netlink_unregister_notifier(&colonl_notifier);
}

MODULE_DESCRIPTION("netfilter userspace colo communication");
MODULE_AUTHOR("Zhanghailiang <zhang.zhanghailiang@huawei.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_NFNL_SUBSYS(NFNL_SUBSYS_COLO);

module_init(nfnetlink_colo_init);
module_exit(nfnetlink_colo_fini);

/*
* TODO: Add some statistics  info to userspace by proc,
* like what nfnetlink_log and nfnetlink_queue do.
*/
