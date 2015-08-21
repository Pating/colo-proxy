/*
 * netfilter conntrack colo extendition.
 *
 * Copyright (c) 2014, 2015 Fujitsu Limited.
 * Copyright (c) 2014, 2015 HUAWEI TECHNOLOGIES CO.,LTD.
 * Copyright (c) 2014, 2015 Intel Corporation.
 *
 * Authors:
 *  Gao feng <gaofeng@cn.fujitsu.com>
 *  Zhanghailiang <zhang.zhanghailiang@huawei.com>
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/module.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/tcp.h>

#include "nf_conntrack_colo.h"
#include "nfnetlink_colo.h"
#include "xt_COLO.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gao feng <gaofeng@cn.fujitsu.com>");
MODULE_DESCRIPTION("Xtables: netfilter conntrack colo extendition.");

static void nfct_init_colo(struct nf_conn_colo *conn,
			   u32 vm_pid, u32 flag)
{
	union nf_conn_colo_tcp *proto = NULL;

	if (nf_ct_protonum((struct nf_conn *)conn->nfct) == IPPROTO_TCP) {
		proto = &conn->proto;

		memset(proto, 0, sizeof(*proto));

		if (flag & COLO_CONN_PRIMARY) {
			u32 rcv_nxt = 0;
			u32 max_ack = 0;

			proto->p.compared_seq = proto->p.mrcv_nxt =
			proto->p.srcv_nxt = rcv_nxt;
			proto->p.mack = proto->p.sack = max_ack;
			proto->p.sort = false;
			proto->p.mscale = proto->p.sscale = 1;
			pr_dbg("conn %p nfct_init_colo compared_seq %u, mrnxt %u, srnxt %u, mack %u, sack %u\n",
				conn, proto->p.compared_seq, proto->p.mrcv_nxt,
				proto->p.srcv_nxt, proto->p.mack, proto->p.sack);
		} else {
			proto->s.sec_isn = proto->s.pri_isn = 0;
		}
	}

	skb_queue_head_init(&conn->slaver_pkt_queue);
	INIT_LIST_HEAD(&conn->entry_list);

	INIT_LIST_HEAD(&conn->conn_list);
	spin_lock_init(&conn->lock);
	spin_lock_init(&conn->chk_lock);
	conn->flags |= flag;
	conn->vm_pid = vm_pid;
	conn->init = true;
	smp_wmb();

}

static
struct nf_conn_colo *nfct_create_colo(struct nf_conn *ct, u32 vm_pid, u32 flag)
{
	struct nf_ct_ext_colo *colo = NULL;
	struct nf_conn_colo *conn = NULL;

	if (nf_ct_is_confirmed(ct)) {
		pr_dbg("conntrack %p is confirmed!\n", ct);
		//return NULL;
	}

	if (nf_ct_protonum(ct) == IPPROTO_TCP) {
		if (flag & COLO_CONN_SECONDARY) {
			/* seq adjust is only meaningful for TCP conn */
			if (!nfct_seqadj_ext_add(ct)) {
				pr_err("failed to add SEQADJ extension\n");
				return NULL;
			}
		}
	}

	colo = (struct nf_ct_ext_colo *) nf_ct_ext_add(ct, NF_CT_EXT_COLO,
							    GFP_ATOMIC);
	if (!colo) {
		pr_err("add colo extend failed\n");
		return NULL;
	}

	conn = kzalloc(sizeof(*conn), GFP_ATOMIC);
	if (!conn) {
		pr_err("can not malloc conn\n");
		return NULL;
	}
	conn->nfct = &ct->ct_general;
	conn->init = false;
	colo->conn = conn;

	return conn;
}

struct nf_conn_colo *
nf_ct_colo_get(struct sk_buff *skb, struct colo_node *node, u32 flag)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct nf_conn_colo *colo_conn;

	ct = nf_ct_get(skb, &ctinfo);

	if (ct == NULL || ct == nf_ct_untracked_get()) {
		return NULL;
	}

	colo_conn = nfct_colo(ct);
	if (colo_conn == NULL) {
		colo_conn = nfct_create_colo(ct, node->vm_pid, flag);
		if (colo_conn == NULL) {
			pr_err("create colo conn failed!\n");
			return NULL;
		}

		nfct_init_colo(colo_conn, node->vm_pid, flag);
		pr_dbg("colo_tg: create conn %p for contrack %p node:%d,\n",
		       colo_conn, ct, node->vm_pid);
	}

	return colo_conn;
}
EXPORT_SYMBOL_GPL(nf_ct_colo_get);

static void nf_ct_colo_extend_move(void *new, void *old)
{
	struct nf_ct_ext_colo *new_colo = new, *old_colo = old;
	struct nf_conn_colo *new_conn = kzalloc(sizeof(*new_conn), GFP_ATOMIC);
	struct nf_conn_colo *old_conn = old_colo->conn;
	struct colo_node *node;
	unsigned long flags;

	pr_dbg("nf_ct_colo_extend_move new %p, old %p\n", new, old);
	new_colo->conn = new_conn;
	if (!new_conn) {
		pr_err("can not malloc new conn\n");
		BUG_ON(1);
		return;
	}
	node = colo_node_get(old_conn->vm_pid);

	if (WARN_ONCE(node == NULL, "Can not find node whose index %d!\n",
		old_conn->vm_pid)) {
		return;
	}

	spin_lock_bh(&old_conn->lock);
	INIT_LIST_HEAD(&new_conn->entry_list);
	if (!list_empty(&old_conn->entry_list))
		list_splice(&old_conn->entry_list, &new_conn->entry_list);
	spin_unlock_bh(&old_conn->lock);

	spin_lock_irqsave(&old_conn->slaver_pkt_queue.lock, flags);
	skb_queue_head_init(&new_conn->slaver_pkt_queue);
	skb_queue_splice_init(&old_conn->slaver_pkt_queue, &new_conn->slaver_pkt_queue);
	spin_unlock_irqrestore(&old_conn->slaver_pkt_queue.lock, flags);

	spin_lock_init(&new_conn->lock);
	spin_lock_init(&new_conn->chk_lock);

	if (nf_ct_protonum((struct nf_conn *)old_conn->nfct) == IPPROTO_TCP) {
		union nf_conn_colo_tcp *old_proto, *new_proto;

		old_proto = &old_conn->proto;
		new_proto = &new_conn->proto;
		memcpy(new_proto, old_proto, sizeof(*old_proto));
	}

#if 0
		if (old_conn->flags | COLO_CONN_SECONDARY) {
			new_proto->s.sec_isn = old_proto->s.sec_isn;
			new_proto->s.pri_isn = old_proto->s.pri_isn;
			goto out;
		}
	}
out:
#endif
	new_conn->vm_pid = old_conn->vm_pid;
	new_conn->nfct = old_conn->nfct;

	spin_lock_bh(&node->lock);
	INIT_LIST_HEAD(&new_conn->conn_list);
	if (!list_empty(&old_conn->conn_list))
		list_replace(&old_conn->conn_list, &new_conn->conn_list);
	spin_unlock_bh(&node->lock);
	kfree(old_conn);
	old_colo->conn = NULL;
	colo_node_put(node);
}

static void nf_ct_colo_extend_destroy(struct nf_conn *ct)
{
	struct nf_ct_ext_colo *colo;
	struct nf_conn_colo *conn;
	struct colo_node *node;

	conn = nfct_colo(ct);
	if (conn == NULL)
		return;
	conn->init = false;
	smp_wmb();

	node = colo_node_get(conn->vm_pid);
	if (node == NULL)
		goto out;

	spin_lock_bh(&node->lock);
	list_del_init(&conn->conn_list);
	spin_unlock_bh(&node->lock);
	kfree(conn);
	colo = __nfct_colo(ct);
	colo->conn = NULL;
out:
	colo_node_put(node);
}

static struct nf_ct_ext_type nf_ct_colo_extend __read_mostly = {
	.len		= sizeof(struct nf_ct_ext_colo),
	.move		= nf_ct_colo_extend_move,
	.destroy	= nf_ct_colo_extend_destroy,
	.align		= __alignof__(struct nf_ct_ext_colo),
	.id		= NF_CT_EXT_COLO,
};

static int __init nf_conntrack_colo_init(void)
{
	
	request_module("nf_conntrack_ipv4");
	request_module("nf_conntrack_ipv6");
	return nf_ct_extend_register(&nf_ct_colo_extend);
}

static void __exit nf_conntrack_colo_fini(void)
{
	nf_ct_extend_unregister(&nf_ct_colo_extend);
}

module_init(nf_conntrack_colo_init);
module_exit(nf_conntrack_colo_fini);
