/*
 * PRIMARY side proxy module for COLO
 *
 * Copyright (c) 2014, 2015 Fujitsu Limited.
 * Copyright (c) 2014, 2015 HUAWEI TECHNOLOGIES CO.,LTD.
 * Copyright (c) 2014, 2015 Intel Corporation.
 *
 * Authors:
 *  Gao feng <gaofeng@cn.fujitsu.com>
 *  Zhang Hailiang <zhang.zhanghailiang@huawei.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/module.h>
#include <linux/list_sort.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter/xt_COLO.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_queue.h>
#include <net/ip.h>
#include <net/arp.h>
#include <net/tcp.h>
#include <linux/icmp.h>
#include <linux/version.h>
#include "xt_COLO.h"
#include "nf_conntrack_colo.h"
#include "nfnetlink_colo.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gao feng <gaofeng@cn.fujitsu.com>");
MODULE_DESCRIPTION("Xtables: primary proxy module for colo.");

DEFINE_PER_CPU(struct nf_conn, slaver_conntrack);

static DECLARE_WAIT_QUEUE_HEAD(kcolo_wait);

struct forward_device {
	struct list_head list;
	struct packet_type ptype;
	char name[256];
	int rfc; /* Should also add a lock to protect this struct */
};

static struct forward_device forward_device_head = {
	.list = LIST_HEAD_INIT(forward_device_head.list),
};
DEFINE_MUTEX(forward_device_lock);

#if 0
#define nf_conntrack_get__(nfct) { printk("%s,%d: before get nfct %p reference %u\n", __func__, __LINE__, nfct, atomic_read(&nfct->use)); \
								nf_conntrack_get(nfct); }
#define nf_conntrack_put__(nfct) { printk("%s,%d: before put nfct %p reference %u\n", __func__, __LINE__, nfct, atomic_read(&nfct->use)); \
								nf_conntrack_put(nfct); }
#else
#define nf_conntrack_get__(nfct) nf_conntrack_get(nfct)
#define nf_conntrack_put__(nfct) nf_conntrack_put(nfct)
#endif

static bool colo_compare_skb(struct sk_buff *skb,
			     struct sk_buff *skb1,
			     u32 dataoff, u32 dataoff1,
			     u32 len)
{
	u32 mpos, spos, moffset, soffset;
	u32 msize, ssize;
	char *mbuff, *sbuff;

	if (len == 0)
		return true;

	mpos = spos = moffset = soffset = 0;
	msize = ssize = len;
	mbuff = sbuff = NULL;

	do {
		if (moffset == 0) {
			colo_get_data(skb, &mbuff, mpos + dataoff, &msize);
			mpos += msize;
		}
		if (soffset == 0) {
			colo_get_data(skb1, &sbuff, spos + dataoff1, &ssize);
			spos += ssize;
		}
		if (mbuff == NULL || sbuff == NULL) {
			pr_dbg("get mbuff %p, sbuff %p, do checkpoint\n", mbuff, sbuff);
			return false;
		}

		if (memcmp(mbuff + moffset, sbuff + soffset,
			   MIN(msize - moffset, ssize - soffset))) {
			int i;
			pr_dbg("compare data inconsist, do checkpoint\n");
			pr_dbg("master: pos %u\n", mpos);
			for (i = 0; i < msize; i++)
				pr_dbg("%c ", *(mbuff + i));
			pr_dbg("\nslaver: pos %u\n", spos);
			for (i = 0; i < ssize; i++)
				pr_dbg("%c ", *(sbuff + i));
			pr_dbg("\n");

			return false;
		}

		if (msize - moffset > ssize - soffset) {
			moffset += ssize - soffset;
			ssize = len - spos;
			soffset = 0;
			continue;
		} else if (ssize - soffset > msize - moffset) {
			soffset += msize - moffset;
			msize = len - mpos;
			moffset = 0;
			continue;
		} else {
			moffset = soffset = 0;
			msize = len - mpos;
			ssize = len - spos;
		}

	} while (mpos != len || spos != len);

	return true;
}

static void 
__colo_compare_common(struct colo_primary *colo,
		      struct nf_conn_colo *conn,
		      bool (*compare)(struct sk_buff *,
				      struct sk_buff *,
				      u32 *, u32, u32, u32, u8 *),
		      bool (*pre_compare)(struct nf_conn_colo *,
					  struct nf_queue_entry *,
					  u32 *, u32))
{
	struct nf_queue_entry *e, *n;
	LIST_HEAD(master_head);
	struct sk_buff_head slaver_head;
	struct sk_buff *skb;
	bool sort = false;
	bool checkpoint = false;
	union nf_conn_colo_tcp *p = NULL;
	u32 max_ack = 0, compared_seq;
	u32 swin = 0; u16 mscale = 1;
	u8 free, times = 0;

	/* Get checkpoint lock */
	spin_lock(&conn->chk_lock);

	skb_queue_head_init(&slaver_head);

	if (nf_ct_protonum((struct nf_conn *)conn->nfct) == IPPROTO_TCP) {
		p = &conn->proto;
	}

	spin_lock_bh(&conn->lock);
	if (list_empty(&conn->entry_list)) {
		spin_unlock_bh(&conn->lock);
		goto out;
	}

	list_splice_init(&conn->entry_list, &master_head);
	if (p) {
		max_ack = p->p.mack;
		compared_seq = p->p.compared_seq;
		mscale = p->p.mscale;
	}
	spin_unlock_bh(&conn->lock);

	spin_lock_bh(&conn->slaver_pkt_queue.lock);
	skb_queue_splice_init(&conn->slaver_pkt_queue, &slaver_head);
	if (p) {
		if (p->p.sack && before(p->p.sack, max_ack))
			max_ack = p->p.sack;
		swin = p->p.swin;
	}
	spin_unlock_bh(&conn->slaver_pkt_queue.lock);

restart:
	skb = skb_peek(&slaver_head);

	list_for_each_entry_safe(e, n, &master_head, list) {
		if (times++ > 64 || need_resched()) {
			/* Do not cost cpu for a long time. */
			pr_dbg("times %d exceed 64 or need_resched, do schedule\n", times);

			spin_lock_bh(&conn->lock);
			list_splice_init(&master_head, &conn->entry_list);
			if (p) {
				p->p.sort = true;
			}
			spin_unlock_bh(&conn->lock);

			spin_lock_bh(&conn->slaver_pkt_queue.lock);
			skb_queue_splice_init(&slaver_head, &conn->slaver_pkt_queue);
			spin_unlock_bh(&conn->slaver_pkt_queue.lock);

			spin_unlock(&conn->chk_lock);

			schedule();

			pr_dbg("kcolo_thread come back!\n");

			spin_lock(&conn->chk_lock);

			spin_lock_bh(&conn->lock);
			if (list_empty(&conn->entry_list)) {
				spin_unlock_bh(&conn->lock);
				goto out;
			}

			list_splice_init(&conn->entry_list, &master_head);
			spin_unlock_bh(&conn->lock);

			spin_lock_bh(&conn->slaver_pkt_queue.lock);
			skb_queue_splice_init(&conn->slaver_pkt_queue, &slaver_head);
			spin_unlock_bh(&conn->slaver_pkt_queue.lock);

			times = 0;
			/* restart compare this connection */
			goto restart;
		}
		/* ugly, entry is freed & handled by pre_compare */
		if (pre_compare && pre_compare(conn, e, &compared_seq, max_ack))
			continue;

next:
		if (skb == NULL) {
			struct nf_conn *ct = (struct nf_conn *) conn->nfct;

			if (test_bit(IPS_DYING_BIT, &ct->status)) {
				/* timeout, it's a long time, there is something wrong
				 * with slaver, we should help him. */
				pr_err("DO checkpoint, reason: conn %p timeout, should do checkpoint\n", ct);
				checkpoint = true;
			}

			break;
		}

		free = 0;
		if (!compare(e->skb, skb, &compared_seq, max_ack, mscale, swin, &free)) {
			/* should do checkpoint */
			checkpoint = true;
			break;
		}

		if (free & COLO_COMPARE_FREE_SLAVER) {
			__skb_unlink(skb, &slaver_head);
			kfree_skb(skb);
			skb = skb_peek(&slaver_head);
		}

		if (free & COLO_COMPARE_FREE_MASTER) {
			list_del_init(&e->list);
			nf_reinject(e, NF_STOP);
		} else if (!(free & COLO_COMPARE_NEXT_MASTER)) {
			goto next;
		} 
	}

	spin_lock_bh(&conn->lock);
	if (!list_empty(&master_head)) {
		__list_splice(&master_head, &conn->entry_list, conn->entry_list.next);
		sort = true;
	}
	if (p) {
		if (before(p->p.compared_seq, compared_seq))
			p->p.compared_seq = compared_seq;
		p->p.sort = sort;
	}
	spin_unlock_bh(&conn->lock);

	spin_lock_bh(&conn->slaver_pkt_queue.lock);
	if (!skb_queue_empty(&slaver_head)) {
		__skb_queue_splice(&slaver_head, (struct sk_buff *) &conn->slaver_pkt_queue,
				   conn->slaver_pkt_queue.next);
		conn->slaver_pkt_queue.qlen += slaver_head.qlen;
	}
	spin_unlock_bh(&conn->slaver_pkt_queue.lock);

out:
	spin_unlock(&conn->chk_lock);

	if (checkpoint)
		colo_send_checkpoint_req(colo);
}

static bool colo_compare_other_skb(struct sk_buff *skb,
				   struct sk_buff *skb1,
				   u32 *compared_seq,
				   u32 a, u32 b, u32 c,
				   u8 *free)
{
	pr_dbg("compare other: get master skb %p, slaver skb %p\n", skb, skb1);

	*free = COLO_COMPARE_FREE_MASTER | COLO_COMPARE_FREE_SLAVER;

	if (skb->len != skb1->len) {
		pr_err("DO checkpoint, reason: master skb length %d, slaver length %d\n",
			skb->len, skb1->len);
		return false;
	}

	return colo_compare_skb(skb, skb1, 0, 0, skb->len);
}

static bool colo_compare_icmp_skb(struct sk_buff *skb,
				  struct sk_buff *skb1,
				  u32 *compared_seq,
				  u32 a, u32 b, u32 c,
				  u8 *free)
{
	struct colo_icmp_cb *cb, *cb1;

	*free = COLO_COMPARE_FREE_SLAVER | COLO_COMPARE_FREE_MASTER;

	cb = COLO_SKB_CB(skb);
	cb1 = COLO_SKB_CB(skb1);

	if ((cb->type == cb1->type) && (cb->code == cb1->code)) {
		if (cb->type == ICMP_REDIRECT) {
			if (cb->gw != cb1->gw)
				return false;
		} else if ((cb->type == ICMP_DEST_UNREACH) && (cb->code == ICMP_FRAG_NEEDED)) {
			if (cb->mtu != cb1->mtu)
				return false;
		}
	} else {
		pr_err("DO checkpoint, reason: master type,code %u:%u, slaver %u:%u\n",
			cb->type, cb->code, cb1->type, cb1->code);
		return false;
	}

	return true;
}

static bool colo_compare_udp_skb(struct sk_buff *skb,
				 struct sk_buff *skb1,
				 u32 *compared_seq,
				 u32 a, u32 b, u32 c, 
				 u8 *free)
{
	struct colo_udp_cb *cb, *cb1;

	pr_dbg("compare udp: get master skb %p, slaver skb %p\n", skb, skb1);

	*free = COLO_COMPARE_FREE_MASTER | COLO_COMPARE_FREE_SLAVER;

	if (skb->len != skb1->len) {
		pr_err("Do checkpoint, reason: master skb length %d, slaver length %d\n",
			skb->len, skb1->len);
		return false;
	}

	cb = COLO_SKB_CB(skb);
	cb1 = COLO_SKB_CB(skb1);

	if (cb->size != cb1->size) {
		pr_err("DO checkpoint, reason: master udp payload %u, slaver payload %u\n",
			cb->size, cb1->size);
		return false;
	}

	return colo_compare_skb(skb, skb1, cb->dataoff, cb1->dataoff, cb->size);
}

static void colo_compare_other(struct colo_primary *colo,
			       struct nf_conn_colo *conn)
{
	return __colo_compare_common(colo, conn,
				     colo_compare_other_skb,
				     NULL);
}

static void colo_compare_icmp(struct colo_primary *colo,
			      struct nf_conn_colo *conn)
{
	return __colo_compare_common(colo, conn,
				     colo_compare_icmp_skb,
				     NULL);
}

static void colo_compare_udp(struct colo_primary *colo,
			     struct nf_conn_colo *conn)
{
	return __colo_compare_common(colo, conn,
				     colo_compare_udp_skb,
				     NULL);
}

/*
 * return true is skb need not to compare.
 * FIXME: compare ooo packet
 */
static bool colo_pre_compare_tcp_skb(struct nf_conn_colo *conn,
				     struct nf_queue_entry *e,
				     u32 *compared_seq,
				     u32 max_ack)
{
	struct sk_buff *skb = e->skb;
	struct colo_tcp_cb *cb = COLO_SKB_CB(skb);
	union nf_conn_colo_tcp *p = &conn->proto;
	u32 win = cb->win << p->p.mscale;

	pr_dbg("master skb seq %u, end %u, ack %u, max ack %u, compared_seq %u, win %u, slaver win %u\n",
		cb->seq, cb->seq_end, cb->ack, max_ack, *compared_seq, win, p->p.swin);

	if (unlikely(cb->syn) && (ACCESS_ONCE(conn->flags) & COLO_CONN_SYN_RECVD)) {
		/* syn must be first in master and slaver. */
		pr_dbg("get slaver's syn, send master's syn out\n");
		*compared_seq = cb->seq_end;

		list_del_init(&e->list);
		nf_reinject(e, NF_STOP);

		return true;
	} else if (unlikely(cb->rst)) {
		return false;
	} else if (!after(cb->seq_end, *compared_seq)) {
		if(after(cb->ack, max_ack)) {
			pr_dbg("%u wait for slaver's ack %u\n",
				cb->ack, max_ack);
			return true;
		}

		if (win > p->p.swin) {
			struct tcphdr *th;
			u16 new_win = p->p.swin >> p->p.mscale;

			if (!new_win) {
				pr_dbg("slaver send zero window packet, help slaver, do checkpoint\n");
				return false;
			}

			if (!skb_make_writable(skb, cb->thoff + sizeof(*th)))
				return true;

			th = (void *) skb->data + cb->thoff;
			inet_proto_csum_replace4(&th->check, skb, th->window, htons(new_win), 0);
			th->window = htons(new_win);
			pr_dbg("change window form %u to %u & set out\n", win, ntohs(th->window));
		}

		pr_dbg("set out already compared data\n");
		list_del_init(&e->list);
		nf_reinject(e, NF_STOP);

		return true;
	}

	return false;
}

static bool colo_compare_tcp_skb(struct sk_buff *skb,
				 struct sk_buff *skb1,
				 u32 *compared_seq,
				 u32 max_ack, u32 mscale,
				 u32 swin, u8 *free)
{
	struct colo_tcp_cb *cb, *cb1;

	cb = COLO_SKB_CB(skb);
	cb1 = COLO_SKB_CB(skb1);
	pr_dbg("cb seq %u, end %u, ack %u, cb1 seq %u, end %u, ack %u, max_ack %u\n",
		cb->seq, cb->seq_end, cb->ack, cb1->seq, cb1->seq_end, cb1->ack, max_ack);

	*free = 0;

	/* both rst packet */
	if (unlikely(cb->rst || cb1->rst)) {
		if ((cb->rst ^ cb1->rst) || (cb->seq_end != cb1->seq_end)) {
			pr_err("DO checkpoint, reason: rst diff cb %d, seq_end %u, cb1 %d, seq_end %u\n",
				cb->rst, cb->seq_end, cb1->rst, cb1->seq_end);
			return false;
		}

		pr_dbg("send out master rst packet\n");
		*free = COLO_COMPARE_FREE_MASTER | COLO_COMPARE_FREE_SLAVER;
		pr_dbg("free slaver rst packet\n");
		return true;
	}

	/* the retrans packet's seq may not be cutted,
	 * so cut it to the slaver seq alignment. */
	if (unlikely(before(cb->seq, *compared_seq) && after(cb->seq_end, *compared_seq))) {
		pr_dbg("maybe retrans, seq %u, seq_end %u, compared %u dataoff %u\n",
			cb->seq, cb->seq_end, *compared_seq, cb->dataoff);
		cb->dataoff += *compared_seq - cb->seq;
		cb->seq = *compared_seq;
		pr_dbg("after seq %u, dataoff %u\n", cb->seq, cb->dataoff);
	}

	/* start must be same */
	if (WARN_ONCE(cb->seq != cb1->seq, "DO checkpoint, reason: master seq %u slaver seq %u",
		      cb->seq, cb1->seq))
		return false;

	if (likely(!(cb1->fin || cb->fin)))
		goto compare;

	if (cb1->fin && cb->fin) {
		if (cb1->seq_end != cb->seq_end) {
			pr_dbg("get differenct fin seq %u %u\n",
				cb->seq_end, cb1->seq_end);
			return false;
		}

		/* pure fin packet */
		pr_dbg("get slaver fin packet, cb1 seq %u,seq_end %u\n",
			cb1->seq, cb1->seq_end);
		pr_dbg("get master fin packet, cb seq %u,seq_end %u\n",
			cb->seq, cb->seq_end);
		if (--cb1->seq_end == cb1->seq) {
			pr_dbg("free slaver pure fin packet\n");
			/* both fin packet, at the same start and same end. */
			BUG_ON(cb->seq_end -1 != cb->seq);

			/* pure fin packet, send out */
			/* let it go, let it go */
			*free = COLO_COMPARE_FREE_SLAVER;
			if (!after(cb->ack, max_ack) && ((cb->win << mscale) <= swin)) {
				*free |= COLO_COMPARE_FREE_MASTER;
				pr_dbg("send out master pure fin packet\n");
			} else {
				/* Slaver hasn't ack the data. do not send out this skb */
				*free |= COLO_COMPARE_NEXT_MASTER;
				pr_dbg("buffer skb, seq %u, seq_end %u, ack %u, mwin %u, swin %u\n",
					cb->seq, cb->seq_end, cb->ack, cb->win << mscale, swin);
			}
			*compared_seq = cb->seq_end;
			return true;
		}
		cb->seq_end -= 1;
	} else if (cb1->fin && !cb->fin) {
		if (!after(cb1->seq_end, cb->seq_end)) {
			pr_err("DO checkpoint: reason: slaver fin packet seq is %u while master packet seq %u\n",
				cb1->seq_end, cb->seq_end);
			return false;
		}
		cb1->seq_end -= 1;
	} else if (!cb1->fin && cb->fin) {
		if (!after(cb->seq_end, cb1->seq_end)) {
			pr_err("DO checkpoint: reason: master fin packet seq is %u while slaver packet seq %u\n",
				cb->seq_end, cb1->seq_end);
			return false;
		}
		cb->seq_end -= 1;
	}

compare:
	/* slaver is fin packet or both fin/non-fin packet */
	if (!after(cb->seq_end, cb1->seq_end)) {
		u32 len = cb->seq_end - cb->seq;
		u32 seq_end = cb->seq_end;

		if (!colo_compare_skb(skb, skb1, cb->dataoff, cb1->dataoff, len)) {
			pr_err("DO checkpoint: reason: payload is not consisted(if)\n");
			return false;
		}

		/* data is consist */
		/* restore fin packet, get ready for next round */
		cb1->seq_end += cb1->fin;
		if (cb1->seq_end == seq_end + cb->fin) {
			/* slaver packet has finished its jod */
			pr_dbg("free slaver skb seq %u, seq_end %u, ack %u\n",
				cb1->seq, cb1->seq_end, cb1->ack);

			*compared_seq = cb1->seq_end;
			*free = COLO_COMPARE_FREE_SLAVER;
		} else {
			/* one part of slaver packet still need to be compared */
			cb1->dataoff += len;
			*compared_seq = cb1->seq = seq_end + cb->fin;
			pr_dbg("update slaver skb seq to %u\n", cb1->seq);
		}

		/* let it go, let it go */
		if (!after(cb->ack, max_ack) && ((cb->win << mscale) <= swin)) {
			pr_dbg("send out master skb, seq %u, seq_end %u, ack %u\n",
				cb->seq, cb->seq_end, cb->ack);
			*free |= COLO_COMPARE_FREE_MASTER;
		} else {
			/* Slaver hasn't ack the data. do not send out this skb */
			*free |= COLO_COMPARE_NEXT_MASTER;
			pr_dbg("buffer skb, seq %u, seq_end %u, ack %u, mwin %u, swin %u\n",
				cb->seq, cb->seq_end, cb->ack, cb->win << mscale, swin);
		}
	} else {
		u32 len = cb1->seq_end - cb1->seq;

		if (!colo_compare_skb(skb, skb1, cb->dataoff, cb1->dataoff, len)) {
			pr_err("DO checkpoint: reason: payload is not consisted(else)\n");
			return false;
		}

		/* master packet is longer than skaver packet, compare the
		 * same part, and move the seq & dataoff */
		cb->dataoff += len;
		*compared_seq = cb->seq = cb1->seq_end;

		/* restore fin packet, get ready for next round */
		cb->seq_end += cb->fin;
		*free |= COLO_COMPARE_FREE_SLAVER;
	}

	return true;
}


static void colo_compare_tcp(struct colo_primary *colo,
			     struct nf_conn_colo *conn)
{
	return __colo_compare_common(colo, conn,
				     colo_compare_tcp_skb,
				     colo_pre_compare_tcp_skb);
}

static int kcolo_thread(void *dummy)
{
	struct colo_primary *colo = dummy;
	struct colo_node *node = container_of(colo, struct colo_node, u.p);
	set_freezable();

	while (!kthread_should_stop()) {
		struct nf_conn_colo *conn = NULL;

		DECLARE_WAITQUEUE(wait, current);

		spin_lock_bh(&node->lock);
		if(!list_empty(&node->conn_list))
			conn = list_first_entry(&node->conn_list, struct nf_conn_colo, conn_list);

		if (!conn || colo->checkpoint) {
			add_wait_queue(&colo->wait, &wait);
			set_current_state(TASK_INTERRUPTIBLE);
			spin_unlock_bh(&node->lock);

			pr_dbg("kcolo_thread, no conn, schedule out, chk %d\n", colo->checkpoint);
			try_to_freeze();
			schedule();
			__set_current_state(TASK_RUNNING);
			remove_wait_queue(&colo->wait, &wait);
			continue;
		}

		pr_dbg("get conn %p\n", conn->nfct);
		list_move_tail(&conn->conn_list, &node->wait_list);

		spin_unlock_bh(&node->lock);

		// get reference, the last nf_reinject may trigger conntrack destruction.
		nf_conntrack_get__(conn->nfct);

		if (nf_ct_protonum((struct nf_conn *)conn->nfct) == IPPROTO_TCP) {
			colo_compare_tcp(colo, conn);
		} else if (nf_ct_protonum((struct nf_conn *)conn->nfct) == IPPROTO_UDP) {
			colo_compare_udp(colo, conn);
		} else if (nf_ct_protonum((struct nf_conn *)conn->nfct) == IPPROTO_ICMP) {
			colo_compare_icmp(colo, conn);
		} else {
			colo_compare_other(colo, conn);
		}
		// release the reference, this conntrack can go now
		nf_conntrack_put__(conn->nfct);
	}

	pr_dbg("kcolo_thread %d exit\n", node->vm_pid);
	return 0;
}

static void colo_setup_checkpoint_by_id(u32 id);

static int colo_enqueue_icmp_packet(struct nf_conn_colo *conn,
				    struct nf_queue_entry *entry)
{
	struct sk_buff *skb = entry->skb;
	struct icmphdr *icmph, _ih;
	struct colo_icmp_cb *cb = COLO_SKB_CB(skb);

	icmph = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_ih), &_ih);
	if (icmph == NULL) {
		return -1;
	}

	cb->type = icmph->type;
	cb->code = icmph->code;

	if ((cb->type == ICMP_ECHO) || (cb->type == ICMP_ECHOREPLY)) {
		cb->seq = ntohs(icmph->un.echo.sequence);
		cb->id = ntohs(icmph->un.echo.id);
		pr_dbg("[master]conn %p, type %u, seq %u, id %d\n",
			conn->nfct, cb->type, cb->seq, cb->id);
	} else if (cb->type == ICMP_REDIRECT) {
		cb->gw = icmph->un.gateway;
	} else if ((cb->type == ICMP_DEST_UNREACH) && (cb->code == ICMP_FRAG_NEEDED)) {
		cb->mtu = icmph->un.frag.mtu;
	}

	list_add_tail(&entry->list, &conn->entry_list);
	return 0;
}

static int colo_tcp_seq_cmp(void *p, struct list_head *a,
			    struct list_head *b)
{
	struct nf_queue_entry *ea = list_entry(a, struct nf_queue_entry, list);
	struct nf_queue_entry *eb = list_entry(b, struct nf_queue_entry, list);
	struct colo_tcp_cb *cba = COLO_SKB_CB(ea->skb);
	struct colo_tcp_cb *cbb = COLO_SKB_CB(eb->skb);

	return after(cba->seq, cbb->seq);
}

static int colo_enqueue_tcp_packet(struct nf_conn_colo *conn,
				   struct nf_queue_entry *entry)
{
	struct sk_buff *skb = entry->skb;
	struct tcphdr *th;
	union nf_conn_colo_tcp *proto = &conn->proto;
	struct colo_tcp_cb *cb, *cb1;
	struct nf_queue_entry *e, *e_next;

	cb = COLO_SKB_CB(skb);

	th = colo_get_tcphdr(nf_ct_l3num((struct nf_conn*) conn->nfct),
			     skb, cb, &proto->p.mscale);

	if (th == NULL)
		return -1;

	pr_dbg("DEBUG: master: conn %p enqueue skb seq %u, seq_end %u, ack %u, LEN: %u\n",
		conn, cb->seq, cb->seq_end, cb->ack, cb->seq_end - cb->seq);

	/* Reopen? */
	if ((proto->p.mrcv_nxt == 0) || (th->syn && cb->seq_end != proto->p.mrcv_nxt)) {
		/* Init */
		bool reopen = !!proto->p.mrcv_nxt;
		proto->p.srcv_nxt = proto->p.mrcv_nxt = cb->seq_end;
		proto->p.sack = proto->p.mack = cb->ack;
		proto->p.compared_seq = cb->seq;
		pr_dbg("master syn %d, seq_end %u, rcv_nxt is %u\n",
			th->syn, cb->seq_end, proto->p.mrcv_nxt);
		if (!reopen && th->syn && (conn->flags & COLO_CONN_SYN_RECVD)) {
			nf_reinject(entry, NF_STOP);
		} else {
			if (reopen && th->syn
				&& (conn->flags & COLO_CONN_SYN_RECVD))
				conn->flags &= ~COLO_CONN_SYN_RECVD;
			list_add_tail(&entry->list, &conn->entry_list);
		}
		return 0;
	}

	if (before(proto->p.mack, cb->ack))
		proto->p.mack = cb->ack;
	pr_dbg("master max ack %u, rcv_nxt %u, window size %u\n",
		proto->p.mack, proto->p.mrcv_nxt, cb->win << proto->p.mscale);

	if(th->rst || th->fin) {
		pr_dbg("master received rst/fin %d/%d\n", th->rst, th->fin);
	}

	if (proto->p.sort) {
		proto->p.sort = false;
		list_sort(NULL, &conn->entry_list, colo_tcp_seq_cmp);
	}

	if (!after(cb->seq_end, proto->p.mrcv_nxt)) {
		struct sk_buff *skb1;
		/* we should add packet to entry_list even it is retransed,
		 * since this packet's ack may be bigger than max(mack, sack) */
		list_for_each_entry_safe(e, e_next, &conn->entry_list, list) {
			skb1 = e->skb;
			cb1 = COLO_SKB_CB(skb1);

			if (!after(cb->seq, cb1->seq)) {
				list_add_tail(&entry->list, &e->list);
				pr_dbg("insert before cb1 seq %u, seq_end %u\n",
					cb1->seq, cb1->seq_end);
				return 0;
			}
		}
		list_add_tail(&entry->list, &conn->entry_list);
	} else if (!after(cb->seq, proto->p.mrcv_nxt)) {
		// at least part of data is new.
		u32 nrcv_nxt;

		cb->dataoff += (proto->p.mrcv_nxt - cb->seq);
		cb->seq = proto->p.mrcv_nxt;
		nrcv_nxt = proto->p.mrcv_nxt = cb->seq_end;

		list_add_tail(&entry->list, &conn->entry_list);
		pr_dbg("new_data:seq_valid %u, seq_valid_end %u, new rcv_nxt %u\n", cb->seq,
			cb->seq_end, proto->p.mrcv_nxt);
	} else {
		// out-of-order packet, drop it now
		return -1;
	}

	return 0;
}

static int colo_enqueue_udp_packet(struct nf_conn_colo *conn,
				   struct nf_queue_entry *entry)
{
	struct sk_buff *skb = entry->skb;

	if (colo_get_udphdr(nf_ct_l3num((struct nf_conn *)conn->nfct),
			     skb, COLO_SKB_CB(skb)) == NULL) {
		return -1;
	}

	list_add_tail(&entry->list, &conn->entry_list);
	return 0;
}

static int colo_enqueue_packet(struct nf_queue_entry *entry, unsigned int ptr)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct nf_conn_colo *conn;
	struct sk_buff *skb = entry->skb;
	struct colo_node *node;
	struct colo_tcp_cb *cb;
	int ret = 0;

	ct = nf_ct_get(skb, &ctinfo);

	conn = nfct_colo(ct);

	if (conn == NULL) {
		pr_dbg("colo_enqueue_packet colo isn't exist\n");
		return -1;
	}

	if (skb_is_gso(skb)) {
		pr_dbg("master: gso again???!!!\n");
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	if (entry->state.hook != NF_INET_PRE_ROUTING) {
#else
	if (entry->hook != NF_INET_PRE_ROUTING) {
#endif
		pr_dbg("packet is not on pre routing chain\n");
		return -1;
	}

	node = colo_node_get(conn->vm_pid);
	if (!node) {
		pr_dbg("%s: Could not find node: %d\n",__func__, conn->vm_pid);
		nf_reinject(entry, NF_STOP);
		return 0;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
	switch (entry->state.pf) {
#else
	switch (entry->pf) {
#endif
	case NFPROTO_IPV4:
		skb->protocol = htons(ETH_P_IP);
		break;
	case NFPROTO_IPV6:
		skb->protocol = htons(ETH_P_IPV6);
		break;
	}

	spin_lock_bh(&conn->lock);

	cb = COLO_SKB_CB(skb);
	BUILD_BUG_ON(sizeof(*cb) + sizeof(struct inet_skb_parm) > 48);
	memset(cb, 0, sizeof(*cb));

	switch (nf_ct_protonum(ct)) {
	case IPPROTO_TCP:
		ret = colo_enqueue_tcp_packet(conn, entry);
		break;
	case IPPROTO_UDP:
		ret = colo_enqueue_udp_packet(conn, entry);
		break;
	case IPPROTO_ICMP:
		ret = colo_enqueue_icmp_packet(conn, entry);
		break;
	default:
		list_add_tail(&entry->list, &conn->entry_list);
		pr_dbg("colo_enqueue_packet add skb into ct %p colo %p queue %p\n",
			ct, conn, &conn->entry_list);
	}

	spin_unlock_bh(&conn->lock);

	if (ret < 0) {
		colo_node_put(node);
		return ret;
	}

	spin_lock_bh(&node->lock);
	list_move_tail(&conn->conn_list, &node->conn_list);
	wake_up_interruptible(&node->u.p.wait);
	spin_unlock_bh(&node->lock);

	colo_node_put(node);

	return 0;
}

static inline struct nf_conn *nf_ct_slaver_get(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	return raw_cpu_ptr(&slaver_conntrack);
#else
	return &__raw_get_cpu_var(slaver_conntrack);
#endif
}

static inline int nf_ct_is_colo_template(const struct nf_conn *ct)
{

	return test_bit(IPS_COLO_TEMPLATE_BIT, &ct->status);
}

static unsigned int
colo_slaver_enqueue_icmp_packet(struct nf_conn_colo *conn,
				struct sk_buff *skb)
{
	struct icmphdr *icmph, _ih;
	struct colo_icmp_cb *cb = COLO_SKB_CB(skb);

	icmph = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_ih), &_ih);
	if (icmph == NULL) {
		return NF_DROP;
	}

	cb->type = icmph->type;
	cb->code = icmph->code;

	if ((cb->type == ICMP_ECHO) || (cb->type == ICMP_ECHOREPLY)) {
		cb->seq = ntohs(icmph->un.echo.sequence);
		cb->id = ntohs(icmph->un.echo.id);
		pr_dbg("[slaver]conn %p, type %u, seq %u, id %d\n", conn->nfct, cb->type, cb->seq, cb->id);
	} else if (cb->type == ICMP_REDIRECT) {
		cb->gw = icmph->un.gateway;
	} else if ((cb->type == ICMP_DEST_UNREACH) && (cb->code == ICMP_FRAG_NEEDED)) {
		cb->mtu = icmph->un.frag.mtu;
	}

	__skb_queue_tail(&conn->slaver_pkt_queue, skb);
	return NF_STOLEN;
}

static unsigned int
colo_slaver_enqueue_tcp_packet(struct nf_conn_colo *conn,
			       struct sk_buff *skb)
{
	struct tcphdr *th;
	union nf_conn_colo_tcp *proto = &conn->proto;
	struct colo_tcp_cb *cb;
	bool stolen = false;
	u32 win;

	cb = COLO_SKB_CB(skb);

	th = colo_get_tcphdr(nf_ct_l3num((struct nf_conn *) conn->nfct),
			     skb, cb, &proto->p.sscale);

	if (th == NULL) {
		pr_dbg("get tcphdr of slaver packet failed\n");
		return NF_DROP;
	}

	pr_dbg("DEBUG: slaver: conn %p enqueue skb seq %u, seq_end %u, ack %u, sack %u, LEN: %u\n",
		conn, cb->seq, cb->seq_end, cb->ack, proto->p.sack, cb->seq_end - cb->seq);

	if (before(proto->p.sack, cb->ack)) {
		proto->p.sack = cb->ack;
		stolen = true;
	}

	pr_dbg("slaver max ack %u, rcv_nxt is %u\n", proto->p.sack, proto->p.srcv_nxt);

	win = cb->win << proto->p.sscale;
	if (th->syn) {
		conn->flags |= COLO_CONN_SYN_RECVD;
		proto->p.swin = win;
		pr_dbg("slaver received syn, window scale %u\n", proto->p.sscale);
		/* need to return NF_STOLEN to start compare thread */
		kfree_skb(skb);
		goto out;
	}

	if (proto->p.swin < win)
		stolen = true;
	proto->p.swin = win;
	pr_dbg("window size %u\n", proto->p.swin);

	if (unlikely(th->rst)) {
		pr_dbg("slaver received rst\n");
		__skb_queue_tail(&conn->slaver_pkt_queue, skb);
		goto out;
	}

	if (!after(cb->seq_end, proto->p.srcv_nxt)) {
		// retrans, don't compare
		if (stolen) {
			/* ack updated, should start compare thread */
			pr_dbg("slaver ack updated or window size updated\n");
			kfree_skb(skb);
			goto out;
		}

		pr_dbg("slaver retrans_data or pure ack, DROP\n");
		return NF_DROP;
	}

	if (!after(cb->seq, proto->p.srcv_nxt)) {
		// at least part of data is new.
		u32 nrcv_nxt;

		cb->dataoff += proto->p.srcv_nxt - cb->seq;
		cb->seq = proto->p.srcv_nxt;
		nrcv_nxt = proto->p.srcv_nxt = cb->seq_end;
		__skb_queue_tail(&conn->slaver_pkt_queue, skb);

		pr_dbg("new_data:seq_valid %u, seq_valid_end %u, new rcv_nxt %u\n", cb->seq,
			cb->seq_end, proto->p.srcv_nxt);

		if (th->fin)
			goto out;
	} else {
		// out-of-order packet, drop it now
		return NF_DROP;
	}
out:
	return NF_STOLEN;
}

static unsigned int
colo_slaver_enqueue_udp_packet(struct nf_conn_colo *conn,
			       struct sk_buff *skb)
{
	if (colo_get_udphdr(nf_ct_l3num((struct nf_conn *)conn->nfct),
			    skb, COLO_SKB_CB(skb)) == NULL) {
		return NF_DROP;
	}

	__skb_queue_tail(&conn->slaver_pkt_queue, skb);
	return NF_STOLEN;
}

static unsigned int
colo_slaver_enqueue_packet(struct nf_conn_colo *conn,
			   struct sk_buff *skb,
			   u_int8_t protonum)
{
	unsigned int ret = NF_DROP;
	struct colo_tcp_cb *cb;

	spin_lock_bh(&conn->slaver_pkt_queue.lock);

	ret = NF_STOLEN;

	cb = COLO_SKB_CB(skb);
	BUILD_BUG_ON(sizeof(*cb) + sizeof(struct inet_skb_parm) > 48);
	memset(cb, 0, sizeof(*cb));

	switch (protonum) {
	case IPPROTO_TCP:
		ret = colo_slaver_enqueue_tcp_packet(conn, skb);
		break;
	case IPPROTO_ICMP:
		ret = colo_slaver_enqueue_icmp_packet(conn, skb);
		break;
	case IPPROTO_UDP:
		ret = colo_slaver_enqueue_udp_packet(conn, skb);
		pr_dbg("[slaver] receiver udp packet\n");
		break;
	default:
		__skb_queue_tail(&conn->slaver_pkt_queue, skb);
		break;
	}

	spin_unlock_bh(&conn->slaver_pkt_queue.lock);
	return ret;
}

static struct nf_conn *
resolve_master_ct(struct sk_buff *skb, unsigned int dataoff,
		  u_int16_t l3num, u_int8_t protonum,
		  struct nf_conntrack_l3proto *l3proto,
		  struct nf_conntrack_l4proto *l4proto)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_tuple_hash *h;

	if (!nf_ct_get_tuple(skb, skb_network_offset(skb),
			     dataoff, l3num, protonum, &tuple, l3proto,
			     l4proto)) {
		pr_dbg("resolve_normal_ct: Can't get tuple\n");
		return NULL;
	}

	/* look for tuple match */
	h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);

	if (h == NULL) {
		pr_dbg("can't find master's ct for slaver packet\n");
		return NULL;
	}

	return nf_ct_tuplehash_to_ctrack(h);
}

static struct nf_conn *
nf_conntrack_slaver_in(u_int8_t pf, unsigned int hooknum,
		       struct sk_buff *skb)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conntrack_l3proto *l3proto;
	struct nf_conntrack_l4proto *l4proto;
	unsigned int dataoff;
	u_int8_t protonum;

	/* rcu_read_lock()ed by nf_hook_slow */
	l3proto = __nf_ct_l3proto_find(pf);
	if (l3proto->get_l4proto(skb, skb_network_offset(skb), &dataoff, &protonum) <= 0) {
		pr_dbg("slaver: l3proto not prepared to track yet or error occurred\n");
		NF_CT_STAT_INC_ATOMIC(&init_net, error);
		NF_CT_STAT_INC_ATOMIC(&init_net, invalid);
		goto out;
	}

	l4proto = __nf_ct_l4proto_find(pf, protonum);

	/* It may be an special packet, error, unclean...
	 * inverse of the return code tells to the netfilter
	 * core what to do with the packet. */
	if (l4proto->error != NULL) {
		if (l4proto->error(&init_net, NULL, skb, dataoff, &ctinfo, pf, hooknum) <= 0) {
			pr_dbg("slaver: l4proto not prepared to track yet or error occurred\n");
			NF_CT_STAT_INC_ATOMIC(&init_net, error);
			NF_CT_STAT_INC_ATOMIC(&init_net, invalid);
			goto out;
		}
	}

	return resolve_master_ct(skb, dataoff, pf, protonum, l3proto, l4proto);
out:
	return NULL;
}

static unsigned int
colo_slaver_queue_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
		     const struct nf_hook_state *unused)
#else
		       const struct net_device *in, const struct net_device *out,
		       int (*okfn)(struct sk_buff *))
#endif
{
	struct nf_conn *ct;
	struct nf_conn_colo *conn;
	struct colo_node *node;
	unsigned int ret = NF_DROP;
	u_int8_t protonum;

	if ((skb->nfct ==  NULL) ||
	    !nf_ct_is_colo_template((struct nf_conn *)skb->nfct))
		return NF_ACCEPT;

	/* after defrage */
	nf_conntrack_put__(skb->nfct);
	skb->nfct = NULL;

	rcu_read_lock();
	ct = nf_conntrack_slaver_in(ops->pf, ops->hooknum, skb);

	if (ct == NULL) {
		pr_dbg("slaver can't find master's conntrack\n");
		goto out_unlock;
	}

	skb->nfct = &ct->ct_general;

	conn = nfct_colo(ct);
	if (conn == NULL || !conn->init) {
		/* this is rare, since conntrack is created when client's first packet coming */
		pr_dbg("no colo conn %p\n", conn);
		goto out_unlock;
	}

	node = colo_node_get(conn->vm_pid);
	if (node == NULL) {
		pr_dbg("Try to find node %d, colo primary node has gone\n", conn->vm_pid);
		goto out;
	}

	protonum = nf_ct_protonum(ct);

	ret = colo_slaver_enqueue_packet(conn, skb, protonum);

	if (ret != NF_STOLEN)
		goto out;

	spin_lock_bh(&node->lock);
	list_move_tail(&conn->conn_list, &node->conn_list);
	wake_up_interruptible(&node->u.p.wait);
	spin_unlock_bh(&node->lock);
out:
	colo_node_put(node);
out_unlock:
	rcu_read_unlock();
	return ret;
}

static unsigned int
colo_slaver_arp_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
		     const struct nf_hook_state *unused)
#else
		     const struct net_device *in, const struct net_device *out,
		     int (*okfn)(struct sk_buff *))
#endif
{
	unsigned int ret = NF_ACCEPT;
	const struct arphdr *arp;

	if ((skb->nfct ==  NULL) ||
	    !nf_ct_is_colo_template((struct nf_conn *)skb->nfct))
		return ret;

	pr_dbg("get slaver's arp packet\n");

	nf_conntrack_put__(skb->nfct);
	skb->nfct = NULL;

	arp = arp_hdr(skb);

	/* I really don't care if arp is consentience, keeping the
	 * tcp/udp connection alive is more important.
	 * trigger checkpoint immediately, skb->mark should be
	 * consistent with node index. */

	if (ntohs(arp->ar_op) == ARPOP_REQUEST)
		colo_setup_checkpoint_by_id(skb->mark);

	return NF_DROP;
}

static struct nf_hook_ops colo_primary_ops[] __read_mostly = {
	{
		.hook		= colo_slaver_queue_hook,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_RAW + 1,
	},
	{
		.hook		= colo_slaver_queue_hook,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_RAW + 1,
	},
	{
		.hook		= colo_slaver_arp_hook,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_ARP,
		.hooknum	= NF_ARP_IN,
		.priority	= NF_IP_PRI_FILTER + 1,
	},
};

static void colo_tcp_do_checkpoint(struct nf_conn_colo *conn)
{
	struct nf_queue_entry *e, *n;
	union nf_conn_colo_tcp *proto = &conn->proto;

	spin_lock_bh(&conn->lock);
	proto->p.compared_seq = proto->p.mrcv_nxt;

	if (!list_empty(&conn->entry_list)) {
		conn->flags |= COLO_CONN_SYN_RECVD;
		list_for_each_entry_safe(e, n, &conn->entry_list, list) {
			list_del_init(&e->list);
			nf_reinject(e, NF_STOP);
		}
	}

	/* Slaver stopped, no packet came from slaver */
	spin_lock_bh(&conn->slaver_pkt_queue.lock);
	__skb_queue_purge(&conn->slaver_pkt_queue);
	proto->p.srcv_nxt = proto->p.mrcv_nxt;
	proto->p.sack = proto->p.mack;
	proto->p.sscale = proto->p.mscale;

	spin_unlock_bh(&conn->slaver_pkt_queue.lock);
	spin_unlock_bh(&conn->lock);
}

static void colo_other_do_checkpoint(struct nf_conn_colo *conn)
{
	struct nf_queue_entry *e, *n;

	spin_lock_bh(&conn->lock);
	list_for_each_entry_safe(e, n, &conn->entry_list, list) {
		list_del_init(&e->list);
		nf_reinject(e, NF_STOP);
	}

	spin_unlock_bh(&conn->lock);
	skb_queue_purge(&conn->slaver_pkt_queue);
}

static int primary_do_checkpoint(struct colo_node *node)
{
	struct colo_primary *colo = &node->u.p;

	pr_dbg("master starts checkpoint, send all skb out\n");
	colo->checkpoint = true;

	spin_lock_bh(&node->lock);
	list_splice_init(&node->wait_list, &node->conn_list);

	while(!list_empty (&node->conn_list)) {
		struct nf_conn_colo *conn = list_first_entry (&node->conn_list,
		                         struct nf_conn_colo,
		                         conn_list);

		//nf_conntrack_get__ (conn->nfct);
		list_move_tail (&conn->conn_list, &node->wait_list);
		spin_unlock_bh (&node->lock);

		if (need_resched()) {
			pr_dbg ("colo do checkpoint need resched\n");
			schedule();
			pr_dbg ("colo do checkpoint come back\n");
		}

		spin_lock (&conn->chk_lock);
		if (nf_ct_protonum ( (struct nf_conn *) conn->nfct) == IPPROTO_TCP) {
			colo_tcp_do_checkpoint (conn);
		} else {
			colo_other_do_checkpoint (conn);
		}
		spin_unlock (&conn->chk_lock);
		//nf_conntrack_put__ (conn->nfct);

		spin_lock_bh (&node->lock);
	}
	spin_unlock_bh (&node->lock);
	colo->checkpoint = false;
	return 0;
}
static void colo_setup_checkpoint_by_id(u32 id) {
	struct colo_node *node;

	node = colo_node_get(id);
	if (node) {
		pr_dbg("mark %d, find colo_primary %p, setup checkpoint\n",
			id, node);
		colo_send_checkpoint_req(&node->u.p);
	}
        colo_node_put(node);
}

static void colo_primary_cleanup_conn(struct nf_conn_colo *conn)
{
	struct nf_queue_entry *e, *n;

	spin_lock_bh(&conn->lock);
	spin_lock(&conn->slaver_pkt_queue.lock);

	list_for_each_entry_safe(e, n, &conn->entry_list, list) {
		list_del_init(&e->list);
		nf_reinject(e, NF_STOP);
	}

	__skb_queue_purge(&conn->slaver_pkt_queue);

	spin_unlock(&conn->slaver_pkt_queue.lock);
	spin_unlock_bh(&conn->lock);
}

static void colo_primary_destroy_node(struct colo_node *node)
{
	struct nf_conn_colo *conn = NULL;
	struct task_struct *task;

	spin_lock_bh(&node->lock);
	node->destroy_notify_cb = NULL;
	task = node->u.p.task;
	if (task)
		node->u.p.task = NULL;
	spin_unlock_bh(&node->lock);

	if (task)
		kthread_stop(task);
next:
	spin_lock_bh(&node->lock);

	list_splice_init(&node->wait_list, &node->conn_list);

	if (!list_empty(&node->conn_list)) {
		conn = list_first_entry(&node->conn_list,
					struct nf_conn_colo,
					conn_list);

		nf_conntrack_get__(conn->nfct);
		list_del_init(&conn->conn_list);
		spin_unlock_bh(&node->lock);
	} else {
		spin_unlock_bh(&node->lock);
		module_put(THIS_MODULE);
		return;
	}

	colo_primary_cleanup_conn(conn);

	nf_conntrack_put__(conn->nfct);

	goto next;
}

static void colo_primary_destroy(struct colo_node *node)
{
	colo_primary_destroy_node(node);
}

static int slaver_nic_rcv(struct sk_buff *skb, struct net_device *dev,
			  struct packet_type *pt, struct net_device *orig_dev)
{
	if (skb->pkt_type == PACKET_OUTGOING)
		goto out;

	skb->pkt_type = PACKET_HOST;

	/* make skb belongs to slaver conn, for defrage */
	skb->nfct = &nf_ct_slaver_get()->ct_general;
	skb->nfctinfo = IP_CT_NEW;
	nf_conntrack_get__(skb->nfct);

out:
	kfree_skb(skb);
	return NET_RX_SUCCESS;
}

static int setup_forward_netdev(const char *dev_name)
{
	struct forward_device *fw_dev = NULL;
	int ret;

	mutex_lock(&forward_device_lock);
	list_for_each_entry(fw_dev, &forward_device_head.list, list) {
		pr_dbg("Got %s from fwdev_list\n", fw_dev->name);
		if (strcmp(fw_dev->name, dev_name)) {
			continue;
		}

		if (fw_dev->rfc == INT_MAX) {
			pr_err("forward device reference overflow\n");
			ret = -EBUSY;
			goto err;
		}

		fw_dev->rfc++;
		pr_dbg("%s have registered as a forward device, rfc %d\n",
			dev_name, fw_dev->rfc);
		mutex_unlock(&forward_device_lock);
		return 0;
	}

	pr_dbg("Register %s as a forward device\n", dev_name);
	fw_dev = kzalloc(sizeof(*fw_dev), GFP_KERNEL);
	if (!fw_dev) {
		pr_err("Can not alloc memory for ptype\n");
		ret = -ENOMEM;
		goto err;
	}

	fw_dev->ptype.dev = dev_get_by_name(&init_net, dev_name);
	if (fw_dev->ptype.dev == NULL) {
		pr_err("Can't find net device %s\n", dev_name);
		ret = -EINVAL;
		goto err;
	}
	fw_dev->ptype.type = cpu_to_be16(ETH_P_ALL);
	fw_dev->ptype.func = slaver_nic_rcv;
	fw_dev->rfc = 1;
	strcpy(fw_dev->name, dev_name);

	rtnl_lock();
	ret = dev_set_promiscuity(fw_dev->ptype.dev, 1);
	rtnl_unlock();
	if (ret < 0) {
		pr_err("dev_set_promiscuity failed\n");
		goto err_promiscuity;
	}

	list_add_tail(&fw_dev->list, &forward_device_head.list);
	pr_dbg("Register proto\n");
	dev_add_pack(&fw_dev->ptype);

	mutex_unlock(&forward_device_lock);
	return 0;

err_promiscuity:
	dev_put(fw_dev->ptype.dev);
err:
	kfree(fw_dev);
	mutex_unlock(&forward_device_lock);
	return ret;
}

static void cleanup_forward_netdev(const char *dev_name)
{
	struct forward_device *fw_dev;

	mutex_lock(&forward_device_lock);
	list_for_each_entry(fw_dev, &forward_device_head.list, list) {
		if (strcmp(fw_dev->name, dev_name)) {
			continue;
		}
		if (fw_dev->rfc-- == 1) {
			rtnl_lock();
			dev_set_promiscuity(fw_dev->ptype.dev, -1);
			rtnl_unlock();
			pr_dbg("remove pack %s\n", fw_dev->name);
			dev_remove_pack(&fw_dev->ptype);
			dev_put(fw_dev->ptype.dev);
			list_del(&fw_dev->list);
			kfree(fw_dev);
			break;
		}
		pr_dbg("%s fw_dev->rfc = %d\n", fw_dev->name, fw_dev->rfc);
	}
	mutex_unlock(&forward_device_lock);
}

static int colo_primary_tg_check(const struct xt_tgchk_param *par)
{
	struct xt_colo_primary_info *info = par->targinfo;
	struct colo_primary *colo;
	struct colo_node *node;
	char *dev_name = info->forward_dev;
	int ret = 0;

	node = colo_node_get(info->index);
	if (node == NULL) {
		pr_err("Can not find colo node whose pid is %d\n", info->index);
		return -EINVAL;
	}

	ret = setup_forward_netdev(dev_name);
	if (ret < 0) {
		goto err;
	}
	colo = &node->u.p;

	if (colo->task) {
		pr_dbg("node %d already been initialized\n", info->index);
		/* already initialized by other rules */
		goto out;
	}

	colo->task = kthread_run(kcolo_thread, colo, "kcolo%u", info->index);
	if (IS_ERR(colo->task)) {
		pr_err("colo_tg: fail to create kcolo thread\n");
		ret = PTR_ERR(colo->task);
		goto err_kthread;
	}

	init_waitqueue_head(&colo->wait);
	colo->checkpoint = false;

	__module_get(THIS_MODULE);
	/* init primary info */

	spin_lock_bh(&node->lock);
	node->destroy_notify_cb = colo_primary_destroy;
	node->do_checkpoint_cb = primary_do_checkpoint;
	spin_unlock_bh(&node->lock);
out:
	info->colo = colo;
	return 0;

err_kthread:
	cleanup_forward_netdev(dev_name);
err:
	colo_node_put(node);
	return ret;
}

static void colo_primary_tg_destroy(const struct xt_tgdtor_param *par)
{
	struct xt_colo_primary_info *info = par->targinfo;
	struct colo_node *node;

	node = container_of(info->colo, struct colo_node, u.p);
	cleanup_forward_netdev(info->forward_dev);
	colo_node_put(node);
}

static unsigned int
colo_primary_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_colo_primary_info *info = par->targinfo;
	struct colo_node *node;

	node = container_of(info->colo, struct colo_node, u.p);

	if (nf_ct_colo_get(skb, node, COLO_CONN_PRIMARY) == NULL) {
		pr_dbg("primary_tg no colo extendition?\n");
		return XT_CONTINUE;
	}

	return NF_QUEUE_NR(0);
}

static struct xt_target colo_primary_tg_regs[] __read_mostly = {
	{
		.name		= "PMYCOLO",
		.family		= NFPROTO_UNSPEC,
		.target		= colo_primary_tg,
		.checkentry	= colo_primary_tg_check,
		.destroy	= colo_primary_tg_destroy,
		.targetsize	= sizeof(struct xt_colo_primary_info),
		.table		= "mangle",
		.hooks		= (1 << NF_INET_PRE_ROUTING),
		.me		= THIS_MODULE,
	},
};

static const struct nf_queue_handler coloqh = {
	.outfn	= &colo_enqueue_packet,
};

static int __init colo_primary_init(void)
{
	int err = 0;
	int cpu;

	pr_dbg("register hooks\n");
	err = nf_register_hooks(colo_primary_ops, ARRAY_SIZE(colo_primary_ops));
	if (err < 0)
		goto err1;

	pr_dbg("register target\n");
	err = xt_register_targets(colo_primary_tg_regs,
				  ARRAY_SIZE(colo_primary_tg_regs));
	if (err < 0)
		goto err2;

	err = -EINVAL;
	for_each_possible_cpu(cpu) {
		struct nf_conn *ct = &per_cpu(slaver_conntrack, cpu);
		struct nf_conntrack_zone *nf_ct_zone;

		write_pnet(&ct->ct_net, &init_net);
		atomic_set(&ct->ct_general.use, 1);
		ct->status = IPS_CONFIRMED | IPS_UNTRACKED | IPS_COLO_TEMPLATE;

		nf_ct_zone = nf_ct_ext_add(ct, NF_CT_EXT_ZONE, GFP_ATOMIC);
		if (nf_ct_zone == NULL) {
			goto err3;
		}
		nf_ct_zone->id = NF_CT_COLO_ZONE;
	}

	nf_register_queue_handler(&coloqh);
	return 0;

err3:
	for_each_possible_cpu(cpu) {
		struct nf_conn *ct = &per_cpu(slaver_conntrack, cpu);

		if (ct->ext) {
			kfree(ct->ext);
			ct->ext = NULL;
		}
	}
	xt_unregister_targets(colo_primary_tg_regs, ARRAY_SIZE(colo_primary_tg_regs));
err2:
	nf_unregister_hooks(colo_primary_ops, ARRAY_SIZE(colo_primary_ops));
err1:
	return err;
}

static void colo_primary_exit(void)
{
	int cpu;
	nf_unregister_queue_handler();
	for_each_possible_cpu(cpu) {
		struct nf_conn *ct = &per_cpu(slaver_conntrack, cpu);

		if (ct->ext) {
			kfree(ct->ext);
			ct->ext = NULL;
		}
	}

	xt_unregister_targets(colo_primary_tg_regs, ARRAY_SIZE(colo_primary_tg_regs));
	nf_unregister_hooks(colo_primary_ops, ARRAY_SIZE(colo_primary_ops));
}

module_init(colo_primary_init);
module_exit(colo_primary_exit);
