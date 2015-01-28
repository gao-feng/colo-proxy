/*
 * netfilter conntrack colo extendition.
 *
 * Copyright (c) 2014, 2015 Fujitsu Limited.
 * Copyright (c) 2014, 2015 Huawei, Inc.
 * Copyright (c) 2014, 2015 Intel, Inc.
 *
 * Authors:
 *  Gao feng <gaofeng@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/module.h>
#include <linux/netfilter/xt_COLO.h>
#include <net/netfilter/nf_queue.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/xt_COLO.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_queue.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include <net/tcp.h>

#include "nf_conntrack_colo.h"
#include "xt_COLO.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gao feng <gaofeng@cn.fujitsu.com>");
MODULE_DESCRIPTION("Xtables: netfilter conntrack colo extendition.");

#define COLO_NODES_NUM	10
static struct colo_node __rcu *colo_nodes[COLO_NODES_NUM];
struct sock *colo_sock;
EXPORT_SYMBOL(colo_sock);

DEFINE_MUTEX(node_mutex);

struct colo_node *colo_node_find(u32 index)
{
	if (WARN_ONCE(index >= COLO_NODES_NUM, "index %d exceed\n", index))
		return NULL;

	return rcu_dereference(colo_nodes[index]);
}
EXPORT_SYMBOL_GPL(colo_node_find);

struct colo_node *colo_node_find_get(u32 index)
{
	struct colo_node *node;

	if (WARN_ONCE(index >= COLO_NODES_NUM, "index %d exceed\n", index))
		return NULL;

	mutex_lock(&node_mutex);
	node = colo_nodes[index];
	if (node)
		node->refcnt++;
	mutex_unlock(&node_mutex);

	return node;
}
EXPORT_SYMBOL_GPL(colo_node_find_get);

int colo_node_register(struct colo_node *colo)
{
	int ret = 0;

	mutex_lock(&node_mutex);
	if (colo_nodes[colo->index]) {
		ret = -EBUSY;
		goto out;
	}

	rcu_assign_pointer(colo_nodes[colo->index], colo);
out:
	mutex_unlock(&node_mutex);
	return ret;
}
EXPORT_SYMBOL_GPL(colo_node_register);

void colo_node_unregister(struct colo_node *node)
{
	int ret = 0;
	mutex_lock(&node_mutex);
	if (--node->refcnt == 0) {
		RCU_INIT_POINTER(colo_nodes[node->index], NULL);
		ret = 1;
	}
	mutex_unlock(&node_mutex);

	if (ret == 1) {
		synchronize_rcu();
		kfree(node);
	}
}
EXPORT_SYMBOL_GPL(colo_node_unregister);

static void nfct_init_colo(struct nf_conn_colo *conn,
			   u32 index, u32 flag)
{
	union nf_conn_colo_tcp *proto = NULL;

	if (nf_ct_protonum((struct nf_conn *)conn->nfct) == IPPROTO_TCP) {
		proto = (union nf_conn_colo_tcp *) conn->proto;

		memset(proto, 0, sizeof(*proto));

		if (flag & COLO_CONN_PRIMARY) {
			u32 rcv_nxt = 0;
			u32 max_ack = 0;


			proto->p.compared_seq = proto->p.mrcv_nxt =
			proto->p.srcv_nxt = rcv_nxt;
			proto->p.mack = proto->p.sack = max_ack;
			proto->p.sort = false;
			proto->p.mscale = proto->p.sscale = 1;
			pr_dbg("nfct_init_colo compared_seq %u, mrnxt %u, srnxt %u, mack %u, sack %u\n",
				proto->p.compared_seq, proto->p.mrcv_nxt,
				proto->p.srcv_nxt, proto->p.mack, proto->p.sack);
		} else {
			proto->s.sec_tsoffset = proto->s.sec_isn =
			proto->s.pri_isn = 0;
		}
	}

	skb_queue_head_init(&conn->slaver_pkt_queue);
	INIT_LIST_HEAD(&conn->entry_list);

	INIT_LIST_HEAD(&conn->conn_list);
	spin_lock_init(&conn->lock);
	spin_lock_init(&conn->chk_lock);
	conn->flags |= flag;
	conn->index = index;
}

static
struct nf_conn_colo *nfct_create_colo(struct nf_conn *ct, u32 index, u32 flag)
{
	struct nf_conn_colo *conn = NULL;
	size_t length = 0;

	if (nf_ct_is_confirmed(ct)) {
		pr_dbg("fuck confirmed!\n");
		//return NULL;
	}

	if (nf_ct_protonum(ct) == IPPROTO_TCP) {
		length = sizeof(union nf_conn_colo_tcp);

		if (flag & COLO_CONN_SECONDARY) {
			/* seq adjust is only meaningful for TCP conn */
			if (!nfct_seqadj_ext_add(ct)) {
				pr_dbg("fuck failed to add SEQADJ extension\n");
			}
		}
	}

	conn = (struct nf_conn_colo *) nf_ct_ext_add_length(ct, NF_CT_EXT_COLO,
							    length, GFP_ATOMIC);
	if (!conn) {
		pr_dbg("fuck! add extend failed\n");
		return NULL;
	}

	conn->nfct = &ct->ct_general;

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
		colo_conn = nfct_create_colo(ct, node->index, flag);
		if (colo_conn == NULL) {
			pr_dbg("fuck! create failed!\n");
			return NULL;
		}

		nfct_init_colo(colo_conn, node->index, flag);
		pr_dbg("colo_tg: create colo_conn %p for conn %p\n",
		       colo_conn, ct);
	}

	return colo_conn;
}
EXPORT_SYMBOL_GPL(nf_ct_colo_get);

static void nf_ct_colo_extend_move(void *new, void *old)
{
	struct nf_conn_colo *new_conn = new;
	struct nf_conn_colo *old_conn = old;
	struct colo_node *node;
	unsigned long flags;

	pr_dbg("nf_ct_colo_extend_move new %p, old %p\n", new, old);

	rcu_read_lock();
	node = colo_node_find(old_conn->index);

	if (WARN_ONCE(node == NULL, "cannot find node whose index %d\n",
		      old_conn->index)) {
		rcu_read_unlock();
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

		old_proto = (union nf_conn_colo_tcp *) old_conn->proto;
		new_proto = (union nf_conn_colo_tcp *) new_conn->proto;

		if (old_conn->flags | COLO_CONN_SECONDARY) {
			new_proto->s.sec_isn = old_proto->s.sec_isn;
			new_proto->s.pri_isn = old_proto->s.pri_isn;
			goto out;
		}
	}
out:
	new_conn->index = old_conn->index;
	new_conn->nfct = old_conn->nfct;

	spin_lock_bh(&node->lock);
	INIT_LIST_HEAD(&new_conn->conn_list);
	if (!list_empty(&old_conn->conn_list))
		list_replace(&old_conn->conn_list, &new_conn->conn_list);
	spin_unlock_bh(&node->lock);
	rcu_read_unlock();
}

static void nf_ct_colo_extend_destroy(struct nf_conn *ct)
{
	struct nf_conn_colo *conn;
	struct colo_node *node;


	conn = nfct_colo(ct);
	if (conn == NULL)
		return;

	rcu_read_lock();
	node = colo_node_find(conn->index);
	if (node == NULL)
		goto out;

	spin_lock_bh(&node->lock);
	list_del_init(&conn->conn_list);
	spin_unlock_bh(&node->lock);

out:
	rcu_read_unlock();
}

static struct nf_ct_ext_type nf_ct_colo_extend __read_mostly = {
	.len		= sizeof(struct nf_conn_colo),
	.move		= nf_ct_colo_extend_move,
	.destroy	= nf_ct_colo_extend_destroy,
	.align		= __alignof__(struct nf_conn_colo),
	.id		= NF_CT_EXT_COLO,
};

static int colo_init_proxy(struct sock *sk, int index)
{
	struct colo_node *node;
	int ret = -ENOMEM;

	rcu_read_lock();
	if (colo_node_find(index)) {
		rcu_read_unlock();
		pr_dbg("node %d exist\n", index);
		return -EEXIST;
	}
	rcu_read_unlock();

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (node == NULL)
		goto out;

	node->index = index;
	node->refcnt = 1;
	INIT_LIST_HEAD(&node->list);
	INIT_LIST_HEAD(&node->wait_list);
	spin_lock_init(&node->lock);
	RCU_INIT_POINTER(node->func, NULL);
	RCU_INIT_POINTER(node->notify, NULL);

	ret = colo_node_register(node);
	if (ret < 0)
		goto err1;
out:
	return ret;
err1:
	kfree(node);
	goto out;
}

static int colo_receive_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int ret = -EINVAL, index;
	struct colo_node *node;
	int (*func)(void *, struct sk_buff *, struct nlmsghdr *);

	index = NETLINK_CB(skb).portid;

	/* Initialize fsnotify for netlink socket. */
	if (nlh->nlmsg_type == COLO_PROXY_INIT)
		return colo_init_proxy(NETLINK_CB(skb).sk, index);

	rcu_read_lock();
	node = colo_node_find(index);

	if (WARN_ONCE(node == NULL, "cannot find node whose index %d\n", index))
		return 0;

	func = rcu_dereference(node->func);
	if (func)
		ret = func(node, skb, nlh);

	rcu_read_unlock();
	return ret;
}

static DEFINE_MUTEX(colo_netlink_mutex);

static void colo_receive(struct sk_buff *skb)
{
	mutex_lock(&colo_netlink_mutex);
	netlink_rcv_skb(skb, &colo_receive_msg);
	mutex_unlock(&colo_netlink_mutex);
}

static int colonl_close_event(struct notifier_block *nb,
			unsigned long event, void *ptr)
{
	struct netlink_notify *n = ptr;
	struct colo_node *node;
	void (*close_notify) (void *);

	if (event != NETLINK_URELEASE || !n->portid)
		return 0;

	node = colo_node_find(n->portid);
	BUG_ON(node == NULL);

	rcu_read_lock();
	close_notify = rcu_dereference(node->notify);
	if (close_notify)
		close_notify(node);
	else
		colo_node_unregister(node);
	rcu_read_unlock();

	return 0;
}

static struct notifier_block colonl_notifier = {
	.notifier_call	= colonl_close_event,
};

static int __init nf_conntrack_colo_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input	= colo_receive,
	};

	colo_sock = netlink_kernel_create(&init_net, NETLINK_COLO, &cfg);
	BUG_ON(colo_sock == NULL);

	netlink_register_notifier(&colonl_notifier);

	return nf_ct_extend_register(&nf_ct_colo_extend);
}

static void __exit nf_conntrack_colo_fini(void)
{
	nf_ct_extend_unregister(&nf_ct_colo_extend);
	netlink_unregister_notifier(&colonl_notifier);
	netlink_kernel_release(colo_sock);
	colo_sock = NULL;
}

module_init(nf_conntrack_colo_init);
module_exit(nf_conntrack_colo_fini);
