/*
 * SECONDARY side proxy module for COLO
 *
 * Copyright (c) 2014, 2015 Fujitsu Limited.
 * Copyright (c) 2014, 2015 HUAWEI TECHNOLOGIES CO.,LTD.
 * Copyright (c) 2014, 2015 Intel Corporation.
 *
 * Authors:
 *  Gao feng <gaofeng@cn.fujitsu.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/xt_COLO.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_queue.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include <net/tcp.h>
#include "xt_COLO.h"
#include "nf_conntrack_colo.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Gao feng <gaofeng@cn.fujitsu.com>");
MODULE_DESCRIPTION("Xtables: secondary proxy module for colo.");

static unsigned int
colo_secondary_hook(const struct nf_hook_ops *ops, struct sk_buff *skb,
		    const struct net_device *in, const struct net_device *out,
		    int (*okfn)(struct sk_buff *))
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn_colo *conn;
	struct nf_conn *ct;
	struct ip_ct_tcp *state;
	struct tcphdr *th;
	union nf_conn_colo_tcp *proto;

	ct = nf_ct_get(skb, &ctinfo);

	if ((ct == NULL) || ((conn = nfct_colo(ct)) == NULL))
		return NF_ACCEPT;

	if ((nf_ct_protonum(ct) != IPPROTO_TCP) ||
	    (conn->flags & COLO_CONN_BYPASS))
		return NF_STOP;

	proto = (union nf_conn_colo_tcp *) conn->proto;

	th = colo_get_tcphdr(ops->pf, skb, NULL, NULL);
	if (th == NULL)
		return NF_DROP;

	if (test_bit(IPS_SEQ_ADJUST_BIT, &ct->status)) {
		state = &ct->proto.tcp;

		if (unlikely(state->state == TCP_CONNTRACK_CLOSE &&
			     th->syn && !th->ack &&
			     CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL)) {
			clear_bit(IPS_SEQ_ADJUST_BIT, &ct->status);
			proto->s.sec_isn = 0;
			proto->s.pri_isn = 0;
		}
		goto out;
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_REPLY) {
		if (!th->syn || !th->ack)
			goto out;

		if (conn->flags & COLO_CONN_POSITIVE) {
			proto->s.pri_isn = ntohl(th->ack_seq) - 1;
			pr_dbg("[secondary] get master guest's first syn %u\n", proto->s.pri_isn);
			/* check again, setup seqadj extension in lock,
			 * since checkpoint may occur before this packet */
			spin_lock_bh(&conn->lock);
			if (!(conn->flags & COLO_CONN_BYPASS) && proto->s.sec_isn &&
			     (proto->s.pri_isn != proto->s.sec_isn)) {
				colo_seqadj_init(ct, IP_CT_NEW,
						 proto->s.pri_isn - proto->s.sec_isn);
			}
			spin_unlock_bh(&conn->lock);
		} else {
			/* syn/ack packet sent out by slaver guest */
			proto->s.sec_isn = ntohl(th->seq);
			pr_dbg("[secondary] get slaver guest's first syn %u\n", proto->s.sec_isn);
		}
	} else {
		if (conn->flags & COLO_CONN_POSITIVE) {
			if (!th->syn || th->ack)
				goto out;

			proto->s.sec_isn = ntohl(th->seq);
			pr_dbg("[secondary] get slaver guest's first syn %u\n", proto->s.sec_isn);
		} else {
			if (proto->s.pri_isn || th->syn || th->fin || th->rst)
				goto out;

			proto->s.pri_isn = ntohl(th->ack_seq) - 1;
			pr_dbg("[secondary] get master guest's first syn %u\n", proto->s.pri_isn);

			/* check again, setup seqadj extension in lock */
			spin_lock_bh(&conn->lock);
			if (!(conn->flags & COLO_CONN_BYPASS) && proto->s.sec_isn &&
			     (proto->s.pri_isn != proto->s.sec_isn)) {
				colo_seqadj_init(ct, IP_CT_IS_REPLY,
						 proto->s.pri_isn - proto->s.sec_isn);
			}
			spin_unlock_bh(&conn->lock);
		}
	}

out:
	return NF_STOP;
}

static struct nf_hook_ops colo_secondary_ops[] __read_mostly = {
	{
		.hook		= colo_secondary_hook,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_MANGLE + 1,
	},
	{
		.hook		= colo_secondary_hook,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_MANGLE + 1,
	},
};

static void colo_tcp_chk_finish(struct nf_conn_colo *conn)
{
	struct nf_conn *ct = (struct nf_conn *)conn->nfct;
	union nf_conn_colo_tcp *proto = (union nf_conn_colo_tcp *)conn->proto;

	pr_dbg("call colo_tcp_chk_finish to cleanup conn %p\n", ct);
	clear_bit(IPS_SEQ_ADJUST_BIT, &ct->status);
}

static void colo_sec_do_failover(struct colo_node *node)
{
	node->u.s.failover = true;
}

static void colo_sec_do_checkpoint(struct colo_node *node)
{
	struct nf_conn_colo *conn;

	pr_dbg("master starts checkpoint, slaver do checkpoint\n");

	spin_lock_bh(&node->lock);
next:
	if (!list_empty(&node->list))
		conn = list_first_entry(&node->list, struct nf_conn_colo, conn_list);
	else
		goto out;

	spin_lock_bh(&conn->lock);

	conn->flags |= COLO_CONN_BYPASS;
	list_move_tail(&conn->conn_list, &node->wait_list);

	if (nf_ct_protonum((struct nf_conn *)conn->nfct) == IPPROTO_TCP) {
		colo_tcp_chk_finish(conn);
	}

	spin_unlock_bh(&conn->lock);

	goto next;
out:
	spin_unlock_bh(&node->lock);
}

static int colo_secondary_receive(void *node,
				  struct sk_buff *skb,
				  struct nlmsghdr *nlh)
{
	switch (nlh->nlmsg_type) {
		/* Start failover */
		case COLO_FAILOVER:
			colo_sec_do_failover(node);
			break;
		/* guest stopped, do checkpoint */
		case COLO_CHECKPOINT:
			colo_sec_do_checkpoint(node);
			return 0;
		default:
			break;
	}

	return 0;
}

static void colo_secondary_destroy(void *_node)
{
	struct colo_node *node = (struct colo_node *) _node;
	struct nf_conn_colo *colo_conn, *next;

	RCU_INIT_POINTER(node->func, NULL);
	RCU_INIT_POINTER(node->notify, NULL);
	synchronize_rcu();

	spin_lock_bh(&node->lock);
	list_for_each_entry_safe(colo_conn, next, &node->list, conn_list) {
		list_del_init(&colo_conn->conn_list);
		colo_conn->flags |= COLO_CONN_BYPASS;
	}
	spin_unlock_bh(&node->lock);

	colo_node_unregister(node);
	module_put(THIS_MODULE);
}

static int colo_secondary_tg_check(const struct xt_tgchk_param *par)
{
	struct xt_colo_secondary_info *info = par->targinfo;
	struct colo_secondary *colo;
	struct colo_node *node;

	if (info->index >= COLO_NODES_NUM)
		return -EINVAL;

	node = colo_node_find_get(info->index);
	if (node == NULL) {
		pr_dbg("cannot find colo node whose index is %d\n", info->index);
		return -EINVAL;
	}

	colo = &node->u.s;

	if (node->func)
		goto out;

	__module_get(THIS_MODULE);

	RCU_INIT_POINTER(node->func, colo_secondary_receive);
	RCU_INIT_POINTER(node->notify, colo_secondary_destroy);
	colo->failover = false;

out:
	info->colo = colo;
	return 0;
}

static void colo_secondary_tg_destroy(const struct xt_tgdtor_param *par)
{
	struct xt_colo_secondary_info *info = par->targinfo;
	struct colo_node *node;

	node = container_of(info->colo, struct colo_node, u.s);

	colo_node_unregister(node);
}

static unsigned int
colo_secondary_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_colo_secondary_info *info = par->targinfo;
	struct colo_secondary *colo = info->colo;
	struct nf_conn_colo *conn = NULL;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	struct colo_node *node;

	if (ct == NULL || colo->failover) {
		/* after failover, before migration */
		return XT_CONTINUE;
	}

	node = container_of(colo, struct colo_node, u.s);

	conn = nf_ct_colo_get(skb, node, COLO_CONN_SECONDARY);
	if (conn == NULL || (conn->flags & COLO_CONN_BYPASS))
		return XT_CONTINUE;

	/* Add ct into colo_secondary list */
	spin_lock_bh(&node->lock);
	if (list_empty(&conn->conn_list)) {
		list_add_tail(&conn->conn_list, &node->list);

		if ((nf_ct_protonum(ct) == IPPROTO_TCP) &&
		    (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL)) {
			/* Guest start connection positively */
			conn->flags |= COLO_CONN_POSITIVE;
		}
	}
	spin_unlock_bh(&node->lock);

	return XT_CONTINUE;
}

static struct xt_target colo_secondary_tg_regs[] __read_mostly = {
	{
		.name		= "SECCOLO",
		.family		= NFPROTO_UNSPEC,
		.target		= colo_secondary_tg,
		.checkentry	= colo_secondary_tg_check,
		.destroy	= colo_secondary_tg_destroy,
		.targetsize	= sizeof(struct xt_colo_secondary_info),
		.table		= "mangle",
		.hooks		= (1 << NF_INET_PRE_ROUTING),
		.me		= THIS_MODULE,
	},
};

static int colo_secondary_init(void)
{
	int err;

	pr_dbg("register_hooks\n");
	err = nf_register_hooks(colo_secondary_ops,
				ARRAY_SIZE(colo_secondary_ops));
	if (err < 0)
		goto err;

	pr_dbg("register targets\n");
	err = xt_register_targets(colo_secondary_tg_regs,
				  ARRAY_SIZE(colo_secondary_tg_regs));

	if (err < 0)
		goto err1;

	return 0;
err1:
	nf_unregister_hooks(colo_secondary_ops,
			    ARRAY_SIZE(colo_secondary_ops));
err:
	return err;
}

static void colo_secondary_exit(void)
{
	xt_unregister_targets(colo_secondary_tg_regs,
			      ARRAY_SIZE(colo_secondary_tg_regs));

	nf_unregister_hooks(colo_secondary_ops,
			    ARRAY_SIZE(colo_secondary_ops));
}

module_init(colo_secondary_init);
module_exit(colo_secondary_exit);
