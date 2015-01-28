/*
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

#ifndef _NF_CONNTRACK_COLO_H
#define _NF_CONNTRACK_COLO_H

#include <net/netfilter/nf_conntrack_extend.h>
#include "xt_COLO.h"

union nf_conn_colo_tcp {
	struct {
		u32			mrcv_nxt;
		u32			srcv_nxt;
		bool			sort;
		/* FIXME: get ride of mack, mwin */
		u32			mack;
		u32			sack;
		u32			mwin;
		u32			swin;
		u16			mscale;
		u16			sscale;
		u32			compared_seq;
		u32			master_snd_nxt;
		u32			slaver_snd_nxt;
	} p;

	struct {
		u32			sec_isn;
		u32			pri_isn;
	} s;
};

struct nf_conn_colo {
	struct list_head	conn_list;
	struct list_head	entry_list;
	struct sk_buff_head	slaver_pkt_queue;
	struct nf_conntrack	*nfct;
	spinlock_t		lock;
	spinlock_t		chk_lock;
	u32			flags;
	u32			index;
	char			proto[];
};

/* COLO netlink socket */
extern struct sock *colo_sock;

static inline
struct nf_conn_colo *nfct_colo(const struct nf_conn *ct)
{
	return (struct nf_conn_colo *) nf_ct_ext_find(ct, NF_CT_EXT_COLO);
}

struct nf_conn_colo *
nf_ct_colo_get(struct sk_buff *skb, struct colo_node *node, u32 flag);

struct colo_node *colo_node_find(u32 index);

struct colo_node *colo_node_find_get(u32 index);

int colo_node_register(struct colo_node *colo);

void colo_node_unregister(struct colo_node *colo);
#endif
