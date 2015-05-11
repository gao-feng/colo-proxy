/*
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

#ifndef _XT_COLO_H
#define _XT_COLO_H

#include <net/netfilter/nf_conntrack_seqadj.h>

#ifdef DEBUG
#define pr_dbg(fmt, ...) printk(pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_dbg(fmt, ...) do {} while(0)
#endif

#define MIN(X, Y) ((X) <= (Y) ? (X) : (Y))
#define MAX(X, Y) ((X) >= (Y) ? (X) : (Y))

#define COLO_SLAVER_PACKET_MARK	0x1117
#define NF_CT_COLO_ZONE  0x1987

#define NETLINK_COLO 28

enum colo_netlink_status {
	COLO_QUERY_CHECKPOINT = (NLMSG_MIN_TYPE + 1),
	COLO_CHECKPOINT,
	COLO_FAILOVER,
	COLO_PROXY_INIT,
	COLO_PROXY_RESET,
};

struct nf_conn_colo;

struct colomsg {
	bool	checkpoint;
};

enum colo_conn_flags {
	COLO_CONN_BYPASS	= 0x1,
	COLO_CONN_PRIMARY	= 0x2,
	COLO_CONN_SECONDARY	= 0x4,
	COLO_CONN_SYN_RECVD	= 0x8,
	COLO_CONN_POSITIVE	= 0x10,
};

struct colo_primary {
	struct task_struct	*task;
	wait_queue_head_t	wait;
	bool			checkpoint;
};

struct colo_secondary {
	bool			failover;
};

struct colo_node {
	struct list_head	list;
	struct list_head	wait_list;
	spinlock_t		lock;
	int			(*func)(void *node,
					struct sk_buff *skb,
					struct nlmsghdr *nlh);
	void			(*notify)(void *node);
	u32			index;
	u32			refcnt;
	union {
		struct colo_primary p;
		struct colo_secondary s;
	} u;
};

#define COLO_NODES_NUM	10

/* MUST small than 48 - sizeof (struct inet_skb_parm) */
struct colo_tcp_cb {
	u32			seq;
	u32			seq_end;
	u32			ack;
	u16			dataoff;
	u16			thoff;
	u16			win;
	u16			syn:1,
				fin:1,
				rst:1;
};

struct colo_udp_cb {
	u32			size;
	u16			dataoff;
};

struct colo_icmp_cb {
	u32			gw;
	u16			mtu;
	u16			id;
	u16			seq;
	u8			type;
	u8			code;
};

#define COLO_SKB_CB(__skb)	((void *)((__skb)->cb + sizeof(struct inet_skb_parm)))

#define COLO_COMPARE_FREE_MASTER	0x01
#define COLO_COMPARE_NEXT_MASTER	0x02
#define COLO_COMPARE_FREE_SLAVER	0x04

static inline void colo_get_data(struct sk_buff *skb,
				 char **buff,
				 u32 doff,
				 u32 *size)
{
	u32 start = skb_headlen(skb);
	struct sk_buff *frag_skb;
	int i;
	*buff = NULL;
/*
	pr_dbg("dataoff %u, cb->dataoff %u, doff %u, size %u, skblen %u\n",
		dataoff, cb->dataoff, doff, *size, skb->len);
*/
	if (doff < start) {
		*buff = skb->data + doff;

		if (doff + *size <= start)
			return;

		*size = start - doff;
		return;
	}

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		u32 frag_size = skb_frag_size(frag);
		u32 end = start + frag_size;

		if (doff >= end) {
			start = end;
			continue;
		}

		*buff = (void *) (page_address(frag->page.p) +
				  frag->page_offset + doff - start);

		if (*size > (frag_size - (doff - start)))
			*size = frag_size - doff + start;
		return;
	}

	skb_walk_frags(skb, frag_skb) {
		u32 end = start + frag_skb->len;

		if (doff >= end) {
			start = end;
			continue;
		}

		return colo_get_data(frag_skb, buff, doff - start, size);
	}
}

static unsigned int optlen(const u_int8_t *opt, unsigned int offset)
{
	if (opt[offset] <= TCPOPT_NOP || opt[offset + 1] == 0)
		return 1;
	else
		return opt[offset + 1];
}

static inline void
colo_operate_tcpopt(struct sk_buff *skb, struct tcphdr *th, u16 *scale)
{
	int i, j;
	u32 optl = 0;
	u8 *opt = (u8 *)th;

	for (i = sizeof(*th); i < th->doff * 4; i += optl) {
		u_int16_t n, o;

		optl = optlen(opt, i);

		if (i + optl > th->doff * 4)
			break;

		if (unlikely(th->syn && scale && opt[i] == TCPOPT_WINDOW &&
			     optl == TCPOLEN_WINDOW)) {
			*scale = *(opt + i + 2);
			pr_dbg("master get window sacle %u\n", *scale);
			continue;
		}

		if (opt[i] != TCPOPT_SACK)
			continue;

		for (j = 0; j < optl; j++) {
			o = opt[i + j];
			n = TCPOPT_NOP;

			if ((i + j) % 2 == 0) {
				o <<= 8;
				n <<= 8;
			}

			inet_proto_csum_replace2(&th->check, skb, htons(o), htons(n), 0);
		}
		memset(opt + i, TCPOPT_NOP, optl);
	}
}

static inline
struct tcphdr *colo_get_tcphdr(u_int8_t pf, struct sk_buff *skb,
			       struct colo_tcp_cb *cb, u16 *scale)
{
	struct tcphdr _tcph, *th;
	u_int8_t protonum;
	unsigned int nhoff = skb_network_offset(skb);
	struct nf_conntrack_l3proto *l3proto;
	u32 dataoff;

	l3proto = __nf_ct_l3proto_find(pf);
	if(!l3proto->get_l4proto(skb, nhoff, &dataoff, &protonum)) {
		pr_dbg("fuck get iphdr failed\n");
		return NULL;
	}

	if (protonum != IPPROTO_TCP) {
		pr_dbg("is not tcp packet\n");
		return NULL;
	}

	th = skb_header_pointer(skb, dataoff, sizeof(_tcph), &_tcph);
	if (th == NULL) {
		pr_dbg("fuck get tcphdr failed\n");
		return NULL;
	}

	if (!cb)
		goto out;

	/* Primary skbuff */
	if ((th->doff * 4) == sizeof(*th))
		goto set_cb;

	/* strip sack options & get scale value */
	if (!skb_make_writable(skb, dataoff + th->doff * 4))
		return NULL;

	/* BUG_ON(!scale) */
	th = (struct tcphdr *)(skb->data + dataoff);
	colo_operate_tcpopt(skb, th, scale);

set_cb:
	cb->thoff = dataoff;
	cb->dataoff = dataoff + (th->doff << 2);
	cb->seq = ntohl(th->seq);
	cb->seq_end = cb->seq + skb->len - (dataoff - nhoff) - (th->doff << 2)
		+ th->fin + th->syn;
	cb->ack = ntohl(th->ack_seq);
	cb->win = ntohs(th->window);
	cb->syn = th->syn;
	cb->fin = th->fin;
	cb->rst = th->rst;
out:
	return th;
}

static inline struct udphdr *colo_get_udphdr(u_int8_t pf, struct sk_buff *skb,
					     struct colo_udp_cb *cb)
{
	struct udphdr _udph, *uh;
	u_int8_t protonum;
	unsigned int nhoff = skb_network_offset(skb);
	struct nf_conntrack_l3proto *l3proto;
	u32 dataoff;
	u32 udplen;

	l3proto = __nf_ct_l3proto_find(pf);
	if(!l3proto->get_l4proto(skb, nhoff, &dataoff, &protonum)) {
		pr_dbg("fuck get iphdr failed\n");
		return NULL;
	}

	if (protonum != IPPROTO_UDP) {
		pr_dbg("is not udp packet\n");
		return NULL;
	}

	uh = skb_header_pointer(skb, dataoff, sizeof(_udph), &_udph);
	if (uh == NULL) {
		pr_dbg("fuck get udphdr failed\n");
		return NULL;
	}

	udplen = ntohs(uh->len);
	if (udplen < sizeof(_udph)) {
		pr_dbg("fuck udplen %u, udphdr len %lu\n", udplen, sizeof(_udph));
		return NULL;
	}

	if (skb->len != (dataoff + udplen)) {
		pr_dbg("fuck skblen %u, network len %u, udp len %u\n", skb->len, dataoff, udplen);
		return NULL;
	}

	if (!cb)
		goto out;

	cb->dataoff = dataoff + sizeof(_udph);
	cb->size = udplen - sizeof(_udph);
out:
	return uh;
}

static inline
void colo_seqadj_init(struct nf_conn *ct,
		      enum ip_conntrack_info ctinfo,
		      s32 off)
{
	nf_ct_seqadj_init(ct, ctinfo, off);
}
#endif
