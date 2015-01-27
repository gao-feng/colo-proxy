PROXY is a kernel netfilter module, colo use it to compare the packets from master and slaver guest.

there are three modules in colo-proxy
nf_conntrack_colo:
this module creates colo netlink socket through which qemu communicates with proxy,
and register the nf_ct_colo_extend, this extension is used to store packets and
connection related informations.

xt_PMYCOLO:
this module does the queue of packets from master and slaver guest.
for master, the queue is implemented through nfqueue & xt_PMYCOLO target.
for slaver, the queue is implemented through pkttype & netfilter hook.
and this module also does the compare of packets. it use a kernel thread to
do this job, it is called kcolo[node_index].
this module requires one parameter "sec_dev", the sec_dev is the packet forwarding
device, the slaver packet will arrive master host through this device. and the packet
reply to master guest will be copied and forward to slaver guest through this device too.


xt_SECCOLO:
this module just does one job: adjust the tcp seq/ack of packet which sent out by
slaver guest, since the Initailize Sequence Number is random, the isn of master and
slaver is different, we should adjust slaver's isn to make sure it is consistent with
master.
