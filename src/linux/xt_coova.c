/* -*- mode: c; c-basic-offset: 8; -*-
 *
 * Copyright (c) 2010-2012 David Bird (Coova Technologies)
 *
 * Inspired by the "recent" module which carried these notices:
 *
 * Copyright (c) 2006 Patrick McHardy <kaber@trash.net>
 * Copyright © CC Computer Consultants GmbH, 2007 - 2008
 *
 * Author: Stephen Frost <sfrost@snowman.net>
 * Copyright 2002-2003, Stephen Frost, 2.5.x port by laforge@netfilter.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/list.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <linux/bitops.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/version.h>
#include <net/net_namespace.h>

#include <linux/netfilter/x_tables.h>
#include "xt_coova.h"

MODULE_AUTHOR("Guojiang Li <guojiang@591wifi.com>");
MODULE_DESCRIPTION("Xtables: \"coova\" module for use with WiCloudChilli");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_coova");
MODULE_ALIAS("ip6t_coova");

#define MAX_WEBSITE_LEN 2048

static unsigned int ip_list_tot = 65536;
static unsigned int ip_pkt_list_tot = 20;
//static unsigned int ip_list_tot = 5;
//static unsigned int ip_pkt_list_tot = 20;
static unsigned int ip_list_hash_size = 0;
static unsigned int ip_list_perms = 0644;
static unsigned int ip_list_uid = 0;
static unsigned int ip_list_gid = 0;
static unsigned int uamserverlen = 0;
static unsigned int uamhostlen = 0;
static char uamserver[1024];
static char uamhost[16];
static char nasid[32];
static char nasmac[32];
static unsigned int cna = 0;
static unsigned int ana = 0;
module_param(ip_list_tot, uint, 0400);
module_param(ip_pkt_list_tot, uint, 0400);
module_param(ip_list_hash_size, uint, 0400);
module_param(ip_list_perms, uint, 0400);
module_param(ip_list_uid, uint, 0400);
module_param(ip_list_gid, uint, 0400);
MODULE_PARM_DESC(ip_list_tot, "number of IPs to remember per list");
MODULE_PARM_DESC(ip_pkt_list_tot, "number of packets per IP to remember (max. 255)");
MODULE_PARM_DESC(ip_list_hash_size, "size of hash table used to look up IPs");
MODULE_PARM_DESC(ip_list_perms, "permissions on /proc/net/coova/* files");
MODULE_PARM_DESC(ip_list_uid,"owner of /proc/net/coova/* files");
MODULE_PARM_DESC(ip_list_gid,"owning group of /proc/net/coova/* files");

struct allows_entry {
        struct list_head        list;
        int32_t                 addr;
        int32_t                 mask;
        u_int8_t                status;
};

struct coova_entry {
	struct list_head	list;
	struct list_head	lru_list;
	union nf_inet_addr	addr;
	unsigned char           hwaddr[ETH_ALEN];
	u_int16_t		family;
	u_int8_t		index;
	unsigned long		firstTime;

	u_int8_t                state;
	u_int64_t		bytes_in;
	u_int64_t		bytes_out;
	u_int64_t		pkts_in;
	u_int64_t		pkts_out;
	u_int8_t                is_http_10;
	unsigned long		cna_time;
};

struct coova_table {
	struct list_head	list;
	char			name[XT_COOVA_NAME_LEN];
	unsigned int		refcnt;
	unsigned int		entries;
	struct list_head	lru_list;
	struct list_head	iphash[0];
};

static LIST_HEAD(tables);
static LIST_HEAD(allows);
static DEFINE_SPINLOCK(coova_lock);
static DEFINE_SPINLOCK(allows_lock);
static DEFINE_MUTEX(coova_mutex);

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *coova_proc_dir;
static struct proc_dir_entry *allow_proc_dir;
static const struct file_operations coova_mt_fops, allows_fops;
#endif

static u_int32_t wNums = 0;
static u_int32_t hash_rnd;
static bool hash_rnd_initted;

static unsigned int coova_entry_hash4(const union nf_inet_addr *addr)
{
	if (!hash_rnd_initted) {
		get_random_bytes(&hash_rnd, sizeof(hash_rnd));
		hash_rnd_initted = true;
	}
	return jhash_1word((__force u32)addr->ip, hash_rnd) &
	       (ip_list_hash_size - 1);
}

static unsigned int coova_entry_hash6(const union nf_inet_addr *addr)
{
	if (!hash_rnd_initted) {
		get_random_bytes(&hash_rnd, sizeof(hash_rnd));
		hash_rnd_initted = true;
	}
	return jhash2((u32 *)addr->ip6, ARRAY_SIZE(addr->ip6), hash_rnd) &
	       (ip_list_hash_size - 1);
}

static struct coova_entry *
coova_entry_lookup(const struct coova_table *table,
		   const union nf_inet_addr *addrp, u_int16_t family)
{
	struct coova_entry *e;
	unsigned int h;

	if (family == AF_INET6) {
		h = coova_entry_hash6(addrp);
	} else {
		h = coova_entry_hash4(addrp);
	}

	list_for_each_entry(e, &table->iphash[h], list) {
		if (e->family == family &&
		    memcmp(&e->addr, addrp, sizeof(e->addr)) == 0)
			return e;
	}
	return NULL;
}

static struct coova_entry *
coova_entry_lookup_mac(const struct coova_table *table, 
	unsigned char *hwaddr, const union nf_inet_addr *addrp, u_int16_t family)
{
	struct coova_entry *e;
	unsigned int h;

	if (family == AF_INET6) {
		h = coova_entry_hash6(addrp);
	} else {
		h = coova_entry_hash4(addrp);
	}

	list_for_each_entry(e, &table->iphash[h], list) {
		if ( memcmp(&e->hwaddr, hwaddr, ETH_ALEN) == 0)
			return e;
	}
	return NULL;
}

static struct allows_entry * allows_entry_lookup(const u_int32_t addrp)
{
        struct allows_entry *t;
	int i = 0;

        list_for_each_entry(t, &allows, list) {
		i++;
		//printk(KERN_DEBUG "xt_coova: allow check [%d]/[%d].", wNums, i);
                if((addrp&(t->mask)) == ((t->addr)&(t->mask))) {
                	return t;
                }
        }
        return NULL;
}

static void coova_entry_remove(struct coova_table *t, struct coova_entry *e)
{
	list_del(&e->list);
	list_del(&e->lru_list);
	kfree(e);
	t->entries--;
}

static void allow_entry_remove(struct allows_entry *e)
{
        list_del(&(e->list));
        kfree(e);
}

static void coova_entry_reset(struct coova_entry *e)
{
	e->state = 0;
	e->bytes_in = 0;
	e->bytes_out = 0;
	e->pkts_in = 0;
	e->pkts_out = 0;
}

static struct coova_entry *
coova_entry_init(struct coova_table *t, const union nf_inet_addr *addr,
		 u_int16_t family)
{
	struct coova_entry *e, *next;
	unsigned int i;

	if (t->entries >= ip_list_tot) {

#if 0
		e = list_entry(t->lru_list.next, struct coova_entry, lru_list);
		coova_entry_remove(t, e);
#else
		for (i = 0; i < ip_list_hash_size; i++) {
			list_for_each_entry_safe(e, next, &t->iphash[i], list) {
				if ( 0 == e->state ) {
					coova_entry_remove(t, e);
					break;
				}
			}
		}
#endif
	}

	e = kmalloc(sizeof(*e), GFP_ATOMIC);

	if (e == NULL)
		return NULL;

	memcpy(&e->addr, addr, sizeof(e->addr));
	e->index     = 1;
	e->family    = family;

	coova_entry_reset(e);

	if (family == AF_INET6)
		list_add_tail(&e->list, &t->iphash[coova_entry_hash6(addr)]);
	else
		list_add_tail(&e->list, &t->iphash[coova_entry_hash4(addr)]);

	list_add_tail(&e->lru_list, &t->lru_list);
	t->entries++;
	return e;
}

static void coova_entry_update(struct coova_table *t, struct coova_entry *e)
{
	list_move_tail(&e->lru_list, &t->lru_list);
}

static struct coova_table *coova_table_lookup(const char *name)
{
	struct coova_table *t;

	list_for_each_entry(t, &tables, list)
		if (!strcmp(t->name, name))
			return t;
	return NULL;
}

static void allows_empty(void)
{
        struct allows_entry *e, *next;
        list_for_each_entry_safe(e, next, &allows, list)
        {
                        e->status = 0;
        }
}

static void allows_empty_del(void)
{
        struct allows_entry *e, *next;
        list_for_each_entry_safe(e, next, &allows, list)
                //if(  e->status == 0 )
                        allow_entry_remove(e);
}

static void allows_flush(void)
{
        struct allows_entry *e, *next;
        list_for_each_entry_safe(e, next, &allows, list)
                        allow_entry_remove(e);
}

static void coova_table_flush(struct coova_table *t)
{
	struct coova_entry *e, *next;
	unsigned int i;

	for (i = 0; i < ip_list_hash_size; i++)
		list_for_each_entry_safe(e, next, &t->iphash[i], list)
			coova_entry_remove(t, e);
}

static void rebuild_checksum(struct sk_buff* skb, struct iphdr *iph, struct tcphdr *tcph)
{
	unsigned  int ntcp_hdr_off;
    	ntcp_hdr_off = tcph->doff << 2;
	
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
		
	skb->csum = 0;
	skb->csum = csum_partial((unsigned char *)((unsigned char *)tcph + ntcp_hdr_off), ntohs(iph->tot_len) - (iph->ihl << 2) - ntcp_hdr_off, 0);
	
	tcph->check = 0;
	tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					ntohs(iph->tot_len) - (iph->ihl << 2), iph->protocol, 
					csum_partial((unsigned char *)tcph, ntcp_hdr_off, skb->csum));
				
	skb->ip_summed = CHECKSUM_NONE;
}

static int build_new_skb(struct sk_buff* old_skb,struct iphdr *old_iph,struct tcphdr *old_tcph,int old_length,int code, char* new_website)
{
    	unsigned char* mach;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sk_buff * new_skb;
	char *p;
	char *data_302 = "HTTP/1.1 302 Found\r\nLocation: ";
	char *data_200 = "HTTP/1.1 200 OK\r\n";
	char *data_204 = "HTTP/1.1 204 No Content\r\n";
	static char data[MAX_WEBSITE_LEN*4+1024+1+38];
	int i;
        int tcplen;
	int length ;
	static int identify = 0;

	p = data;
	if ( code == 302 ) {
		memcpy(p,(void*)data_302, strlen(data_302));
		p = p + strlen(data_302);
	}else if ( code == 200 ) {
		memcpy(p,(void*)data_200, strlen(data_200));
		p = p + strlen(data_200);
	}else if ( code == 204 ) {
		memcpy(p,(void*)data_204, strlen(data_204));
		p = p + strlen(data_204);
	}else {
		return -1;
	}
	memcpy(p, new_website, strlen(new_website));
	p = p + strlen(new_website);

	*p = '\r';
	p++;
	*p = '\n';
	p++;
	*p = '\r';
	p++;
	*p = '\n';
	p++;	
	*p = 0;
	
	//printk("http data = %s\n",data);
	tcplen = strlen(data);
	length = tcplen + sizeof(struct iphdr) + sizeof(struct tcphdr);

	identify++;
	
	new_skb = dev_alloc_skb(length+16);
	if(!new_skb){
		printk("low memory.../n");
		return -1;
	}

	skb_reserve(new_skb,length+16);
	memcpy(skb_push(new_skb,tcplen),data,tcplen);
    	tcph = (struct tcphdr *)skb_push(new_skb,sizeof(struct tcphdr));
#if LINUX_VERSION_CODE>= KERNEL_VERSION(2,6,30)
	skb_reset_transport_header(new_skb);
	tcph = tcp_hdr(new_skb);
#else
        new_skb->h.th = tcph;

#endif		
	iph = (struct iphdr *)skb_push(new_skb,sizeof(struct iphdr));

#if LINUX_VERSION_CODE>= KERNEL_VERSION(2,6,30)
	skb_reset_network_header(new_skb);
	iph = ip_hdr(new_skb);
#else

	new_skb->nh.iph = iph;

#endif	
	mach = (unsigned char*)skb_push(new_skb,14);
#if LINUX_VERSION_CODE>= KERNEL_VERSION(2,6,30)
	skb_reset_mac_header(new_skb);
#else

	new_skb->mac.raw = mach;

#endif	
	new_skb->protocol = htons(ETH_P_802_3); 
	
	new_skb->sk = NULL;		

#if LINUX_VERSION_CODE>= KERNEL_VERSION(3,10,34)

	for(i=0;i<6;i++) {
		*(((unsigned char*)skb_mac_header(new_skb)) + i)= *(((unsigned char*)skb_mac_header(old_skb)) + i + 6);
		*(((unsigned char*)skb_mac_header(new_skb)) + i + 6)= *(((unsigned char*)skb_mac_header(old_skb)) + i);
	}
	*(((unsigned char*)skb_mac_header(new_skb)) + 12) = 0x8;
	*(((unsigned char*)skb_mac_header(new_skb)) + 13) = 0x0;
//#if LINUX_VERSION_CODE>= KERNEL_VERSION(2,6,30)
//	for(i=0;i<6;i++) {
//		*(((unsigned char*)(new_skb->mac_header)) + i)= *(((unsigned char*)(old_skb->mac_header)) + i + 6);
//		*(((unsigned char*)(new_skb->mac_header)) + i + 6)= *(((unsigned char*)(old_skb->mac_header)) + i);
//	}
//	*(((unsigned char*)(new_skb->mac_header)) + 12) = 0x8;
//	*(((unsigned char*)(new_skb->mac_header)) + 13) = 0x0;
#else
	for(i=0;i<6;i++) {
		new_skb->mac.raw[i] = old_skb->mac.raw[i+6];
		new_skb->mac.raw[i+6] = old_skb->mac.raw[i];
	}
	new_skb->mac.raw[12] = 0x8;
	new_skb->mac.raw[13] = 0x0;
#endif

	tcph->source = old_tcph->dest;
	tcph->dest = old_tcph->source;
	tcph->seq = old_tcph->ack_seq;
	tcph->ack_seq = htonl(ntohl(old_tcph->seq) + old_length );
	tcph->doff = 5;
	tcph->ack = 1;
	tcph->fin = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->urg = 0;
	tcph->syn = 0;
	tcph->window = 0x1000;
	
        iph->ihl = 5;
        iph->version = IPVERSION;
	iph->tos = 0;
	iph->tot_len = htons(length);
	iph->id =htons(identify);
	iph->frag_off=0;
	iph->ttl=30;
	iph->protocol =IPPROTO_TCP ;
	iph->saddr=old_iph->daddr;
	iph->daddr=old_iph->saddr;	
	rebuild_checksum(new_skb,iph,tcph);
	new_skb->dev = old_skb->dev;
#if LINUX_VERSION_CODE>= KERNEL_VERSION(2,6,30)
	NF_HOOK(NFPROTO_IPV4, NF_INET_POST_ROUTING, new_skb, NULL, new_skb->dev, dev_queue_xmit);
#else
	NF_HOOK(PF_INET, NF_IP_POST_ROUTING, new_skb, NULL, new_skb->dev, dev_queue_xmit);
#endif

	return 0;
	
}

static int build_new_302(struct sk_buff* old_skb,struct iphdr *old_iph,struct tcphdr *old_tcph,int old_length,char* new_website)
{
	return build_new_skb(old_skb, old_iph, old_tcph, old_length, 302, new_website);
}

static int build_new_200(struct sk_buff* old_skb,struct iphdr *old_iph,struct tcphdr *old_tcph,int old_length,char* new_website)
{
	return build_new_skb(old_skb, old_iph, old_tcph, old_length, 200, new_website);
}

static int build_new_204(struct sk_buff* old_skb,struct iphdr *old_iph,struct tcphdr *old_tcph,int old_length,char* new_website)
{
	return build_new_skb(old_skb, old_iph, old_tcph, old_length, 204, new_website);
}

static char *  memistr (const char * str1,const char * str2,int len)
{
    char *cp = (char *) str1;
    char *s1, *s2;
        int i;
        int str_len;

    str_len = strlen(str2);
    if (str_len == 0 ) return((char *)str1);
        if( str_len > len) return NULL;

    for(i = 0; i<= (len-str_len);i++){
        s1 = cp +i;
        s2 = (char *) str2;

        while ( *s2 && !(_tolower(*s1)-_tolower(*s2)) )
            s1++, s2++;
            if (!*s2)return(cp + i);
        }
    return NULL;
}

static int get_name(char* input_str,int input_length,const char *name, char end_flag,int max_output_length,char* output_str)
{
        char* p;
        int output_length = 0;
        if(strlen(input_str) ==0 || strlen(name)==0 || input_length == 0 || max_output_length ==0) return -1;
        p = memistr(input_str,name,input_length);
        if(p == NULL) return -1;
        p = p + strlen(name);
        if((int)(p-input_str) >= input_length) return -1;
        while(*p == ' ') {
                p++;
                if((int)(p-input_str) >= input_length) return -1;
        }
        while(*p != end_flag) {
                if(output_length >= max_output_length) return output_length;
                output_str[output_length] = *p;
                output_length++;
                p++;
                if((int)(p-input_str) >= input_length) return -1;
        }
        return output_length;
}

static int get_address(char* input_str,int input_length, char end_flag,int max_output_length,char* output_str)
{
        char* p;
        int output_length = 0;
        if(strlen(input_str) ==0 || input_length == 0 || max_output_length ==0) return -1;

        p = input_str;

        while(*p == ' ') {
                p++;
                if((int)(p-input_str) >= input_length) return -1;
        }
        while(*p != end_flag) {
                if(output_length >= max_output_length) return output_length;
                output_str[output_length] = *p;
                output_length++;
                p++;
                if((int)(p-input_str) >= input_length) return -1;
        }
        return output_length;
}

/*
 *	url encode
 */
static int urlencode(char *src, int len, char *dst) {
  char x[3];
  int n = 0;
  int d = 0;

  for (n=0; n < len; n++) {
    if ((('A' <= *(src+n)) && (*(src+n) <= 'Z')) ||
        (('a' <= *(src+n)) && (*(src+n) <= 'z')) ||
        (('0' <= *(src+n)) && (*(src+n) <= '9')) ||
        ('/' == *(src+n)) ||
        ('-' == *(src+n)) ||
        ('_' == *(src+n)) ||
        ('.' == *(src+n)) ||
        ('!' == *(src+n)) ||
        ('~' == *(src+n)) ||
        ('*' == *(src+n))) {
      *(dst+d) = *(src+n);
	d++;
    }
    else {
      snprintf(x, 3, "%.2x", *(src+n));
      *(dst+d) = '%';
      d++;
      *(dst+d) = x[0];
      d++;
      *(dst+d) = x[1];
      d++;
    }
  }
  return 0;
}

/*
 *	http://portal.e.591wifi.com/portal/portal
 * 	?res=notyet
 *	&uamip=11.1.0.1
 *	&uamport=3660
 *	&challenge=721ba8e9be43df46116187a87a8497f2
 *	&called=00-0C-43-76-20-64
 *	&mac=F4-E3-FB-96-4F-44
 *	&ip=10.1.0.3
 *	&ssid=591_Free_Wifi
 *	&nasid=PT000c43762064dboxW
 *	&sessionid=59812fe300000003
 *	&userurl=http%3a%2f%2fwww.163.com%2f&md=2DA0E88685DA12E80723E54F422920E3
 *
 *		uamserver, "721ba8e9be43df46116187a87a8497f2", "00-0C-43-76-20-64", "F4-E3-FB-96-4F-44",
 */
static void build_portal_url(struct sk_buff* skb,struct iphdr *iph, struct tcphdr *tcph, int length, char *input, char *output)
{
	unsigned char *src = eth_hdr(skb)->h_source;
	unsigned char *dst = eth_hdr(skb)->h_dest;
	int len = 0;

	if ( NULL != src && NULL != dst && NULL != iph ) {

		//printk(KERN_INFO "\ncalled=%02X-%02X-%02X-%02X-%02X-%02X&mac=%02X-%02X-%02X-%02X-%02X-%02X", 
		//	src[0], src[1], src[2], src[3], src[4], src[5],
		//	dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);

		memcpy(output+len, uamserver, uamserverlen);
		len = len + uamserverlen;
		memcpy(output+len, "?res=notyet&uamip=11.1.0.1&uamport=3660", 39);
		len = len + 39;

		sprintf(output, "%s?res=notyet&uamip=11.1.0.1&uamport=3660&kernel=1&challenge=%s"
			"&called=%s&mac=%02X-%02X-%02X-%02X-%02X-%02X"
			"&ip=%pI4&ssid=Free_WiFi&nasid=%s&hsid=%s&userurl=http://%s",
			uamserver, "721ba8e9be43df46116187a87a8497f2", nasmac, 
			src[0], src[1], src[2], src[3], src[4], src[5], 
			&(iph->saddr), nasid, nasid, input);
	}
}

/*
 *	http://portal.e.591wifi.com/portal/portal
 * 	?res=notyet
 *	&uamip=11.1.0.1
 *	&uamport=3660
 *	&challenge=721ba8e9be43df46116187a87a8497f2
 *	&called=00-0C-43-76-20-64
 *	&mac=F4-E3-FB-96-4F-44
 *	&ip=10.1.0.3
 *	&ssid=591_Free_Wifi
 *	&nasid=PT000c43762064dboxW
 *	&sessionid=59812fe300000003
 *	&userurl=http%3a%2f%2fwww.163.com%2f&md=2DA0E88685DA12E80723E54F422920E3
 *
 *		uamserver, "721ba8e9be43df46116187a87a8497f2", "00-0C-43-76-20-64", "F4-E3-FB-96-4F-44",
 */
static int check_http_request(struct coova_entry *e, struct sk_buff* skb,struct iphdr *iph, struct tcphdr *tcph,unsigned char* haystack, int length,int isRequest)
{
	static char output_str[MAX_WEBSITE_LEN+1];
	static char encode_str[MAX_WEBSITE_LEN*4+1];
	static char output_str1[MAX_WEBSITE_LEN*4+1024+1];
	static char useragent_str[MAX_WEBSITE_LEN+1];
	static char proto_str[16];
	int len1,len2,len3, len4;

	if ( e == NULL ) return -1;

	memset(output_str, 0, MAX_WEBSITE_LEN+1);
	memset(encode_str, 0, MAX_WEBSITE_LEN*4+1);
	memset(output_str1, 0, MAX_WEBSITE_LEN*4+1024+1);
	memset(useragent_str, 0, MAX_WEBSITE_LEN+1);
	memset(proto_str, 0, 16);

	len1 = get_name(haystack,length,"host:",'\r',MAX_WEBSITE_LEN,output_str);
	if(len1 <=0) return -1;
        if(isRequest == 1)
	    len2 = get_address(haystack+3,length-3,' ',MAX_WEBSITE_LEN-len1,output_str + len1);
        else
	    len2 = get_address(haystack+4,length-4,' ',MAX_WEBSITE_LEN-len1,output_str + len1);

	if(len2 <=0) return -1;
	output_str[len1+len2] = '\0';
 	urlencode(output_str, len1+len2, encode_str);       

        if(isRequest == 1)
	    len3 = get_address(haystack+3+len2+1, length-3-len2-1, '\r', 15, proto_str);
        else
	    len3 = get_address(haystack+4+len2+1, length-4-len2-1, '\r', 15, proto_str);

	len4 = get_name(haystack,length,"User-Agent:",'\r', MAX_WEBSITE_LEN, useragent_str);

	//printk(KERN_INFO "CNA [%d], ANA [%d]\n", cna, ana);
	//printk(KERN_INFO "orig URL: [%s], proto [%s], user agent [%s]\n", encode_str, proto_str, useragent_str);

	/* check CNA or ANA */
	if ( len3 > 0 ) {

		if ( cna > 0 ) {
			if ( strstr(useragent_str, "CaptiveNetworkSupport") != NULL 
				|| strstr(encode_str, "/library/test/success.html") != NULL
				|| strstr(encode_str, "hotspot-detect.html") != NULL ) {

				return build_new_200(skb,iph,tcph,length, 
					"Content-type: text/html\r\n\r\n"
					"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>"
				);
			}
		}else {
			//printk(KERN_INFO "http_10 [%d] [%s]\n", e->is_http_10, encode_str);
			if ( memcmp(proto_str, "HTTP/1.0", 8) == 0 && strstr(useragent_str, "CaptiveNetworkSupport") != NULL ) {
				/* 500 jiffies means 5s */
				if ( jiffies - e->cna_time < 500 ) {
					return build_new_200(skb,iph,tcph,length, 
						"Content-type: text/html\r\n\r\n"
						"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>"
					);
				}
				e->cna_time = jiffies;
			}else if ( memcmp(proto_str, "HTTP/1.1", 8) == 0 && 
				( strstr(encode_str, "/library/test/success.html") != NULL
				|| strstr(encode_str, "hotspot-detect.html") != NULL ) ) {

				e->cna_time = jiffies;
			}
		}
		if ( ana > 0 ) {
			if ( strstr(encode_str, "/generate_204") != NULL ) {
				return build_new_204(skb,iph,tcph,length, "Content-type: text/html\r\n\r\n");
			}else if ( strstr(encode_str, "www.baidu.com") != NULL ) {
				return build_new_302(skb,iph,tcph,length, 
					"Cache-Control: no-cache\r\n"
					"Content-Length: 0\r\n"
					"Location: https://m.baidu.com/?from=844b&vit=fps\r\n\r\n"
				);
			}
		}
	}

	//printk(KERN_INFO "302 parameter: [%s]/[%s]", uamserver, uamhost);
	//printk(KERN_INFO "orig URL: [%s]", encode_str);

	if ( memcmp(output_str, uamhost, uamhostlen) != 0 ) {

		unsigned char *src = eth_hdr(skb)->h_source;
		unsigned char *dst = eth_hdr(skb)->h_dest;

		if ( NULL != src && NULL != dst && NULL != iph ) {
			build_portal_url(skb, iph, tcph, length, encode_str, output_str1);
			//printk(KERN_INFO "build 302 url: [%s]", output_str1);
			return build_new_302(skb,iph,tcph,length, output_str1);
		}else {
			return 0;
		}
	}else {
		return 0;
	}
}

static int check_http(struct coova_entry *e, struct sk_buff* skb,struct iphdr *iph, struct tcphdr *tcph,unsigned char* haystack, int length)
{
        if( memcmp(haystack, "GET", 3)==0 || memcmp(haystack, "PUT", 3)==0 ) {
                return check_http_request(e, skb,iph,tcph,haystack,length,1);
        } else if( memcmp(haystack, "POST", 4)==0 || memcmp(haystack, "HEAD", 4)==0 ) {
                return check_http_request(e, skb,iph,tcph,haystack,length,0);
        }else {
		//printk(KERN_INFO "xt_coova: return 9.");
		return 9;
	}
}

static bool
coova_mt(const struct sk_buff *skb, struct xt_action_param *par) 
{
	const struct xt_coova_mtinfo *info = par->matchinfo;
	struct iphdr *iph = ip_hdr(skb);
	struct coova_table *t;
	struct coova_entry *e;
	struct allows_entry *a = NULL;
	union nf_inet_addr addr = {};
	union nf_inet_addr addr2 = {};
	unsigned char *hwaddr = 0;
	bool ret = 0;
	int hret = 0;

	uint16_t p_bytes = 0;
	struct udphdr *udph = NULL;
	struct tcphdr *tcph = NULL;
	unsigned char* haystack;
	int hlen;

	if (par->match->family == AF_INET) {
		if ( iph->protocol == IPPROTO_UDP ) {
			udph = (void *)iph + (iph->ihl << 2);

			/* pass dns packet */
			if ( udph->dest == htons(53) || udph->source == htons(53) ) {
				return 1;
			}
		}else if ( iph->protocol == IPPROTO_TCP ) {
			tcph = (void *)iph + (iph->ihl << 2);
		}

		if (info->side == XT_COOVA_DEST) {
			addr.ip = iph->daddr;
			addr2.ip = iph->saddr;
		} else {
			addr.ip = iph->saddr;
			addr2.ip = iph->daddr;
		}
		p_bytes = ntohs(iph->tot_len);
	} else {
		const struct ipv6hdr *iph = ipv6_hdr(skb);

		if (info->side == XT_COOVA_DEST)
			memcpy(&addr.in6, &iph->daddr, sizeof(addr.in6));
		else
			memcpy(&addr.in6, &iph->saddr, sizeof(addr.in6));

		p_bytes = ntohs(iph->payload_len);
	}

	if (info->side != XT_COOVA_DEST) {
		if (skb_mac_header(skb) >= skb->head &&
		    skb_mac_header(skb) + ETH_HLEN <= skb->data) {
			hwaddr = eth_hdr(skb)->h_source;
		} else {
			return ret;
		}
	}

	spin_lock_bh(&coova_lock);
	t = coova_table_lookup(info->name);
	e = coova_entry_lookup(t, &addr, par->match->family);

	if ( e == NULL ) {
		if ( hwaddr ) {
			e = coova_entry_lookup_mac(t, hwaddr, &addr, par->match->family);
		}
	}

	if (e == NULL) {
		e = coova_entry_init(t, &addr, par->match->family);
		if (e == NULL) {
			spin_unlock_bh(&coova_lock);
			goto out;
		}
	}

	if (hwaddr)
		memcpy(e->hwaddr, hwaddr, ETH_ALEN);

	if (e->state) {
		if (info->side == XT_COOVA_DEST) {
			e->bytes_out += (uint64_t) p_bytes;
			e->pkts_out ++;
		} else {
			e->bytes_in += (uint64_t) p_bytes;
			e->pkts_in ++;
		}
	}

	coova_entry_update(t, e);

	ret = e->state;

	spin_unlock_bh(&coova_lock);

#if 0
	if ( 1 == ret ) {
		//printk(KERN_INFO "xt_coova: tag 0x80.");
		iph->tos = 0x80;  // Authed Tos, bypass
		iph->check = 0;
		iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	}
#endif

#if 1
	if ( 1 != ret ) {
		//printk(KERN_INFO "allows check .[%d]\n", addr2.ip);
		a = allows_entry_lookup(addr2.ip);
		if ( a != NULL ) {
			ret = 1;
		}else {
			//printk(KERN_INFO "allows check not found.[%d]\n", addr2.ip);
			if (par->match->family == AF_INET) {
				if ( iph->protocol == IPPROTO_TCP ) {
					tcph = (void *)iph + (iph->ihl << 2);

					/*
		 	 	 	 *	FIXME
		 	 	 	 *	output & input bytes
		 	 	 	 */
					if ( tcph->dest == htons(80) || tcph->source == htons(80) ) {
						if ( tcph->psh == 1 && tcph->ack == 1 ) {
							//printk(KERN_INFO "xt_coova: check tcp port 80 push data.");
       							haystack = (void *)tcph + (tcph->doff << 2);
       							hlen = ntohs(iph->tot_len)-(iph->ihl<< 2)- (tcph->doff<< 2);

#if LINUX_VERSION_CODE>= KERNEL_VERSION(2,6,30)
               						if( (hret = check_http(e, (struct sk_buff *)skb, iph, tcph, haystack, hlen)) == 0) ret = 0;
							if ( hret == 9 ) ret = 1;
#else
               						if( (hret = check_http(e, *pskb, iph,tcph,haystack,hlen)) == 0) ret = 0;
							if ( hret == 9 ) ret = 1;
#endif   
						}else {
							ret = 1;
						}
					}else {
						ret = 0;
					}
				}
			}
		}
	}
#endif
	
 out:
	//printk(KERN_INFO "xt_coova: out.");

	if (info->invert) 
		ret = !ret;

	return ret;
}

bool
coova_tag_bypass_tos(const struct sk_buff *skb) 
{
	struct iphdr *iph = ip_hdr(skb);
	struct coova_table *t;
	struct coova_entry *e;
	union nf_inet_addr addr = {};
	bool ret = 0;

        if ( iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP ) {
		addr.ip = iph->daddr;
	}else {
		return ret;
	}

	spin_lock_bh(&coova_lock);
	t = coova_table_lookup("chilli");
	e = coova_entry_lookup(t, &addr, 2); // 2 means AF_INET

	if (e == NULL) {
		//printk(KERN_INFO "NOT FOUND.[%d] [%d]", iph->saddr, iph->daddr);
		goto out;
	}

	//printk(KERN_INFO "-----FOUND.[%d] [%d]", iph->saddr, iph->daddr);

	/*
	 *	jiffies means 10ms counts
	 *	1000 means 10 seconds
	 */
	//printk(KERN_INFO "xt_coova: found. len = [%d] [%lu] [%lu]", ntohs(iph->tot_len), jiffies, e->firstTime);
	ret = e->state;
	if ( 1 == ret && jiffies - e->firstTime > 1000 ) {
		//printk(KERN_INFO "xt_coova: tag 0x80.");
		//printk(KERN_INFO "xt_coova: tag 0x80.");
		iph->tos = 0x80;  // Authed Tos, bypass
		iph->check = 0;
		iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
	}
	
 out:
	//printk(KERN_INFO "xt_coova: out.");
	spin_unlock_bh(&coova_lock);

	return ret;
}
EXPORT_SYMBOL(coova_tag_bypass_tos);

static int coova_mt_check(const struct xt_mtchk_param *par)
{
	const struct xt_coova_mtinfo *info = par->matchinfo;
	struct coova_table *t;
#ifdef CONFIG_PROC_FS
	struct proc_dir_entry *pde;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	kuid_t uid;
	kgid_t gid;
#endif
#endif
	unsigned i;
	int ret = 0;

	if (info->name[0] == '\0' ||
	    strnlen(info->name, XT_COOVA_NAME_LEN) == XT_COOVA_NAME_LEN)
		return -EINVAL;

	//printk(KERN_INFO "xt_coova: looking for %s\n", info->name);

	mutex_lock(&coova_mutex);
	t = coova_table_lookup(info->name);
	if (t != NULL) {
		t->refcnt++;
		//printk(KERN_INFO "xt_coova: found %s refcnt=%d\n", info->name, t->refcnt);
		goto out;
	}

	t = kzalloc(sizeof(*t) + sizeof(t->iphash[0]) * ip_list_hash_size,
		    GFP_KERNEL);
	if (t == NULL) {
		ret = -ENOMEM;
		goto out;
	}
	t->refcnt = 1;
	strcpy(t->name, info->name);
	INIT_LIST_HEAD(&t->lru_list);
	for (i = 0; i < ip_list_hash_size; i++)
		INIT_LIST_HEAD(&t->iphash[i]);

#ifdef CONFIG_PROC_FS
	pde = proc_create_data(t->name, ip_list_perms, coova_proc_dir,
			       &coova_mt_fops, t);
	if (pde == NULL) {
		kfree(t);
		ret = -ENOMEM;
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	uid = make_kuid(&init_user_ns, ip_list_uid);
	gid = make_kgid(&init_user_ns, ip_list_gid);
    	proc_set_user(pde, uid, gid);
#else
	pde->uid = ip_list_uid;
	pde->gid = ip_list_gid;
#endif

#endif
	spin_lock_bh(&coova_lock);
	list_add_tail(&t->list, &tables);
	spin_unlock_bh(&coova_lock);
	//printk(KERN_INFO "xt_coova: created %s refcnt=%d\n", t->name, t->refcnt);
out:
	mutex_unlock(&coova_mutex);
	//printk(KERN_INFO "xt_coova: match ret=%d\n", ret); 
	return ret;
}

static void coova_mt_destroy(const struct xt_mtdtor_param *par)
{
	const struct xt_coova_mtinfo *info = par->matchinfo;
	struct coova_table *t;

	mutex_lock(&coova_mutex);
	t = coova_table_lookup(info->name);
	if (--t->refcnt == 0) {
		spin_lock_bh(&coova_lock);
		list_del(&t->list);
		spin_unlock_bh(&coova_lock);
#ifdef CONFIG_PROC_FS
		remove_proc_entry(t->name, coova_proc_dir);
#endif
		coova_table_flush(t);
		allows_flush();
		kfree(t);
	}
	mutex_unlock(&coova_mutex);
}

#ifdef CONFIG_PROC_FS
struct coova_iter_state {
	const struct coova_table *table;
	unsigned int bucket;
};

static void *coova_seq_start(struct seq_file *seq, loff_t *pos)
	__acquires(coova_lock)
{
	struct coova_iter_state *st = seq->private;
	const struct coova_table *t = st->table;
	struct coova_entry *e;
	loff_t p = *pos;

	spin_lock_bh(&coova_lock);

	for (st->bucket = 0; st->bucket < ip_list_hash_size; st->bucket++)
		list_for_each_entry(e, &t->iphash[st->bucket], list)
			if (p-- == 0)
				return e;
	return NULL;
}

static void *allows_seq_start(struct seq_file *seq, loff_t *pos)
        __acquires(allows_lock)
{
        struct allows_entry *e = NULL;

        spin_lock_bh(&allows_lock);

        e = list_entry(allows.next, struct allows_entry, list);
        loff_t p = *pos;

        if(p <= 0) {
                return e;
        } else {
                list_for_each_entry(e, &allows, list)
                        if (p-- == 0)
                                return e;
        }
        return NULL;
}

static void *coova_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct coova_iter_state *st = seq->private;
	const struct coova_table *t = st->table;
	const struct coova_entry *e = v;
	const struct list_head *head = e->list.next;

	while (head == &t->iphash[st->bucket]) {
		if (++st->bucket >= ip_list_hash_size)
			return NULL;
		head = t->iphash[st->bucket].next;
	}
	(*pos)++;
	return list_entry(head, struct coova_entry, list);
}

static void *allows_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	const struct allows_entry *e = v;
        const struct list_head *head = e->list.next;
        (*pos)++;
        return list_entry(head, struct allows_entry, list);
}

static void coova_seq_stop(struct seq_file *s, void *v)
	__releases(coova_lock)
{
	spin_unlock_bh(&coova_lock);
}

static void allows_seq_stop(struct seq_file *seq, void *v)
        __releases(allows_lock)
{
        spin_unlock_bh(&allows_lock);
}

static int allows_seq_show(struct seq_file *seq, void *v)
{
        const struct allows_entry *e = v;
	if ( e->status == 1 )
        	seq_printf(seq, "%d %pI4 / %pI4\n", e->status, &e->addr, &e->mask);
        return 0;
}

static int coova_seq_show(struct seq_file *seq, void *v)
{
	const struct coova_entry *e = v;
	unsigned int i;

	i = (e->index - 1) % ip_pkt_list_tot;
	if (e->family == AF_INET6)
		seq_printf(seq, "mac=%.2X-%.2X-%.2X-%.2X-%.2X-%.2X src=%pI6",
			   e->hwaddr[0],e->hwaddr[1],e->hwaddr[2],
			   e->hwaddr[3],e->hwaddr[4],e->hwaddr[5],
			   &e->addr.in6);
	else
		seq_printf(seq, "mac=%.2X-%.2X-%.2X-%.2X-%.2X-%.2X src=%pI4",
			   e->hwaddr[0],e->hwaddr[1],e->hwaddr[2],
			   e->hwaddr[3],e->hwaddr[4],e->hwaddr[5],
			   &e->addr.ip);
	seq_printf(seq, " state=%u", e->state);
	seq_printf(seq, " bin=%llu bout=%llu", 
		   (unsigned long long)e->bytes_in, 
		   (unsigned long long)e->bytes_out);
	seq_printf(seq, " pin=%llu pout=%llu", 
		   (unsigned long long)e->pkts_in, 
		   (unsigned long long)e->pkts_out);
	seq_printf(seq, "\n");
	return 0;
}

static const struct seq_operations coova_seq_ops = {
	.start		= coova_seq_start,
	.next		= coova_seq_next,
	.stop		= coova_seq_stop,
	.show		= coova_seq_show,
};

static const struct seq_operations allows_seq_ops = {
        .start          = allows_seq_start,
        .next           = allows_seq_next,
        .stop           = allows_seq_stop,
        .show           = allows_seq_show,
};

static int allows_seq_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &allows_seq_ops);
}

static ssize_t  allows_write(struct file *file, const char __user *input,
                    size_t size, loff_t *loff)
{
        char *pos;
        struct allows_entry *e;
        uint32_t addr, mask;
        char buf[512] = {0};
	const char *c = buf;

        if (size == 0)
                return 0;
        if (size > sizeof(buf))
                size = sizeof(buf);

	memset((void *)buf, 0, sizeof(buf));
        if (copy_from_user(buf, input, size) != 0)
                return -EFAULT;

        //printk(KERN_ERR "xt_coova: allows_write [%s]\n", buf);
        //-all, then flush all
	switch (*c) {
	case 'P': /* Portal URL */
        	if (!memcmp(buf, "Phttp://", 8)) {
			memset((void *)uamserver, 0, sizeof(uamserver));
			memset((void *)uamhost, 0, sizeof(uamhost));
			memcpy(uamserver, buf+1, size-2);
			uamserverlen = size - 2;
			//printk(KERN_INFO KBUILD_MODNAME ": Set UAM Server = [%s]\n", uamserver);
			pos = strstr(uamserver+7, "/");
			if ( NULL != pos ) {
				memcpy(uamhost, uamserver+7, pos - uamserver - 7);
				uamhostlen = strlen(uamhost);
				//printk(KERN_INFO KBUILD_MODNAME ": Set UAM Host = [%s]\n", uamhost);
			}
		}
		return size;
	case 'N': /* NAS id */
		memset((void *)nasid, 0, sizeof(nasid));
		memcpy(nasid, buf+1, size-2);
		//printk(KERN_INFO KBUILD_MODNAME ": NAS Id = [%s]\n", nasid);
		return size;
	case 'M': /* NAS MAC */
		memset((void *)nasmac, 0, sizeof(nasmac));
		memcpy(nasmac, buf+1, size-2);
		//printk(KERN_INFO KBUILD_MODNAME ": NAS MAC = [%s]\n", nasmac);
		return size;
	case 'C': /* CNA or ANA */
        	if ( memcmp(buf+1, "CNA", 3) == 0 ) {
			cna = 1;
		}else if ( memcmp(buf+1, "-CNA", 4) == 0 ) {
			cna = 0;
		}else if ( memcmp(buf+1, "ANA", 3) == 0 ) {
			ana = 1;
		}else if ( memcmp(buf+1, "-ANA", 4) == 0 ) {
			ana = 0;
		}
		return size;
	case '-': /* NAS id */
        	if (!memcmp(buf, "-all", 4)) {
                	spin_lock_bh(&allows_lock);
                	//printk(KERN_ERR "xt_coova: -all %d white nodes --- \n", wNums);
                	//allows_empty();
                	allows_empty_del();
                	wNums = 0;
                	spin_unlock_bh(&allows_lock);
		}
		return 0;
	default:
                pos = strchr(buf, '/');
                if(pos == NULL)
                        return 0;
                *pos = '\0';
                //printk(KERN_ERR "xt_coova: 11111111111111111\n");
                addr = simple_strtol(buf, NULL, 10);
                mask = simple_strtol(pos+1, NULL, 10);

                e = kmalloc(sizeof(*e), GFP_ATOMIC);
                if (e == NULL)
                        return -EFAULT;
                e->addr = addr;
                e->mask = mask;
                e->status = 1;
                //printk(KERN_ERR "xt_coova: 44444444444444444\n");

                spin_lock_bh(&allows_lock);
		if ( NULL == allows_entry_lookup(addr) ) {
                	list_add_tail(&(e->list), &allows);
                	wNums++;
		}
                spin_unlock_bh(&allows_lock);
                //printk(KERN_ERR "xt_coova: 555555555555555555\n");
        }
        return size+1;
}

static int coova_seq_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	struct proc_dir_entry *pde = PDE(inode);
#endif
	struct coova_iter_state *st;

	st = __seq_open_private(file, &coova_seq_ops, sizeof(*st));
	if (st == NULL)
		return -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	st->table = PDE_DATA(inode);
#else
	st->table = pde->data;
#endif
	return 0;
}

static ssize_t
coova_mt_proc_write(struct file *file, const char __user *input,
		    size_t size, loff_t *loff)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	struct coova_table *t = PDE_DATA(file_inode(file));
#else
	const struct proc_dir_entry *pde = PDE(file->f_path.dentry->d_inode);
	struct coova_table *t = pde->data;
#endif
	struct coova_entry *e;
	//char buf[sizeof("+b335:1d35:1e55:dead:c0de:1715:5afe:c0de")];
	char buf[1024];
	const char *c = buf;
	union nf_inet_addr addr = {};
	u_int16_t family;
	bool auth=false;
	bool deauth=false;
	bool release=false;
	bool succ;

	if (size == 0)
		return 0;
	if (size > sizeof(buf))
		size = sizeof(buf);
	if (copy_from_user(buf, input, size) != 0)
		return -EFAULT;

	/* Strict protocol! */
	if (*loff != 0)
		return -ESPIPE;
	switch (*c) {
	case '/': /* flush table */
		spin_lock_bh(&coova_lock);
		coova_table_flush(t);
		spin_unlock_bh(&coova_lock);
		return size;
	case '-': 
		deauth = true;
		break;
	case '+': 
		auth = true;
		break;
	case '*': 
		release = true;
		break;
	default:
		printk(KERN_INFO KBUILD_MODNAME ": Need +ip, -ip, or /\n");
		return -EINVAL;
	}

	++c;
	--size;
	if (strnchr(c, size, ':') != NULL) {
		family = AF_INET6;
		succ   = in6_pton(c, size, (void *)&addr, '\n', NULL);
	} else {
		family = AF_INET;
		succ   = in4_pton(c, size, (void *)&addr, '\n', NULL);
	}

	if (!succ) {
		printk(KERN_INFO KBUILD_MODNAME ": illegal address written " "to procfs\n");
		return -EINVAL;
	}

	spin_lock_bh(&coova_lock);

	e = coova_entry_lookup(t, &addr, family);

	if (release) {

		if (e != NULL)
			coova_entry_remove(t, e);

	} else {
		if (e == NULL) {
			coova_entry_init(t, &addr, family);
		} 

		e = coova_entry_lookup(t, &addr, family);

		if (e != NULL) {
			coova_entry_reset(e);
			
			if (auth) {
				e->state = 1;
				e->firstTime = jiffies;
			} else if (deauth) {
				e->state = 0;
				e->firstTime = 0;
			}
			
			coova_entry_update(t, e);
		}

	}

	spin_unlock_bh(&coova_lock);

	/* Note we removed one above */
	*loff += size + 1;
	return size + 1;
}

static const struct file_operations coova_mt_fops = {
	.open    = coova_seq_open,
	.read    = seq_read,
	.write   = coova_mt_proc_write,
	.release = seq_release_private,
	.owner   = THIS_MODULE,
};

static const struct file_operations allows_fops = {
        .open    = allows_seq_open,
        .read    = seq_read,
        .write   = allows_write,
        .release = seq_release,
        .owner   = THIS_MODULE,
};

#endif /* CONFIG_PROC_FS */

static struct xt_match coova_mt_reg[] __read_mostly = {
        {
                .name           = "coova",
                .family         = AF_INET,
                .match          = coova_mt,
                .matchsize      = sizeof(struct xt_coova_mtinfo),
		.checkentry     = coova_mt_check,
		.destroy        = coova_mt_destroy,
                .hooks          = (1 << NF_INET_PRE_ROUTING) |
		                  (1 << NF_INET_POST_ROUTING) |
                                  (1 << NF_INET_LOCAL_IN) |
                                  (1 << NF_INET_LOCAL_OUT) |
                                  (1 << NF_INET_FORWARD),
                .me             = THIS_MODULE,
        },
        {
                .name           = "coova",
                .family         = AF_INET6,
                .match          = coova_mt,
                .matchsize      = sizeof(struct xt_coova_mtinfo),
		.checkentry     = coova_mt_check,
		.destroy        = coova_mt_destroy,
                .hooks          = (1 << NF_INET_PRE_ROUTING) |
		                  (1 << NF_INET_POST_ROUTING) |
                                  (1 << NF_INET_LOCAL_IN) |
                                  (1 << NF_INET_LOCAL_OUT) |
                                  (1 << NF_INET_FORWARD),
                .me             = THIS_MODULE,
        },
};

static int __init coova_mt_init(void)
{
	int err;

	if (!ip_list_tot || !ip_pkt_list_tot || ip_pkt_list_tot > 65536)
		return -EINVAL;

	ip_list_hash_size = 1 << fls(ip_list_tot);

	err = xt_register_matches(coova_mt_reg, ARRAY_SIZE(coova_mt_reg));

#ifdef CONFIG_PROC_FS
	if (err < 0) {
		printk(KERN_ERR "xt_coova: could not register match %d\n",err);
		return err;
	}
	coova_proc_dir = proc_mkdir("coova", init_net.proc_net);
	if (coova_proc_dir == NULL) {
		xt_unregister_matches(coova_mt_reg, ARRAY_SIZE(coova_mt_reg));
		err = -ENOMEM;
	}

        //gordon
        //new a entry named /proc/net/coova/allows
        allow_proc_dir = proc_create("allows", 0666, coova_proc_dir, &allows_fops);
        if (allow_proc_dir == NULL) {
                xt_unregister_matches(coova_mt_reg, ARRAY_SIZE(coova_mt_reg));
                err = -ENOMEM;
        }
#endif

	printk(KERN_INFO "xt_coova: ready\n");

	return err;
}

static void __exit coova_mt_exit(void)
{
	printk(KERN_INFO "xt_coova: exit\n");

	/* BUG_ON(!list_empty(&tables)); */

	xt_unregister_matches(coova_mt_reg, ARRAY_SIZE(coova_mt_reg));

#ifdef CONFIG_PROC_FS
	remove_proc_entry("allows", coova_proc_dir);
	remove_proc_entry("coova", init_net.proc_net);
#endif
}

module_init(coova_mt_init);
module_exit(coova_mt_exit);
