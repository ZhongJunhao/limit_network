
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/socket.h>

#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/dcache.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/spinlock_types.h>
#include <linux/rcupdate.h>

#include <net/inet_connection_sock.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/tcp.h>




#include <linux/slab.h>


#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

//proc file name
#define FILE_NAME   "network_speed"
//file funtions
static int file_open(struct inode *, struct file *);
static void *my_seq_start(struct seq_file * filp,loff_t *pos);
static void *my_seq_next(struct seq_file* filp,void *v,loff_t *pos);
static void my_seq_stop(struct seq_file* filp,void *v);
static int my_seq_show(struct seq_file* m,void *v);
//file structures
static struct proc_dir_entry *file_entry;
static struct file_operations file_oper = {
	.owner = THIS_MODULE,
	.open = file_open,
	.release = seq_release,
	.read = seq_read,
	.llseek = seq_lseek,
};

static struct seq_operations seq_oper = {
	.start = my_seq_start,
	.next = my_seq_next,
	.stop = my_seq_stop,
	.show = my_seq_show,
};

#define SOCKET_HASH_MOD  (1<<8) 
static struct hlist_head htb_sock[SOCKET_HASH_MOD];
static spinlock_t lock_htb_sock;
struct trans_info{
	u64 pre_time;
	int speed;
};

struct speed_node{
	struct socket *sk;
	struct trans_info recv,snd;
	
	struct hlist_node hlist;
};


struct nf_hook_ops in_hook_ops;
struct nf_hook_ops out_hook_ops;

static unsigned int my_hash_fun(struct socket *sk)
{
	unsigned int result = (unsigned int)sk;
	unsigned char *temp = (unsigned char *)&result;
	result = temp[0]^temp[1]^temp[2]^temp[3];
	result &= (SOCKET_HASH_MOD-1);
	return result;	
}

static struct speed_node * htb_sock_find(struct socket *sk)
{
	unsigned int h = my_hash_fun(sk);
	struct hlist_node *list;
	struct speed_node *result = NULL;
	spin_lock(&lock_htb_sock);
	hlist_for_each_entry(result,list,&htb_sock[h],hlist)
	{
		if(result->sk == sk)
		{
			spin_unlock(&lock_htb_sock);
			return result;
		}
	}
	spin_unlock(&lock_htb_sock);
	return (struct speed_node *)NULL;
		
}

static void htb_sock_add(struct socket *sk)
{
	struct speed_node *node = NULL;
	unsigned int h ;
	if(htb_sock_find(sk)!= NULL) return ; //had been in it return;
	h = my_hash_fun(sk);
	printk("add node h: %u , socket : %x\n",h,(unsigned int)sk);
	node = (struct speed_node *)kmalloc(sizeof(struct speed_node),GFP_KERNEL);
	if(node!=NULL)
	{
		node->recv.pre_time = jiffies;
		node->snd.pre_time = jiffies;
		node->recv.speed = 0;
		node->snd.speed = 0;
		node->sk = sk;
		spin_lock(&lock_htb_sock);
		hlist_add_head(&node->hlist,&htb_sock[h]);
		spin_unlock(&lock_htb_sock);
	}
}


static void htb_sock_del(struct speed_node *del_node)
{
	if(del_node!=NULL)
	{
		spin_lock(&lock_htb_sock);
		hlist_del(&(del_node->hlist));
		spin_unlock(&lock_htb_sock);
		kfree(del_node);
	}
}	

static void freelist(struct speed_node * node)
{
	struct speed_node *next;
	if(node ==NULL) return ;
	next = hlist_entry((node->hlist.next),struct speed_node,hlist);
	while(next != NULL)
	{
		htb_sock_del(next);
		next = hlist_entry((node->hlist.next),struct speed_node,hlist);
	}
	htb_sock_del(node);
}


static struct sock *udp_v4_lookup_longway(u32 saddr, u16 sport,
					  u32 daddr, u16 dport, int dif)
{
	struct sock *sk, *result = NULL;
	struct hlist_node *node;
	unsigned short hnum = ntohs(dport);
	int badness = -1;

	sk_for_each(sk, node, &udp_hash[hnum & (UDP_HTABLE_SIZE - 1)]) {
		struct inet_sock *inet = inet_sk(sk);

		if (inet->num == hnum && !ipv6_only_sock(sk)) {
			int score = (sk->sk_family == PF_INET ? 1 : 0);
			if (inet->rcv_saddr) {
				if (inet->rcv_saddr != daddr)
					continue;
				score+=2;
			}
			if (inet->daddr) {
				if (inet->daddr != saddr)
					continue;
				score+=2;
			}
			if (inet->dport) {
				if (inet->dport != sport)
					continue;
				score+=2;
			}
			if (sk->sk_bound_dev_if) {
				if (sk->sk_bound_dev_if != dif)
					continue;
				score+=2;
			}
			if(score == 9) {
				result = sk;
				break;
			} else if(score > badness) {
				result = sk;
				badness = score;
			}
		}
	}
	return result;
}


static __inline__ struct sock *udp_v4_lookup(u32 saddr, u16 sport,
					     u32 daddr, u16 dport, int dif)
{
	struct sock *sk;

	read_lock(&udp_hash_lock);
	sk = udp_v4_lookup_longway(saddr, sport, daddr, dport, dif);
	read_unlock(&udp_hash_lock);
	return sk;
}


static unsigned int my_nf_hook(unsigned int hooknum,
                                  struct sk_buff **skb,
                                  const struct net_device *in,
                                  const struct net_device *out,
                                  int (*okfn)(struct sk_buff *))
{
	struct iphdr * iph = (*skb)->nh.iph;
	struct tcphdr * tcph = (struct tcphdr *)((__u32*)iph+iph->ihl);
	struct udphdr * udph = (struct udphdr *)((__u32*)iph+iph->ihl);
	struct sock *sk = (*skb)->sk;
	struct speed_node *sp_node = NULL;
	struct file *f = NULL;
	if( 6 == iph->protocol)//tcp
	{
		if( (NULL == sk)&&
			(sk = inet_lookup(&tcp_hashinfo,iph->saddr,tcph->source,iph->daddr,tcph->dest,inet_iif(*skb))) == NULL)
		{//last packet
			return NF_ACCEPT;
		}
	}else if( 17 == iph->protocol )//udp
	{
		if( (NULL == sk)&& 
			(sk = udp_v4_lookup(iph->saddr,udph->source,iph->daddr,udph->dest,(*skb)->dev->ifindex)) == NULL)
		{//last packet
			return NF_ACCEPT;
		}
	}else//other protocol
	{
		printk("other protocl \n");
	}
	if(sk!=NULL&&sk->sk_socket!=NULL)
	{
		
		sp_node = htb_sock_find(sk->sk_socket);
		if(sp_node != NULL)
		{
			int interval ;
			if(NF_IP_LOCAL_IN == hooknum)
			{
				interval = jiffies - sp_node->recv.pre_time ;
				if(interval != 0)
				{
					sp_node->recv.speed = ((*skb)->len) *( HZ / interval);
				}
				else
				{
					sp_node->recv.speed = 0;
				}
				printk("recv a pack speed %d ,socket : %x \n",sp_node->recv.speed,(unsigned int)sk->sk_socket);
				
			}
			else
			{
				
				interval = jiffies - sp_node->snd.pre_time ;
				if(interval != 0)
				{
					sp_node->snd.speed = ((*skb)->len) *( HZ / interval);
				}
				else
				{
					sp_node->snd.speed = 0;
				}
				printk("send a pack speed %d ,socket : %x\n",sp_node->snd.speed,(unsigned int)sk->sk_socket);
			}
		}
		else
		{
			htb_sock_add(sk->sk_socket);
			
		}
	}
	return NF_ACCEPT;
		
}





static int file_open(struct inode *pinode, struct file *filp)
{
	return seq_open(filp,&seq_oper);
}
static void *my_seq_start(struct seq_file* filp,loff_t *pos)
{
	struct task_struct * t = NULL;
	if(*pos == 0)
	{
		return (void *)pos;
	}
	return (void *)NULL;
}

static void *my_seq_next(struct seq_file* filp,void *v,loff_t *pos)
{
/*
	struct task_struct * t ;
	
	rcu_read_lock();
	t = next_task((struct task_struct *)v);
	if(t == &init_task)
	{
		t = NULL;
	}
	rcu_read_unlock();
*/
	*pos++;
	return (void *)NULL;
}

static void my_seq_stop(struct seq_file* filp,void *v)
{
	return ;
}


static int my_seq_show(struct seq_file* filp,void *v)
{
	struct task_struct * task = NULL;
	int speed_revc = 0;
	int speed_snd = 0;
	struct fdtable *fdt = NULL;
	int i=0;
	int j=0;
	struct file *myfile_fd = NULL;
	struct dentry * the_dentry = NULL;
	struct inode *the_inode = NULL;
	struct socket *the_socket = NULL;
	struct speed_node *sp_node = NULL;
	int find_a_sock = 0;
	
	if(filp==NULL ) return 0;
	rcu_read_lock();
	for_each_process(task)
	{
		if(task == NULL)break;
		fdt = files_fdtable(task->files);
		if(fdt == NULL)
		{
			continue;
		}
		find_a_sock = 0;
		j = 0;
		speed_revc = 0;
		speed_snd = 0;
		for(;;)
		{
			unsigned long set;

			i = j*__NFDBITS;

			if(i>= fdt->max_fdset || i>= fdt->max_fds)
			{
				break;
			}
			set = fdt->open_fds->fds_bits[j++];
			for(;set!=0;i++,set >>= 1)
			{
				if(set&1)
				{
					myfile_fd = fdt->fd[i];
					if(myfile_fd != NULL)
					{
						the_dentry = myfile_fd->f_dentry;
						if(the_dentry != NULL)
						{
							the_inode = the_dentry->d_inode;
							if(the_inode!=NULL && S_ISSOCK(the_inode->i_mode))
							{
								the_socket = SOCKET_I(the_inode);
								if(the_socket!=NULL )
								{
									printk("find a sock,addr %x\n",the_socket);
									find_a_sock = 1;
									sp_node = htb_sock_find(the_socket);
									if(sp_node != NULL)
									{
										speed_revc += sp_node->recv.speed;
										speed_snd += sp_node->snd.speed;
									}
								}
							}
						}
					}
				}
			}
		}
		 seq_printf(filp,"%5d\n",task->pid);
		if(find_a_sock)
		{
			 seq_printf(filp,"%5d\t%10d\t%10d\n",task->pid,speed_revc,speed_snd);
		}
	}
	rcu_read_unlock();
	return 0;
}

static int __init limit_init(void)
{
	int i =0;
	for(i=0;i<SOCKET_HASH_MOD;i++)
	{
		INIT_HLIST_HEAD(htb_sock);
	}
	spin_lock_init(&lock_htb_sock);
	//proc init
	file_entry = create_proc_entry(FILE_NAME,0444,NULL);
	if(file_entry == NULL)
	{
		remove_proc_entry(FILE_NAME,&proc_root);
		printk("proc create err");
		return -1;
	}
	file_entry->proc_fops = &file_oper;
	
	//hook init	
	in_hook_ops.hook = my_nf_hook;
	in_hook_ops.hooknum = NF_IP_LOCAL_IN;
	in_hook_ops.owner = THIS_MODULE;
	in_hook_ops.pf = PF_INET;
	in_hook_ops.priority = NF_IP_PRI_LAST;
	out_hook_ops.hook = my_nf_hook;
	out_hook_ops.hooknum = NF_IP_LOCAL_OUT;
	out_hook_ops.owner = THIS_MODULE;
	out_hook_ops.pf = PF_INET;
	out_hook_ops.priority = NF_IP_PRI_LAST;
	nf_register_hook(&in_hook_ops);
	nf_register_hook(&out_hook_ops);	
	return 0;
}
	

static void __exit limit_exit(void)
{
	int i = 0;
	struct speed_node * node = NULL;	
	nf_unregister_hook(&in_hook_ops);
	nf_unregister_hook(&out_hook_ops);
	remove_proc_entry(FILE_NAME,&proc_root);
	for(i=0 ; i<SOCKET_HASH_MOD; i++)
	{
		if(htb_sock[i].first != NULL)
		{
			node = hlist_entry(htb_sock[i].first,struct speed_node,hlist);
	//		freelist(node);
		}
	}

}

module_init(limit_init);
module_exit(limit_exit);


