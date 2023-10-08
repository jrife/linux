// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Google LLC. */
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/nsproxy.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/debugfs.h>

#define BIND    0
#define CONNECT 1
#define SENDMSG 2

static char ip[27];
module_param_string(ip, ip, sizeof(ip), 0644);
MODULE_PARM_DESC(ip, "IPv4/IPv6 address to use for socket operation");
static char port[7];
module_param_string(port, port, sizeof(port), 0644);
MODULE_PARM_DESC(port, "Port number to use for socket operation");
static uint af;
module_param(af, uint, 0644);
MODULE_PARM_DESC(ip, "Address family (AF_INET or AF_INET6)");
static int type;
module_param(type, int, 0644);
MODULE_PARM_DESC(ip, "Socket type (SOCK_STREAM or SOCK_DGRAM)");
static uint op;
module_param(op, uint, 0644);
MODULE_PARM_DESC(ip, "Socket operation (BIND=0, CONNECT=1, SENDMSG=2)");

static struct debugfs_blob_wrapper sock_name_blob;
static struct debugfs_blob_wrapper peer_name_blob;
static struct debugfs_blob_wrapper addr_blob;
static struct dentry *debugfs_dentry;
static struct sockaddr_storage sock_name;
static struct sockaddr_storage peer_name;
static struct sockaddr_storage addr;
static bool success;

static struct socket *sock = NULL;

static int do_kernel_bind(struct sockaddr *addr, int addrlen)
{
	int ret;
	
	ret = kernel_bind(sock, (struct sockaddr *)addr, addrlen);
	if (ret) {
		pr_err("kernel_bind() returned %d\n", ret);
		goto err;
	}
	
	ret = kernel_getsockname(sock, (struct sockaddr *)&sock_name);
	if (ret < 0) {
		pr_err("kernel_getsockname() returned %d\n", ret);
		goto err;
	}

	if (type == SOCK_STREAM) {
		ret = kernel_listen(sock, 128);
		if (ret == -1) {
			pr_err("kernel_listen() returned %d\n", ret);
			goto err;
		}
	}
	
	ret = 0;
	goto out;
err:
	ret = -1;
out:
	return ret;
}

static int do_kernel_connect(struct sockaddr *addr, int addrlen)
{
        int ret;
	
	ret = kernel_connect(sock, addr, addrlen, O_NONBLOCK);
	if (ret && ret != -EINPROGRESS) {
		pr_err("kernel_connect() returned %d\n", ret);
		goto err;
	}

	ret = kernel_getsockname(sock, (struct sockaddr *)&sock_name);
	if (ret < 0) {
		pr_err("kernel_getsockname() returned %d\n", ret);
		goto err;
	}

	ret = kernel_getpeername(sock, (struct sockaddr *)&peer_name);
	if (ret < 0) {
		pr_err("kernel_getpeername() returned %d\n", ret);
		goto err;
	}

	ret = 0;
	goto out;
err:
	ret = -1;
out:
	return ret;
}

static int do_kernel_sendmsg(struct sockaddr *addr, int addrlen)
{
	struct msghdr msg = {
		.msg_name	= addr,
		.msg_namelen	= addrlen,
	};
	struct kvec iov;
	int ret;

	iov.iov_base = "abc";
	iov.iov_len  = sizeof("abc");

	ret = kernel_sendmsg(sock, &msg, &iov, 1, sizeof("abc"));
	if (ret < 0) {
		pr_err("kernel_sendmsg() returned %d\n", ret);
		goto err;
	}

	/* kernel_sendmsg() and sock_sendmsg() are both used throughout the
	 * kernel. Neither of these functions should modify msg_name, so call
	 * both just to make sure.
	 */
	iov_iter_kvec(&msg.msg_iter, ITER_SOURCE, &iov, 1, sizeof("abc"));
       	ret = sock_sendmsg(sock, &msg);
	if (ret < 0) {
		pr_err("sock_sendmsg() returned %d\n", ret);
		goto err;
	}

	ret = 0;
	goto out;
err:
	ret = -1;
out:
	return ret;
}

static int do_sock_op(int op, struct sockaddr *addr, int addrlen)
{
	pr_info("do_sock_op(%d, %pISpc, %d)\n", op, addr, addrlen);

	switch (op) {
	case BIND:
		return do_kernel_bind(addr, addrlen);
	case CONNECT:
		return do_kernel_connect(addr, addrlen);
	case SENDMSG:
		return do_kernel_sendmsg(addr, addrlen);
	default:
		return -EINVAL;
	}
}

static int kernel_sock_addr_testmod_init(void)
{
	int ret;

	debugfs_dentry = debugfs_create_dir("sock_addr_testmod", NULL);

	addr_blob.data = &addr;
	addr_blob.size = sizeof(addr);
	sock_name_blob.data = &sock_name;
	sock_name_blob.size = sizeof(sock_name);
	peer_name_blob.data = &peer_name;
	peer_name_blob.size = sizeof(peer_name);

	debugfs_create_blob("addr", 0444, debugfs_dentry, &addr_blob);
	debugfs_create_blob("sock_name", 0444, debugfs_dentry, &sock_name_blob);
	debugfs_create_blob("peer_name", 0444, debugfs_dentry, &peer_name_blob);
	debugfs_create_bool("success", 0444, debugfs_dentry, &success);

	ret = inet_pton_with_scope(&init_net, af, ip, port, &addr);
	if (ret) {
		pr_err("inet_pton_with_scope() returned %d\n", ret);
		goto err;
	}
	
	ret = sock_create_kern(&init_net, af, type, type == SOCK_STREAM ? 
			       IPPROTO_TCP : IPPROTO_UDP, &sock);
	if (ret) {
		pr_err("sock_create_kern() returned %d\n", ret);
		goto err;
	}

	if (do_sock_op(op, (struct sockaddr *)&addr, sizeof(addr)))
		goto err;
	
	success = true;
	ret = 0;
	goto out;
err:
	success = false;
	ret = -1;
out:
	return ret;
}

static void kernel_sock_addr_testmod_exit(void)
{
	if (sock)
		sock_release(sock);

	debugfs_remove_recursive(debugfs_dentry);
}

module_init(kernel_sock_addr_testmod_init);
module_exit(kernel_sock_addr_testmod_exit);

MODULE_AUTHOR("Jordan Rife");
MODULE_DESCRIPTION("BPF socket address selftests module");
MODULE_LICENSE("Dual BSD/GPL");