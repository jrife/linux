/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _TEST_SOCK_ADDR_H
#define _TEST_SOCK_ADDR_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cgroup_helpers.h"

#define CONNECT4_PROG_PATH	"./connect4_prog.bpf.o"
#define CONNECT6_PROG_PATH	"./connect6_prog.bpf.o"
#define SENDMSG4_PROG_PATH	"./sendmsg4_prog.bpf.o"
#define SENDMSG6_PROG_PATH	"./sendmsg6_prog.bpf.o"
#define RECVMSG4_PROG_PATH	"./recvmsg4_prog.bpf.o"
#define RECVMSG6_PROG_PATH	"./recvmsg6_prog.bpf.o"
#define BIND4_PROG_PATH		"./bind4_prog.bpf.o"
#define BIND6_PROG_PATH		"./bind6_prog.bpf.o"

#define SERV4_IP		"192.168.1.254"
#define SERV4_REWRITE_IP	"127.0.0.1"
#define SRC4_IP			"172.16.0.1"
#define SRC4_REWRITE_IP		"127.0.0.4"
#define SERV4_PORT		4040
#define SERV4_REWRITE_PORT	4444

#define SERV6_IP		"face:b00c:1234:5678::abcd"
#define SERV6_REWRITE_IP	"::1"
#define SERV6_V4MAPPED_IP	"::ffff:192.168.0.4"
#define SRC6_IP			"::1"
#define SRC6_REWRITE_IP		"::6"
#define WILDCARD6_IP		"::"
#define SERV6_PORT		6060
#define SERV6_REWRITE_PORT	6666

#define INET_NTOP_BUF	40

struct sock_addr_test;

typedef int (*load_fn)(const struct sock_addr_test *test);

struct sock_addr_test {
	const char *descr;
	/* BPF prog properties */
	load_fn loadfn;
	enum bpf_attach_type expected_attach_type;
	enum bpf_attach_type attach_type;
	/* Socket properties */
	int domain;
	int type;
	/* IP:port pairs for BPF prog to override */
	const char *requested_ip;
	unsigned short requested_port;
	const char *expected_ip;
	unsigned short expected_port;
	const char *expected_src_ip;
	/* Expected test result */
	enum {
		LOAD_REJECT,
		ATTACH_REJECT,
		ATTACH_OKAY,
		SYSCALL_EPERM,
		SYSCALL_ENOTSUPP,
		SUCCESS,
	} expected_result;
};

static int load_path(const struct sock_addr_test *test, const char *path)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int err;

	obj = bpf_object__open_file(path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		log_err(">>> Opening BPF object (%s) error.\n", path);
		return -1;
	}

	prog = bpf_object__next_program(obj, NULL);
	if (!prog)
		goto err_out;

	bpf_program__set_type(prog, BPF_PROG_TYPE_CGROUP_SOCK_ADDR);
	bpf_program__set_expected_attach_type(prog, test->expected_attach_type);
	bpf_program__set_flags(prog, BPF_F_TEST_RND_HI32);

	err = bpf_object__load(obj);
	if (err) {
		if (test->expected_result != LOAD_REJECT)
			log_err(">>> Loading program (%s) error.\n", path);
		goto err_out;
	}

	return bpf_program__fd(prog);
err_out:
	bpf_object__close(obj);
	return -1;
}

static int bind4_prog_load(const struct sock_addr_test *test)
{
	return load_path(test, BIND4_PROG_PATH);
}

static int bind6_prog_load(const struct sock_addr_test *test)
{
	return load_path(test, BIND6_PROG_PATH);
}

static int connect4_prog_load(const struct sock_addr_test *test)
{
	return load_path(test, CONNECT4_PROG_PATH);
}

static int connect6_prog_load(const struct sock_addr_test *test)
{
	return load_path(test, CONNECT6_PROG_PATH);
}

static int sendmsg4_rw_c_prog_load(const struct sock_addr_test *test)
{
	return load_path(test, SENDMSG4_PROG_PATH);
}

static int sendmsg6_rw_c_prog_load(const struct sock_addr_test *test)
{
	return load_path(test, SENDMSG6_PROG_PATH);
}

static int mk_sockaddr(int domain, const char *ip, unsigned short port,
		       struct sockaddr *addr, socklen_t addr_len)
{
	struct sockaddr_in6 *addr6;
	struct sockaddr_in *addr4;

	if (domain != AF_INET && domain != AF_INET6) {
		log_err("Unsupported address family");
		return -1;
	}

	memset(addr, 0, addr_len);

	if (domain == AF_INET) {
		if (addr_len < sizeof(struct sockaddr_in))
			return -1;
		addr4 = (struct sockaddr_in *)addr;
		addr4->sin_family = domain;
		addr4->sin_port = htons(port);
		if (inet_pton(domain, ip, (void *)&addr4->sin_addr) != 1) {
			log_err("Invalid IPv4: %s", ip);
			return -1;
		}
	} else if (domain == AF_INET6) {
		if (addr_len < sizeof(struct sockaddr_in6))
			return -1;
		addr6 = (struct sockaddr_in6 *)addr;
		addr6->sin6_family = domain;
		addr6->sin6_port = htons(port);
		if (inet_pton(domain, ip, (void *)&addr6->sin6_addr) != 1) {
			log_err("Invalid IPv6: %s", ip);
			return -1;
		}
	}

	return 0;
}

static int init_addrs(const struct sock_addr_test *test,
		      struct sockaddr_storage *requested_addr,
		      struct sockaddr_storage *expected_addr,
		      struct sockaddr_storage *expected_src_addr)
{
	socklen_t addr_len = sizeof(struct sockaddr_storage);

	if (mk_sockaddr(test->domain, test->expected_ip, test->expected_port,
			(struct sockaddr *)expected_addr, addr_len) == -1)
		goto err;

	if (mk_sockaddr(test->domain, test->requested_ip, test->requested_port,
			(struct sockaddr *)requested_addr, addr_len) == -1)
		goto err;

	if (test->expected_src_ip &&
	    mk_sockaddr(test->domain, test->expected_src_ip, 0,
			(struct sockaddr *)expected_src_addr, addr_len) == -1)
		goto err;

	return 0;
err:
	return -1;
}

static int cmp_addr(const struct sockaddr_storage *addr1,
		    const struct sockaddr_storage *addr2, int cmp_port)
{
	const struct sockaddr_in *four1, *four2;
	const struct sockaddr_in6 *six1, *six2;

	if (addr1->ss_family != addr2->ss_family)
		return -1;

	if (addr1->ss_family == AF_INET) {
		four1 = (const struct sockaddr_in *)addr1;
		four2 = (const struct sockaddr_in *)addr2;
		return !((four1->sin_port == four2->sin_port || !cmp_port) &&
			 four1->sin_addr.s_addr == four2->sin_addr.s_addr);
	} else if (addr1->ss_family == AF_INET6) {
		six1 = (const struct sockaddr_in6 *)addr1;
		six2 = (const struct sockaddr_in6 *)addr2;
		return !((six1->sin6_port == six2->sin6_port || !cmp_port) &&
			 !memcmp(&six1->sin6_addr, &six2->sin6_addr,
				 sizeof(struct in6_addr)));
	}

	return -1;
}

static int start_server(int type, const struct sockaddr_storage *addr,
			socklen_t addr_len)
{
	int fd;

	fd = socket(addr->ss_family, type, 0);
	if (fd == -1) {
		log_err("Failed to create server socket");
		goto out;
	}

	if (bind(fd, (const struct sockaddr *)addr, addr_len) == -1) {
		log_err("Failed to bind server socket");
		goto close_out;
	}

	if (type == SOCK_STREAM) {
		if (listen(fd, 128) == -1) {
			log_err("Failed to listen on server socket");
			goto close_out;
		}
	}

	goto out;
close_out:
	close(fd);
	fd = -1;
out:
	return fd;
}

static int recvmsg_from_client(int sockfd, struct sockaddr_storage *src_addr)
{
	struct timeval tv;
	struct msghdr hdr;
	struct iovec iov;
	char data[64];
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(sockfd, &rfds);

	tv.tv_sec = 2;
	tv.tv_usec = 0;

	if (select(sockfd + 1, &rfds, NULL, NULL, &tv) <= 0 ||
	    !FD_ISSET(sockfd, &rfds))
		return -1;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = data;
	iov.iov_len = sizeof(data);

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_name = src_addr;
	hdr.msg_namelen = sizeof(struct sockaddr_storage);
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;

	return recvmsg(sockfd, &hdr, 0);
}

static int connect_to_server(int type, const struct sockaddr_storage *addr,
			     socklen_t addr_len)
{
	int domain;
	int fd = -1;

	domain = addr->ss_family;

	if (domain != AF_INET && domain != AF_INET6) {
		log_err("Unsupported address family");
		goto err;
	}

	fd = socket(domain, type, 0);
	if (fd == -1) {
		log_err("Failed to create client socket");
		goto err;
	}

	if (connect(fd, (const struct sockaddr *)addr, addr_len) == -1) {
		log_err("Fail to connect to server");
		goto err;
	}

	goto out;
err:
	close(fd);
	fd = -1;
out:
	return fd;
}

#endif
