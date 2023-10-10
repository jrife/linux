// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Google LLC. */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "cgroup_helpers.h"
#include "test_sock_addr.h"
#include "testing_helpers.h"
#include "bpf_util.h"
#include "test_progs.h"

#define BIND    0
#define CONNECT 1
#define SENDMSG 2

static struct sock_addr_test tests[] = {
	/* bind */
	{
		"bind4: ensure that kernel_bind does not overwrite the address "
		"(TCP)",
		bind4_prog_load,
		BPF_CGROUP_INET4_BIND,
		BPF_CGROUP_INET4_BIND,
		AF_INET,
		SOCK_STREAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
	},
	{
		"bind4: ensure that kernel_bind does not overwrite the address "
		"(UDP)",
		bind4_prog_load,
		BPF_CGROUP_INET4_BIND,
		BPF_CGROUP_INET4_BIND,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
	},
	{
		"bind6: ensure that kernel_bind does not overwrite the address "
		"(TCP)",
		bind6_prog_load,
		BPF_CGROUP_INET6_BIND,
		BPF_CGROUP_INET6_BIND,
		AF_INET6,
		SOCK_STREAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
	},
	{
		"bind6: ensure that kernel_bind does not overwrite the address "
		"(UDP)",
		bind6_prog_load,
		BPF_CGROUP_INET6_BIND,
		BPF_CGROUP_INET6_BIND,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
	},

	/* connect */
	{
		"connect4: ensure that kernel_connect does not overwrite the "
		"address (TCP)",
		connect4_prog_load,
		BPF_CGROUP_INET4_CONNECT,
		BPF_CGROUP_INET4_CONNECT,
		AF_INET,
		SOCK_STREAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		"connect4: ensure that kernel_connect does not overwrite the "
		"address (UDP)",
		connect4_prog_load,
		BPF_CGROUP_INET4_CONNECT,
		BPF_CGROUP_INET4_CONNECT,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		"connect6: ensure that kernel_connect does not overwrite the "
		"address (TCP)",
		connect6_prog_load,
		BPF_CGROUP_INET6_CONNECT,
		BPF_CGROUP_INET6_CONNECT,
		AF_INET6,
		SOCK_STREAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},
	{
		"connect6: ensure that kernel_connect does not overwrite the "
		"address (UDP)",
		connect6_prog_load,
		BPF_CGROUP_INET6_CONNECT,
		BPF_CGROUP_INET6_CONNECT,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},

	/* sendmsg */
	{
		"sendmsg4: ensure that kernel_sendmsg does not overwrite the "
		"address (UDP)",
		sendmsg4_rw_c_prog_load,
		BPF_CGROUP_UDP4_SENDMSG,
		BPF_CGROUP_UDP4_SENDMSG,
		AF_INET,
		SOCK_DGRAM,
		SERV4_IP,
		SERV4_PORT,
		SERV4_REWRITE_IP,
		SERV4_REWRITE_PORT,
		SRC4_REWRITE_IP,
	},
	{
		"sendmsg6: ensure that kernel_sendmsg does not overwrite the "
		"address (UDP)",
		sendmsg6_rw_c_prog_load,
		BPF_CGROUP_UDP6_SENDMSG,
		BPF_CGROUP_UDP6_SENDMSG,
		AF_INET6,
		SOCK_DGRAM,
		SERV6_IP,
		SERV6_PORT,
		SERV6_REWRITE_IP,
		SERV6_REWRITE_PORT,
		SRC6_REWRITE_IP,
	},
};

struct sock_addr_testmod_results {
	bool success;
	struct sockaddr_storage addr;
	struct sockaddr_storage sock_name;
	struct sockaddr_storage peer_name;
};

static int load_mod(const struct sock_addr_test *test, int op)
{
	char params_str[512];

	if (sprintf(params_str, "ip=%s port=%hu af=%d type=%d op=%d",
		    test->requested_ip, test->requested_port, test->domain,
		    test->type, op) < 0)
		return -1;

	if (load_bpf_sock_addr_testmod(params_str, false))
		return -1;
	
	return 0;
}

static int unload_mod()
{
	return unload_bpf_sock_addr_testmod(false);
}

static int read_result(const char *path, void *val, size_t len)
{
	FILE *f;
	int err;
	
	f = fopen(path, "r");
	if (!f)
		goto err;
		
	err = fread(val, 1, len, f);
	if (err != len)
		goto err;

	err = 0;
	goto out;

err:
	err = -1;
out:
	if (f)
		fclose(f);

	return err;
}

static int read_mod_results(struct sock_addr_testmod_results *results)
{
	int err;
	char success[2];

	if (read_result("/sys/kernel/debug/sock_addr_testmod/success", success,
			sizeof(success)))
		goto err;
	
	switch (success[0]) {
	case 'N':
		results->success = false;
		break;
	case 'Y':
		results->success = true;
		break;
	default:
		goto err;
	}

	if (read_result("/sys/kernel/debug/sock_addr_testmod/addr",
			&results->addr, sizeof(results->addr)))
		goto err;

	if (read_result("/sys/kernel/debug/sock_addr_testmod/sock_name",
			&results->sock_name, sizeof(results->sock_name)))
		goto err;
	
	if (read_result("/sys/kernel/debug/sock_addr_testmod/peer_name",
			&results->peer_name, sizeof(results->peer_name)))
		goto err;

	err = 0;
	goto out;
err:
	err = -1;
out:
	return err;
}

static int run_mod_test(const struct sock_addr_test *test, int op,
			struct sock_addr_testmod_results *results)
{
	int err;

	if (load_mod(test, op))
		goto err;

	if (read_mod_results(results))
		goto err;
	
	err = 0;
	goto out;
err:
	err = -1;
out:
	if (unload_mod())
		err = -1;

	return err;
}

static const char* ntop(int af, const struct sockaddr_storage *addr, char *buf,
			size_t buf_len)
{
	char ip_buf[INET6_ADDRSTRLEN];
	unsigned short port;

	switch (af) {
	case AF_INET:
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		port = ntohs(sin->sin_port);

		if (!inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf)))
			goto err;

		break;
	case AF_INET6:
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		port = ntohs(sin6->sin6_port);

		if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ip_buf,
			       sizeof(ip_buf)))
			goto err;

		break;
	default:
		goto err;
	}

	sprintf(buf, "%s:%d", ip_buf, port);

	goto out;
err:
	buf = NULL;
out:
	return buf;
}

static void assert_addr_eq(const char *name, int af,
			const struct sockaddr_storage *expected,
		    	const struct sockaddr_storage *got, int cmp_port)
{
	int ret = cmp_addr(expected, got, cmp_port);
	char expected_buf[100];
	char got_buf[100];
	int duration = 0;

	CHECK(ret, name, "(expected=%s, got=%s)\n",
	      ntop(af, expected, expected_buf, sizeof(expected_buf)),
	      ntop(af, got, got_buf, sizeof(got_buf)));
}

static void test_kernel_bind(const struct sock_addr_test *test)
{
	socklen_t addr_len = sizeof(struct sockaddr_storage);
	struct sock_addr_testmod_results results;
	struct sockaddr_storage requested_addr;
	struct sockaddr_storage expected_addr;
	int clientfd = -1;

	if (!ASSERT_OK(init_addrs(test, &requested_addr, &expected_addr, NULL),
		       "init_addrs"))
		goto cleanup;

	if (!ASSERT_OK(load_mod(test, BIND), "load_mod"))
		goto cleanup;
	
	/* Try to connect to server just in case */
	clientfd = connect_to_server(test->type, &expected_addr, addr_len);
	if (!ASSERT_GT(clientfd, 0, "connect_to_server"))
		goto cleanup;

	if (!ASSERT_OK(read_mod_results(&results), "read_mod_results"))
		goto cleanup;

	if (!ASSERT_TRUE(results.success, "results_success"))
		goto cleanup;
	
	assert_addr_eq("addr", test->domain, &requested_addr, &results.addr, 1);
	assert_addr_eq("sock_name", test->domain, &expected_addr,
		       &results.sock_name, 1);

cleanup:
	ASSERT_OK(unload_mod(), "unload_mod");
}

static void test_kernel_connect(const struct sock_addr_test *test)
{
	socklen_t addr_len = sizeof(struct sockaddr_storage);
	struct sockaddr_storage expected_src_addr;
	struct sock_addr_testmod_results results;
	struct sockaddr_storage requested_addr;
	struct sockaddr_storage expected_addr;
	int servfd = -1;

	if (!ASSERT_OK(init_addrs(test, &requested_addr, &expected_addr,
		       &expected_src_addr), "init_addrs"))
		goto cleanup;

	/* Prepare server to connect to */
	servfd = start_server(test->type, &expected_addr, addr_len);
	if (!ASSERT_GT(servfd, 0, "start_server"))
		goto cleanup;

	if (!ASSERT_OK(run_mod_test(test, CONNECT, &results), "run_mod_test"))
		goto cleanup;
	
	if (!ASSERT_TRUE(results.success, "results_success"))
		goto cleanup;
	
	assert_addr_eq("addr", test->domain, &requested_addr, &results.addr, 1);
	assert_addr_eq("source_addr", test->domain, &expected_src_addr,
		       &results.sock_name, 0);
	assert_addr_eq("peer_name", test->domain, &expected_addr,
	               &results.peer_name, 1);

cleanup:
	if (servfd > 0)
		close(servfd);
}

static void test_kernel_sendmsg(const struct sock_addr_test *test)
{
	socklen_t addr_len = sizeof(struct sockaddr_storage);
	struct sock_addr_testmod_results results;
	struct sockaddr_storage expected_addr;
	struct sockaddr_storage sendmsg_addr;
	struct sockaddr_storage recvmsg_addr;
	struct sockaddr_storage server_addr;
	int servfd = -1;

	if (!ASSERT_OK(init_addrs(test, &sendmsg_addr, &server_addr,
				  &expected_addr), "init_addrs"))
		goto cleanup;
	
	/* Prepare server to sendmsg to */
	servfd = start_server(test->type, &server_addr, addr_len);
	if (!ASSERT_GT(servfd, 0, "start_server"))
		goto cleanup;
	
	if (!ASSERT_OK(run_mod_test(test, SENDMSG, &results), "run_mod_test"))
		goto cleanup;

	if (!ASSERT_TRUE(results.success, "results_success"))
		goto cleanup;
	
	assert_addr_eq("msg_name", test->domain, &sendmsg_addr, &results.addr,
		       1);
	
	if (!ASSERT_GT(recvmsg_from_client(servfd, &recvmsg_addr), 0,
		       "recvmsg_from_client"))
		goto cleanup;
	
	assert_addr_eq("source_addr", test->domain, &recvmsg_addr,
		       &expected_addr, 0);

cleanup:
	if (servfd > 0)
		close(servfd);
}

static void run_test_case(int cgfd, const struct sock_addr_test *test)
{
	int progfd = -1;

	progfd = test->loadfn(test);
	if (!ASSERT_GE(progfd, 0, "loadfn"))
		goto cleanup;

	if (!ASSERT_OK(bpf_prog_attach(progfd, cgfd, test->attach_type,
			      BPF_F_ALLOW_OVERRIDE), "bpf_prog_attach"))
		goto cleanup;

	switch (test->attach_type) {
	case BPF_CGROUP_INET4_BIND:
	case BPF_CGROUP_INET6_BIND:
		test_kernel_bind(test);
		break;
	case BPF_CGROUP_INET4_CONNECT:
	case BPF_CGROUP_INET6_CONNECT:
		test_kernel_connect(test);
		break;
	case BPF_CGROUP_UDP4_SENDMSG:
	case BPF_CGROUP_UDP6_SENDMSG:
		test_kernel_sendmsg(test);
		break;
	default:
		ASSERT_TRUE(false, "attach_type_invalid");
	}

cleanup:
	/* Detaching w/o checking return code: best effort attempt. */
	if (progfd != -1) {
		bpf_prog_detach(cgfd, test->attach_type);
		close(progfd);
	}
}

static void run_tests(int cgfd)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); ++i) {
		run_test_case(cgfd, &tests[i]);
	}
}

static int setup_test_env(void)
{
	return system("./test_sock_addr.sh setup");
}

static int cleanup_test_env(void)
{
	return system("./test_sock_addr.sh cleanup");
}

void test_sock_addr_kern(void)
{
	int cgfd = -1;

	if (!ASSERT_OK(setup_test_env(), "setup_test_env"))
		goto cleanup;

	/* Attach programs to root cgroup so they interact with kernel socket
	 * operations.
	 */
	cgfd = get_root_cgroup();
	if (!ASSERT_GE(cgfd, 0, "get_root_cgroup"))
		goto cleanup;

	run_tests(cgfd);
cleanup:
	if (cgfd >= 0)
		close(cgfd);
	cleanup_cgroup_environment();
	cleanup_test_env();
}
