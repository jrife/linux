// SPDX-License-Identifier: GPL-2.0
#include <network_helpers.h>
#include "test_progs.h"
#include "sockops_rto_timeout.skel.h"

#define TEST_NS "sockops_rto_timeout"

static void close_fds(int fds[], int fds_len)
{
	int i;

	for (i = 0; i < fds_len; i++)
		if (fds[i] >= 0)
			close(fds[i]);
}

void test_sockops_rto_timeout(void)
{
	struct sockops_rto_timeout *skel = NULL;
	static const int timeout_s = 10;
	struct nstoken *nstoken = NULL;
	static const int port = 10000;
	int accept_serv[2] = {-1, -1};
	int tcp_clien[2] = {-1, -1};
	int tcp_serv[2] = {-1, -1};
	int cg_fd = -1;
	int attempts;
	int i;

	SYS_NOFAIL("ip netns del " TEST_NS);
	SYS(cleanup, "ip netns add %s", TEST_NS);
	SYS(cleanup, "ip -net %s link set dev lo up", TEST_NS);

	nstoken = open_netns(TEST_NS);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto cleanup;

	cg_fd = test__join_cgroup("/sockops_rto_timeout");
	if (!ASSERT_OK_FD(cg_fd, "join_cgroup"))
		goto cleanup;

	skel = sockops_rto_timeout__open_and_load();
	if (!ASSERT_OK_PTR(skel, "sockops_rto_timeout__open_and_load"))
		goto cleanup;

	if (!ASSERT_OK(bpf_prog_attach(bpf_program__fd(skel->progs.rto_timeout),
				       cg_fd, BPF_CGROUP_SOCK_OPS,
				       BPF_F_ALLOW_OVERRIDE),
		       "bpf_prog_attach"))
		goto cleanup;

	tcp_serv[0] = start_server(AF_INET, SOCK_STREAM, "127.0.0.1", port, 0);
	if (!ASSERT_OK_FD(tcp_serv[0], "start_server"))
		goto cleanup;

	tcp_serv[1] = start_server(AF_INET6, SOCK_STREAM, "::1", port, 0);
	if (!ASSERT_OK_FD(tcp_serv[1], "start_server"))
		goto cleanup;

	/* Make sure first connect() attempt fails. */
	SYS(cleanup, "iptables -A INPUT -p tcp --dport %d -j DROP", port);
	SYS(cleanup, "ip6tables -A INPUT -p tcp --dport %d -j DROP", port);
	for (i = 0; i < ARRAY_SIZE(tcp_serv); i++) {
		tcp_clien[i] = connect_to_fd(tcp_serv[i], 0);
		if (!ASSERT_ERR_FD(tcp_clien[i], "connect_to_fd"))
			goto cleanup;
		if (!ASSERT_EQ(errno, ETIMEDOUT, "ETIMEDOUT"))
			goto cleanup;
	}

	if (!ASSERT_EQ(skel->bss->rto, 2, "rto"))
		goto cleanup;

	/* Make sure second connect() attempt succeeds. */
	SYS(cleanup, "iptables -D INPUT -p tcp --dport %d -j DROP", port);
	SYS(cleanup, "ip6tables -D INPUT -p tcp --dport %d -j DROP", port);
	for (i = 0; i < ARRAY_SIZE(tcp_serv); i++) {
		tcp_clien[i] = connect_to_fd(tcp_serv[i], 0);
		if (!ASSERT_OK_FD(tcp_clien[i], "connect_to_fd"))
			goto cleanup;
		accept_serv[i] = accept(tcp_serv[i], NULL, NULL);
		if (!ASSERT_OK_FD(accept_serv[i], "accept"))
			goto cleanup;
	}

	/* Make sure sockets are working. */
	for (i = 0; i < ARRAY_SIZE(tcp_clien); i++)
		if (!ASSERT_EQ(send(tcp_clien[i], "a", 1, 0), 1, "send"))
			goto cleanup;

	SYS(cleanup, "iptables -A INPUT -p tcp --dport %d -j DROP", port);
	SYS(cleanup, "ip6tables -A INPUT -p tcp --dport %d -j DROP", port);
	for (i = 0; i < ARRAY_SIZE(tcp_clien); i++) {
		attempts = 0;
		while (send(tcp_clien[i], "a", 1, 0) > 0) {
			if (!ASSERT_LT(attempts, timeout_s, "timeout"))
				goto cleanup;
			attempts++;
			sleep(1);
		}
		if (!ASSERT_EQ(errno, ETIMEDOUT, "ETIMEDOUT"))
			goto cleanup;
	}

	if (!ASSERT_EQ(skel->bss->rto, 4, "rto"))
		goto cleanup;
cleanup:
	close_fds(accept_serv, ARRAY_SIZE(accept_serv));
	close_fds(tcp_clien, ARRAY_SIZE(tcp_clien));
	close_fds(tcp_serv, ARRAY_SIZE(tcp_serv));
	if (cg_fd >= 0) {
		bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
		close(cg_fd);
	}
	sockops_rto_timeout__destroy(skel);
	close_netns(nstoken);
	SYS_NOFAIL("ip netns del " TEST_NS);
}

