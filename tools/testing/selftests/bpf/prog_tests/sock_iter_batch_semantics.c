// SPDX-License-Identifier: GPL-2.0

#include <test_progs.h>
#include "network_helpers.h"
#include "sock_iter_batch.skel.h"

#define TEST_NS "sock_iter_batch_netns"

static const __u16 reuse_port = 10001;
static const int nr_soreuse = 4;

static void print_one_by_one(int iter_fd, int limit)
{
	int nread = 1;
	__u64 cookie;

	while (nread > 0 && limit) {
		if (limit > 0)
			limit--;
		nread = read(iter_fd, &cookie, sizeof(cookie));
		if (nread <= 0) {
			if (!nread)
				printf("iteration end\n");
			continue;
		}
		printf("saw socket %llu\n", cookie);
	}
}

static void print_all_sockets(struct bpf_link *iter_link)
{
	int iter_fd = -1;
	iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto done;
	printf("all sockets\n");
	print_one_by_one(iter_fd, -1);
done:
	if (iter_fd < 0)
		close(iter_fd);
}

static void skip_a_socket(void)
{
	struct bpf_link *link = NULL;
	struct sock_iter_batch *skel;
	int err, iter_fd = -1;
	int *fds;

	skel = sock_iter_batch__open();
	if (!ASSERT_OK_PTR(skel, "sock_iter_batch__open"))
		return;

	/* Prepare a bucket of sockets in the kernel hashtable */
	int local_port;

	fds = start_reuseport_server(AF_INET, SOCK_DGRAM, "127.0.0.1", 0, 0,
				     nr_soreuse);
	if (!ASSERT_OK_PTR(fds, "start_reuseport_server"))
		goto done;
	local_port = get_socket_local_port(*fds);
	if (!ASSERT_GE(local_port, 0, "get_socket_local_port"))
		goto done;
	skel->rodata->ports[0] = ntohs(local_port);

	err = sock_iter_batch__load(skel);
	if (!ASSERT_OK(err, "sock_iter_batch__load"))
		goto done;

	link = bpf_program__attach_iter(skel->progs.iter_udp_soreuse_cookie,
					NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto done;

	/* Print all sockets currently in the bucket for reference. */
	print_all_sockets(link);

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto done;

	/* Iterate through the first three sockets in the bucket and print their
	 * socket cookies.
	 */
	printf("start iterations\n");
	print_one_by_one(iter_fd, nr_soreuse - 1);

	/* Close the first three sockets to remove them from the bucket. */
	printf("close three sockets\n");
	close(fds[1]);
	close(fds[2]);
	close(fds[3]);

	/* Try to iterate and print the rest of the sockets we haven't seen yet.
	 * We won't see the fourth and final socket and this will just print
	 * "iteration end".
	 */
	printf("resume iterations\n");
	print_one_by_one(iter_fd, -1);
	print_all_sockets(link);
done:
	free_fds(fds, nr_soreuse);
	if (iter_fd < 0)
		close(iter_fd);
	bpf_link__destroy(link);
	sock_iter_batch__destroy(skel);
}

static void repeat_a_socket(void)
{
	struct bpf_link *link = NULL;
	struct sock_iter_batch *skel;
	int err, i, iter_fd = -1;
	int *fds[2] = {};

	skel = sock_iter_batch__open();
	if (!ASSERT_OK_PTR(skel, "sock_iter_batch__open"))
		return;

	/* Prepare a bucket of sockets in the kernel hashtable */
	int local_port;

	fds[0] = start_reuseport_server(AF_INET, SOCK_DGRAM, "127.0.0.1",
					reuse_port, 0, nr_soreuse);
	if (!ASSERT_OK_PTR(fds[0], "start_reuseport_server"))
		goto done;
	local_port = get_socket_local_port(*fds[0]);
	if (!ASSERT_GE(local_port, 0, "get_socket_local_port"))
		goto done;
	skel->rodata->ports[0] = ntohs(local_port);

	err = sock_iter_batch__load(skel);
	if (!ASSERT_OK(err, "sock_iter_batch__load"))
		goto done;

	link = bpf_program__attach_iter(skel->progs.iter_udp_soreuse_cookie,
					NULL);
	if (!ASSERT_OK_PTR(link, "bpf_program__attach_iter"))
		goto done;

	/* Print all sockets currently in the bucket for reference. */
	print_all_sockets(link);

	iter_fd = bpf_iter_create(bpf_link__fd(link));
	if (!ASSERT_GE(iter_fd, 0, "bpf_iter_create"))
		goto done;

	/* Iterate through the first three sockets in the bucket and print their
	 * socket cookies.
	 */
	printf("start iterations\n");
	print_one_by_one(iter_fd, nr_soreuse - 1);

	printf("add four sockets\n");
	/* Add nr_soreuse more sockets to the bucket. */
	fds[1] = start_reuseport_server(AF_INET, SOCK_DGRAM, "127.0.0.1",
					reuse_port, 0, nr_soreuse);
	if (!ASSERT_OK_PTR(fds[1], "start_reuseport_server"))
		goto done;

	/* Finish iterating and print the rest of the items. We will repeat the
	 * first three sockets again.
	 */
	printf("resume iterations\n");
	print_one_by_one(iter_fd, -1);
	print_all_sockets(link);
done:
	for (i = 0; i < ARRAY_SIZE(fds); i++)
		free_fds(fds[i], nr_soreuse);
	if (iter_fd < 0)
		close(iter_fd);
	bpf_link__destroy(link);
	sock_iter_batch__destroy(skel);
}

void test_sock_iter_batch_semantics(void)
{
	struct nstoken *nstoken = NULL;

	SYS_NOFAIL("ip netns del " TEST_NS);
	SYS(done, "ip netns add %s", TEST_NS);
	SYS(done, "ip -net %s link set dev lo up", TEST_NS);

	nstoken = open_netns(TEST_NS);
	if (!ASSERT_OK_PTR(nstoken, "open_netns"))
		goto done;

	skip_a_socket();
	repeat_a_socket();
	close_netns(nstoken);
done:
	SYS_NOFAIL("ip netns del " TEST_NS);
}
