#include "xfrm_netlink.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sysrepo.h>
#include "utils.h"

#define XFRM_BUFSIZE 4096

static size_t hex2bin_local(const char *hex, unsigned char *out, size_t out_max)
{
	size_t len = strlen(hex);
	size_t i;

	if ((len % 2) != 0) {
		return 0;
	}
	if ((len / 2) > out_max) {
		return 0;
	}

	for (i = 0; i < len / 2; i++) {
		unsigned int byte;
		if (sscanf(hex + (2 * i), "%2x", &byte) != 1) {
			return 0;
		}
		out[i] = (unsigned char)byte;
	}

	return len / 2;
}

static uint8_t ipsec_mode_to_xfrm_mode(uint8_t ipsec_mode)
{
    /* En este proyecto/IPsec PF_KEY:
     *   1 = transport
     *   2 = tunnel (si alguna vez se usa así)
     *
     * En Linux XFRM netlink:
     *   XFRM_MODE_TRANSPORT = 0
     *   XFRM_MODE_TUNNEL    = 1
     */
    if (ipsec_mode == 1) {
        return XFRM_MODE_TRANSPORT;
    }

    return XFRM_MODE_TUNNEL;
}

static int addattr_l(struct nlmsghdr *n, size_t maxlen, int type, const void *data, size_t alen)
{
	size_t len = RTA_LENGTH(alen);
	size_t newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	struct rtattr *rta;

	if (newlen > maxlen) {
		return -1;
	}

	rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;

	if (alen > 0 && data != NULL) {
		memcpy(RTA_DATA(rta), data, alen);
	}

	n->nlmsg_len = newlen;
	return 0;
}

static int send_and_recv_ack(int fd, struct nlmsghdr *nlh)
{
	struct sockaddr_nl nladdr;
	char buf[XFRM_BUFSIZE];
	struct iovec iov;
	struct msghdr msg;
	int ret;

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	iov.iov_base = nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(fd, &msg, 0);
	if (ret < 0) {
		ERR("xfrm netlink sendmsg failed: %s", strerror(errno));
		return -1;
	}

	memset(buf, 0, sizeof(buf));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &nladdr;
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = recvmsg(fd, &msg, 0);
	if (ret < 0) {
		ERR("xfrm netlink recvmsg failed: %s", strerror(errno));
		return -1;
	}

	{
		struct nlmsghdr *h = (struct nlmsghdr *)buf;

		if (h->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);

			if (err->error == 0) {
				DBG("xfrm netlink ACK ok");
				return 0;
			}

			ERR("xfrm netlink kernel error: %s", strerror(-err->error));
			return -1;
		}

		ERR("xfrm netlink unexpected reply type=%u", h->nlmsg_type);
		return -1;
	}
}

int xfrm_addsad_aead(sad_entry_node *sad_node)
{
	int fd;
	char buf[XFRM_BUFSIZE];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct xfrm_usersa_info *xsinfo = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	struct xfrm_algo_aead *aead;
	unsigned char key_bin[128];
	size_t key_len_bytes;
	size_t aead_len;
	int ret;

	if (sad_node == NULL) {
		return SR_ERR_INVAL_ARG;
	}

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd < 0) {
		ERR("cannot open NETLINK_XFRM socket: %s", strerror(errno));
		return SR_ERR_OPERATION_FAILED;
	}

	memset(buf, 0, sizeof(buf));

	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = 1;
	nlh->nlmsg_pid = getpid();

	xsinfo->family = AF_INET;
	xsinfo->id.proto = IPPROTO_ESP;
	xsinfo->id.spi = htonl((uint32_t)sad_node->spi);

	if (inet_pton(AF_INET, get_ip(sad_node->remote_subnet), &xsinfo->id.daddr.a4) != 1) {
		ERR("invalid dst IP: %s", get_ip(sad_node->remote_subnet));
		close(fd);
		return SR_ERR_OPERATION_FAILED;
	}

	if (inet_pton(AF_INET, get_ip(sad_node->local_subnet), &xsinfo->saddr.a4) != 1) {
		ERR("invalid src IP: %s", get_ip(sad_node->local_subnet));
		close(fd);
		return SR_ERR_OPERATION_FAILED;
	}

	xsinfo->mode = ipsec_mode_to_xfrm_mode(sad_node->ipsec_mode);
	xsinfo->reqid = sad_node->req_id;
	xsinfo->replay_window = 0;

	xsinfo->lft.soft_add_expires_seconds =
    (sad_node->lft_time_soft == 0) ? XFRM_INF : sad_node->lft_time_soft;

	xsinfo->lft.hard_add_expires_seconds =
		(sad_node->lft_time_hard == 0) ? XFRM_INF : sad_node->lft_time_hard;

	xsinfo->lft.soft_byte_limit =
		(sad_node->lft_bytes_soft == 0) ? XFRM_INF : sad_node->lft_bytes_soft;

	xsinfo->lft.hard_byte_limit =
		(sad_node->lft_bytes_hard == 0) ? XFRM_INF : sad_node->lft_bytes_hard;

	xsinfo->lft.soft_packet_limit =
		(sad_node->lft_packets_soft == 0) ? XFRM_INF : sad_node->lft_packets_soft;

	xsinfo->lft.hard_packet_limit =
		(sad_node->lft_packets_hard == 0) ? XFRM_INF : sad_node->lft_packets_hard;

	key_len_bytes = hex2bin_local(sad_node->encryption_key, key_bin, sizeof(key_bin));
	if (key_len_bytes == 0) {
		ERR("invalid GCM key hex");
		close(fd);
		return SR_ERR_OPERATION_FAILED;
	}

	if (key_len_bytes != 20) {
		ERR("unexpected GCM key length: got %zu bytes, expected 20", key_len_bytes);
		close(fd);
		return SR_ERR_OPERATION_FAILED;
	}

	aead_len = sizeof(struct xfrm_algo_aead) + key_len_bytes;
	aead = calloc(1, aead_len);
	if (aead == NULL) {
		ERR("calloc failed");
		close(fd);
		return SR_ERR_OPERATION_FAILED;
	}

	strncpy(aead->alg_name, "rfc4106(gcm(aes))", sizeof(aead->alg_name) - 1);
	aead->alg_key_len = key_len_bytes * 8;
	aead->alg_icv_len = 128;
	memcpy(aead->alg_key, key_bin, key_len_bytes);

	ret = addattr_l(nlh, sizeof(buf), XFRMA_ALG_AEAD, aead, aead_len);
	free(aead);

	if (ret < 0) {
		ERR("failed to add XFRMA_ALG_AEAD");
		close(fd);
		return SR_ERR_OPERATION_FAILED;
	}

	DBG("XFRM NEWSA src=%s dst=%s spi=%u reqid=%u ipsec_mode=%u xfrm_mode=%u key_bytes=%zu icv_bits=%u",
    get_ip(sad_node->local_subnet),
    get_ip(sad_node->remote_subnet),
    sad_node->spi,
    sad_node->req_id,
    sad_node->ipsec_mode,
    xsinfo->mode,
    key_len_bytes,
    128U);

	ret = send_and_recv_ack(fd, nlh);
	close(fd);

	if (ret < 0) {
		return SR_ERR_OPERATION_FAILED;
	}

	return SR_ERR_OK;
}

int xfrm_delsad_aead(sad_entry_node *sad_node)
{
	int fd;
	struct {
		struct nlmsghdr nlh;
		struct xfrm_usersa_id xsid;
		xfrm_address_t saddr;
	} req;
	int ret;

	if (sad_node == NULL) {
		return SR_ERR_INVAL_ARG;
	}

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (fd < 0) {
		ERR("cannot open NETLINK_XFRM socket: %s", strerror(errno));
		return SR_ERR_OPERATION_FAILED;
	}

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct xfrm_usersa_id) + sizeof(xfrm_address_t));
	req.nlh.nlmsg_type = XFRM_MSG_DELSA;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nlh.nlmsg_seq = 1;
	req.nlh.nlmsg_pid = getpid();

	req.xsid.family = AF_INET;
	req.xsid.proto = IPPROTO_ESP;
	req.xsid.spi = htonl((uint32_t)sad_node->spi);

	if (inet_pton(AF_INET, get_ip(sad_node->remote_subnet), &req.xsid.daddr.a4) != 1) {
		ERR("invalid dst IP for delete");
		close(fd);
		return SR_ERR_OPERATION_FAILED;
	}

	if (inet_pton(AF_INET, get_ip(sad_node->local_subnet), &req.saddr.a4) != 1) {
		ERR("invalid src IP for delete");
		close(fd);
		return SR_ERR_OPERATION_FAILED;
	}

	DBG("XFRM DELSA src=%s dst=%s spi=%u",
		get_ip(sad_node->local_subnet),
		get_ip(sad_node->remote_subnet),
		sad_node->spi);

	ret = send_and_recv_ack(fd, &req.nlh);
	close(fd);

	if (ret < 0) {
    DBG("XFRM DELSA returned error, assuming SA may already be gone");
    return SR_ERR_OK;
	}

	return SR_ERR_OK;
}