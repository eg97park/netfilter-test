/**
 * sudo iptables-save > ~/_iptables_backup
 * sudo iptables-restore ~/_iptables_backup
sudo iptables -F &&
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0 &&
sudo iptables -A INPUT -j NFQUEUE --queue-num 0;
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "bm.h"
#include <stdbool.h>

/**
 * @brief 콜백 함수 cb로 넘길 구조체 선언.
 * ctx bm 알고리즘용 변수.
 * target_string 찾을 문자열.
 */
typedef struct cb_data_{
	BmCtx* ctx;
	char* target_string;
	bool isMalicious;
}CbData;


/**
 * @brief https://github.com/eg97park/pcap-test/blob/main/pcap-test.c
 * 예전 pcap-test 과제에서 구현했던 구조체 재사용
 */
#pragma pack(1)
struct MY_IPV4{
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char IHL:4;
	u_char VER:4;
#else
	u_char VER:4;
	u_char IHL:4;
#endif
	uint8_t DSCP_ECN;
	uint16_t TOTAL_LEN;
	uint16_t ID;
	uint16_t FLAG_FRAGOFFSET;
	uint8_t TTL;
	uint8_t PROTOCOL;
	uint16_t HDR_CHKSUM;
	uint32_t SRC_IP_ADDR;
	uint32_t DST_IP_ADDR;
};

struct MY_TCP{
	uint16_t SRC_PORT;
	uint16_t DST_PORT;
	uint32_t SEQ_NUM;
	uint32_t ACK_NUM;
#if BYTE_ORDER == LITTLE_ENDIAN
	u_char FLAGS_RESERVED_NS:4;
	u_char DATA_OFFSET:4;
#else
	u_char DATA_OFFSET:4;
	u_char FLAGS_RESERVED_NS:4;
#endif
	uint8_t FLAGS_ETC:4;
	uint16_t WIN_SIZE;
	uint16_t CHKSUM;
	uint16_t URG_PTR;
};


/**
 * @brief 주어진 패킷에서 전역변수로 설정된 target_string을 찾습니다.
 *  찾았다면 악성으로 판단, 주어진 구조체 cbData 내부의 플래그를 1로 설정합니다.
 *  그렇지 않다면 0으로 설정합니다.
 * 
 * @param[in] data 패킷
 * @param[in] len 패킷 길이
 * @param[in] cbData bm 알고리즘용 변수
 * @return[out] int 1: 악성, 0: 정상
 */
int is_malicious(unsigned char **data, int len, CbData* cbData)
{
	unsigned char *payload = NULL;
	uint32_t payload_len = 0;
	struct MY_ETH* _ethhdr = (struct MY_ETH*)*data;

	// IPv4 패킷만 처리.
	if ((*data)[0] != '\x45'){
		return 0;
	}

	// TCP 패킷만 처리.
	struct MY_IPV4* _ipv4hdr = (struct MY_IPV4*)(*data);
	if (_ipv4hdr->PROTOCOL != 0x06){
		return 0;
	}

	// 목적지 포트가 80인 패킷만 처리.
	struct MY_TCP* _tcphdr = (struct MY_TCP*)(*data + _ipv4hdr->IHL * 4);
	if (ntohs(_tcphdr->DST_PORT) != 0x0050){
		return 0;
	}

	payload = *data + _ipv4hdr->IHL * 4 + _tcphdr->DATA_OFFSET * 4;
	payload_len = len - (_ipv4hdr->IHL * 4 + _tcphdr->DATA_OFFSET * 4);

		fprintf(stderr, "#################################\n");
	/**
	 * @todo HTTP request method에 대해서만 처리.
	 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods
	 * GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
	 */

	// HTTP Method 체크.
	if (memcmp(payload, "GET ", 4) == 0 ||
	 memcmp(payload, "POST", 4) == 0 ||
	 memcmp(payload, "HEAD", 4) == 0 ||
	 memcmp(payload, "PUT ", 4) == 0 ||
	 memcmp(payload, "DELE", 4) == 0 ||
	 memcmp(payload, "CONN", 4) == 0 ||
	 memcmp(payload, "OPTI", 4) == 0 ||
	 memcmp(payload, "TRAC", 4) == 0 ||
	 memcmp(payload, "PATC", 4) == 0){
		// target_string 문자열이 payload에 존재하는지 확인.
		fprintf(stderr, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		fprintf(stderr, "method=%c%c%c%c\n", payload[0], payload[1], payload[2], payload[3]);
		char* ptr = BoyerMoore(cbData->target_string, strlen(cbData->target_string), payload, payload_len, cbData->ctx);
		if (ptr != NULL){
			// 악성이라면, 플래그 설정.
			cbData->isMalicious = true;
			return 1;
		} 
	}
	return 0;
}


/* returns packet id */
static uint32_t print_pkt (struct nfq_data *tb, CbData* cbData)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	uint32_t mark, ifi, uid, gid;
	int ret;
	unsigned char *data, *secdata;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ", 
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	if (nfq_get_uid(tb, &uid))
		printf("uid=%u ", uid);

	if (nfq_get_gid(tb, &gid))
		printf("gid=%u ", gid);

	ret = nfq_get_secctx(tb, &secdata);
	if (ret > 0)
		printf("secctx=\"%.*s\" ", ret, secdata);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		printf("payload_len=%d\n", ret);

		// 패킷의 악성 여부를 판단합니다.
		// 악성이라면, id를 음수로 바꿉니다.
		if (is_malicious(&data, ret, cbData)){
			id = id * (-1);
		}
	}

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	uint32_t id = print_pkt(nfa, (CbData*)data);

	// id 값이 음수, 즉 악성 패킷이라면 DROP.
	if (((CbData*)data)->isMalicious){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	// 0, NULL); -> 패킷에 변화 X. IP 헤더부터의 길이. 변조 가능.
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	uint32_t queue = 0;
	char buf[4096] __attribute__ ((aligned));

	// modify usage
	if (argc != 2) {
		fprintf(stderr, "syntax : %s <host>\n", argv[0]);
		fprintf(stderr, "sample : %s test.gilgil.net", argv[0]);
		exit(EXIT_FAILURE);
	}

	CbData cb_params;

	// make target_string like "\r\nHost: <argv[1]>"
	// sample target_string: "\r\nHost: test.gilgil.net"
	cb_params.target_string = (char*)malloc(strlen("\r\nHost: ") + strlen(argv[1]));
	memcpy(cb_params.target_string, "\r\nHost: ", strlen("\r\nHost: "));
	memcpy(cb_params.target_string + strlen("\r\nHost: "), argv[1], strlen(argv[1]));
	cb_params.ctx = BoyerMooreCtxInit((uint8_t*)cb_params.target_string, strlen(cb_params.target_string));
	cb_params.isMalicious = false;

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		BoyerMooreCtxDeInit(cb_params.ctx);
		free(cb_params.target_string);
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		BoyerMooreCtxDeInit(cb_params.ctx);
		free(cb_params.target_string);
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		BoyerMooreCtxDeInit(cb_params.ctx);
		free(cb_params.target_string);
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", queue);
	qh = nfq_create_queue(h, queue, &cb, &cb_params);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		BoyerMooreCtxDeInit(cb_params.ctx);
		free(cb_params.target_string);
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		BoyerMooreCtxDeInit(cb_params.ctx);
		free(cb_params.target_string);
		exit(1);
	}

	printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	BoyerMooreCtxDeInit(cb_params.ctx);
	free(cb_params.target_string);
	exit(0);
}
