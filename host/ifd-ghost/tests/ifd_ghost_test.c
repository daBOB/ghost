/* SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
 * SPDX-License-Identifier: GPL-3.0-only */

/* ifd_ghost.c against a fake wraith on a Unix socket: presence, power,
 * transmit, a dropped connection, and two readers at once. */
#include "ghost_ifd.h"

#include <PCSC/ifdhandler.h>

#undef NDEBUG
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* pcscd provides this to the drivers it loads. */
void log_msg(const int priority, const char *fmt, ...) {
	(void)priority;
	(void)fmt;
}

static const unsigned char kAtr[] = {0x3b, 0xfd, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x15, 0x80, 0x73, 0xc0,
	0x21, 0xc0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4b, 0x65, 0x79, 0x40};

struct fake {
	int listener;
	int present;
	int drop_after; /* requests to answer before hanging up, or -1 */
	int requests;
	char last_op;
};

static int read_all(int fd, void *buf, size_t n) {
	unsigned char *p = buf;
	while (n > 0) {
		ssize_t r = read(fd, p, n);
		if (r <= 0) {
			return -1;
		}
		p += r;
		n -= (size_t)r;
	}
	return 0;
}

static void reply(int fd, uint8_t status, const void *data, uint32_t n) {
	unsigned char head[5] = {status, (unsigned char)n, (unsigned char)(n >> 8), (unsigned char)(n >> 16),
		(unsigned char)(n >> 24)};
	assert(write(fd, head, 5) == 5);
	if (n) {
		assert(write(fd, data, n) == (ssize_t)n);
	}
}

static void *serve(void *arg) {
	struct fake *f = arg;
	for (;;) {
		int fd = accept(f->listener, NULL, NULL);
		if (fd < 0) {
			return NULL;
		}
		unsigned char head[5];
		static unsigned char payload[GHOST_IFD_MAX_PAYLOAD + 2];
		while (read_all(fd, head, 5) == 0) {
			uint32_t n = head[1] | head[2] << 8 | head[3] << 16 | (uint32_t)head[4] << 24;
			assert(n <= GHOST_IFD_MAX_PAYLOAD);
			if (n && read_all(fd, payload, n) < 0) {
				break;
			}
			f->last_op = (char)head[0];
			if (f->drop_after >= 0 && f->requests++ >= f->drop_after) {
				f->drop_after = -1;
				break;
			}
			switch (head[0]) {
			case GHOST_IFD_PRESENCE: {
				unsigned char p = (unsigned char)f->present;
				reply(fd, GHOST_IFD_OK, &p, 1);
				break;
			}
			case GHOST_IFD_POWER_UP:
			case GHOST_IFD_RESET:
				if (f->present) {
					reply(fd, GHOST_IFD_OK, kAtr, sizeof kAtr);
				} else {
					reply(fd, GHOST_IFD_NO_CARD, NULL, 0);
				}
				break;
			case GHOST_IFD_POWER_DOWN: reply(fd, GHOST_IFD_OK, NULL, 0); break;
			case GHOST_IFD_TRANSMIT:
				/* Echo the APDU, then 90 00. */
				payload[n] = 0x90;
				payload[n + 1] = 0x00;
				reply(fd, GHOST_IFD_OK, payload, n + 2);
				break;
			default: reply(fd, GHOST_IFD_FAILED, NULL, 0);
			}
		}
		close(fd);
	}
}

static void start_fake(struct fake *f, const char *path) {
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof addr.sun_path - 1);
	unlink(path);
	f->listener = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(bind(f->listener, (struct sockaddr *)&addr, sizeof addr) == 0);
	assert(listen(f->listener, 4) == 0);
	pthread_t t;
	assert(pthread_create(&t, NULL, serve, f) == 0);
	pthread_detach(t);
}

int main(void) {
	char dir[] = "/tmp/ifd_ghost_test.XXXXXX";
	assert(mkdtemp(dir));
	char path0[256], path1[256], missing[256];
	snprintf(path0, sizeof path0, "%s/reader-0.sock", dir);
	snprintf(path1, sizeof path1, "%s/reader-1.sock", dir);
	snprintf(missing, sizeof missing, "%s/missing.sock", dir);

	struct fake f0 = {.present = 1, .drop_after = -1}, f1 = {.present = 0, .drop_after = -1};
	start_fake(&f0, path0);
	start_fake(&f1, path1);
	const DWORD lun0 = 0, lun1 = 1 << 16, lun2 = 2 << 16;
	assert(IFDHCreateChannelByName(lun0, path0) == IFD_SUCCESS);
	assert(IFDHCreateChannelByName(lun1, path1) == IFD_SUCCESS);
	assert(IFDHCreateChannelByName(lun2, missing) == IFD_SUCCESS);

	/* Presence comes from wraith; nobody there reads as no card. */
	assert(IFDHICCPresence(lun0) == IFD_ICC_PRESENT);
	assert(IFDHICCPresence(lun1) == IFD_ICC_NOT_PRESENT);
	assert(IFDHICCPresence(lun2) == IFD_ICC_NOT_PRESENT);

	UCHAR atr[MAX_ATR_SIZE];
	DWORD atr_len = sizeof atr;
	assert(IFDHPowerICC(lun0, IFD_POWER_UP, atr, &atr_len) == IFD_SUCCESS);
	assert(atr_len == sizeof kAtr && memcmp(atr, kAtr, atr_len) == 0);
	UCHAR cap[MAX_ATR_SIZE];
	DWORD cap_len = sizeof cap;
	assert(IFDHGetCapabilities(lun0, TAG_IFD_ATR, &cap_len, cap) == IFD_SUCCESS);
	assert(cap_len == sizeof kAtr);
	atr_len = sizeof atr;
	assert(IFDHPowerICC(lun1, IFD_POWER_UP, atr, &atr_len) == IFD_ICC_NOT_PRESENT && atr_len == 0);
	atr_len = sizeof atr;
	assert(IFDHPowerICC(lun2, IFD_POWER_UP, atr, &atr_len) == IFD_COMMUNICATION_ERROR);

	SCARD_IO_HEADER pci = {SCARD_PROTOCOL_T1, 0}, rpci;
	UCHAR select[] = {0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08};
	UCHAR rx[GHOST_IFD_MAX_PAYLOAD + 2];
	DWORD rx_len = sizeof rx;
	assert(IFDHTransmitToICC(lun0, pci, select, sizeof select, rx, &rx_len, &rpci) == IFD_SUCCESS);
	assert(rx_len == sizeof select + 2 && memcmp(rx, select, sizeof select) == 0 && rx[rx_len - 2] == 0x90);
	assert(rpci.Protocol == SCARD_PROTOCOL_T1);

	/* An extended APDU, the largest there is. */
	static UCHAR big[GHOST_IFD_MAX_PAYLOAD];
	memset(big, 0x5a, sizeof big);
	rx_len = sizeof rx;
	assert(IFDHTransmitToICC(lun0, pci, big, sizeof big, rx, &rx_len, &rpci) == IFD_SUCCESS);
	assert(rx_len == sizeof big + 2);
	/* A response bigger than pcscd's buffer is an error, not an overflow. */
	rx_len = 16;
	assert(IFDHTransmitToICC(lun0, pci, big, 64, rx, &rx_len, &rpci) == IFD_COMMUNICATION_ERROR);

	/* wraith hangs up: that call fails, and the next reconnects. */
	f0.drop_after = 0;
	f0.requests = 0;
	rx_len = sizeof rx;
	assert(IFDHTransmitToICC(lun0, pci, select, sizeof select, rx, &rx_len, &rpci) == IFD_COMMUNICATION_ERROR);
	rx_len = sizeof rx;
	assert(IFDHTransmitToICC(lun0, pci, select, sizeof select, rx, &rx_len, &rpci) == IFD_SUCCESS);

	atr_len = sizeof atr;
	assert(IFDHPowerICC(lun0, IFD_POWER_DOWN, atr, &atr_len) == IFD_SUCCESS && atr_len == 0);
	assert(f0.last_op == GHOST_IFD_POWER_DOWN);
	cap_len = sizeof cap;
	assert(IFDHGetCapabilities(lun0, TAG_IFD_ATR, &cap_len, cap) == IFD_SUCCESS && cap_len == 0);

	assert(IFDHSetProtocolParameters(lun0, SCARD_PROTOCOL_T0, 0, 0, 0, 0) == IFD_SUCCESS);
	assert(IFDHSetProtocolParameters(lun0, SCARD_PROTOCOL_RAW, 0, 0, 0, 0) == IFD_PROTOCOL_NOT_SUPPORTED);
	assert(IFDHCloseChannel(lun0) == IFD_SUCCESS);
	assert(IFDHCloseChannel(lun1) == IFD_SUCCESS);

	unlink(path0);
	unlink(path1);
	rmdir(dir);
	printf("ifd_ghost_test: ok\n");
	return 0;
}
