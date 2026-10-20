/* SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
 * SPDX-License-Identifier: GPL-3.0-only */

/* ghost's PC/SC reader driver (gdp-spec.md §8.8, docs/adr/0017): a
 * pcsc-lite IFD handler whose readers are a client's, forwarded into the
 * session. The session's own pcscd, which wraith runs, loads it for each
 * entry wraith writes in its reader configuration; the entry's DEVICENAME
 * is a Unix socket wraith serves, and every call here is one request
 * there (ghost_ifd.h). The driver keeps nothing but the ATR, for pcscd's
 * GetCapabilities.
 *
 * pcscd calls one reader from one thread at a time, and different readers
 * from different threads: one mutex per reader. A connection is made on
 * first use and again after any failure, so wraith may come and go. */
#include "ghost_ifd.h"

#include <PCSC/debuglog.h>
#include <PCSC/ifdhandler.h>
#include <PCSC/reader.h>

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

/* pcscd's own limit on readers. */
#define MAX_READERS 16
/* Longer than any prompt the client shows and any touch a card waits for:
 * a reply that takes this long isn't coming. */
#define REPLY_TIMEOUT_S 120

struct reader {
	pthread_mutex_t mutex;
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
	int fd;
	unsigned char atr[MAX_ATR_SIZE];
	DWORD atr_len;
};

static struct reader readers[MAX_READERS];
static pthread_once_t readers_once = PTHREAD_ONCE_INIT;

static void init_readers(void) {
	for (int i = 0; i < MAX_READERS; i++) {
		pthread_mutex_init(&readers[i].mutex, NULL);
		readers[i].fd = -1;
	}
}

static struct reader *reader_for(DWORD lun) {
	pthread_once(&readers_once, init_readers);
	DWORD i = lun >> 16;
	return i < MAX_READERS ? &readers[i] : NULL;
}

static int transfer(int fd, void *buf, size_t n, int writing) {
	unsigned char *p = buf;
	while (n > 0) {
		ssize_t r = writing ? send(fd, p, n, MSG_NOSIGNAL) : recv(fd, p, n, 0);
		if (r < 0 && errno == EINTR) {
			continue;
		}
		if (r <= 0) {
			return -1;
		}
		p += r;
		n -= (size_t)r;
	}
	return 0;
}

static int connect_reader(struct reader *r) {
	if (r->fd >= 0) {
		return 0;
	}
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof addr);
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, r->path, sizeof addr.sun_path);
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		return -1;
	}
	struct timeval tv = {REPLY_TIMEOUT_S, 0};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
		close(fd);
		return -1;
	}
	r->fd = fd;
	return 0;
}

/* One request and its reply, with the reader's mutex held. Returns the
 * reply's status, or -1 if wraith couldn't be reached or answered
 * nonsense. `*out_len` is the room in `out`, then the payload's length. */
static int call(struct reader *r, uint8_t op, const void *in, uint32_t in_len, void *out, uint32_t *out_len) {
	if (connect_reader(r) < 0) {
		return -1;
	}
	unsigned char head[GHOST_IFD_HEADER] = {op, (unsigned char)in_len, (unsigned char)(in_len >> 8),
		(unsigned char)(in_len >> 16), (unsigned char)(in_len >> 24)};
	unsigned char reply[GHOST_IFD_HEADER];
	int status = -1;
	if (transfer(r->fd, head, sizeof head, 1) == 0 && (in_len == 0 || transfer(r->fd, (void *)in, in_len, 1) == 0) &&
		transfer(r->fd, reply, sizeof reply, 0) == 0) {
		uint32_t n = reply[1] | reply[2] << 8 | reply[3] << 16 | (uint32_t)reply[4] << 24;
		uint32_t room = out_len ? *out_len : 0;
		if (n <= room && (n == 0 || transfer(r->fd, out, n, 0) == 0)) {
			if (out_len) {
				*out_len = n;
			}
			status = reply[0];
		}
	}
	if (status < 0) {
		close(r->fd);
		r->fd = -1;
	}
	return status;
}

RESPONSECODE IFDHCreateChannelByName(DWORD Lun, LPSTR DeviceName) {
	struct reader *r = reader_for(Lun);
	if (!r || strlen(DeviceName) >= sizeof r->path) {
		return IFD_COMMUNICATION_ERROR;
	}
	pthread_mutex_lock(&r->mutex);
	memset(r->path, 0, sizeof r->path);
	strcpy(r->path, DeviceName);
	r->atr_len = 0;
	if (r->fd >= 0) {
		close(r->fd);
		r->fd = -1;
	}
	pthread_mutex_unlock(&r->mutex);
	Log3(PCSC_LOG_INFO, "ghost reader %lu on %s", (unsigned long)(Lun >> 16), DeviceName);
	return IFD_SUCCESS;
}

RESPONSECODE IFDHCreateChannel(DWORD Lun, DWORD Channel) {
	(void)Lun;
	(void)Channel;
	return IFD_COMMUNICATION_ERROR; /* only DEVICENAME */
}

RESPONSECODE IFDHCloseChannel(DWORD Lun) {
	struct reader *r = reader_for(Lun);
	if (!r) {
		return IFD_COMMUNICATION_ERROR;
	}
	pthread_mutex_lock(&r->mutex);
	if (r->fd >= 0) {
		close(r->fd);
		r->fd = -1;
	}
	r->atr_len = 0;
	pthread_mutex_unlock(&r->mutex);
	return IFD_SUCCESS;
}

RESPONSECODE IFDHGetCapabilities(DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value) {
	struct reader *r = reader_for(Lun);
	if (!r) {
		return IFD_COMMUNICATION_ERROR;
	}
	RESPONSECODE rv = IFD_SUCCESS;
	switch (Tag) {
	case TAG_IFD_ATR:
	case SCARD_ATTR_ATR_STRING:
		pthread_mutex_lock(&r->mutex);
		if (*Length < r->atr_len) {
			rv = IFD_ERROR_INSUFFICIENT_BUFFER;
		} else {
			memcpy(Value, r->atr, r->atr_len);
			*Length = r->atr_len;
		}
		pthread_mutex_unlock(&r->mutex);
		return rv;
	case TAG_IFD_SLOTS_NUMBER:
	case TAG_IFD_SIMULTANEOUS_ACCESS:
		if (*Length < 1) {
			return IFD_ERROR_INSUFFICIENT_BUFFER;
		}
		*Length = 1;
		*Value = Tag == TAG_IFD_SLOTS_NUMBER ? 1 : MAX_READERS;
		return IFD_SUCCESS;
	case TAG_IFD_THREAD_SAFE: /* readers apart, yes */
	case TAG_IFD_SLOT_THREAD_SAFE:
		if (*Length < 1) {
			return IFD_ERROR_INSUFFICIENT_BUFFER;
		}
		*Length = 1;
		*Value = Tag == TAG_IFD_THREAD_SAFE ? 1 : 0;
		return IFD_SUCCESS;
	}
	return IFD_ERROR_TAG;
}

RESPONSECODE IFDHSetCapabilities(DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value) {
	(void)Lun;
	(void)Tag;
	(void)Length;
	(void)Value;
	return IFD_ERROR_TAG;
}

RESPONSECODE IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol, UCHAR Flags, UCHAR PTS1, UCHAR PTS2, UCHAR PTS3) {
	(void)Lun;
	(void)Flags;
	(void)PTS1;
	(void)PTS2;
	(void)PTS3;
	/* The client's own PC/SC stack speaks the card's protocol; whole APDUs
	 * cross the network either way. */
	return Protocol == SCARD_PROTOCOL_T0 || Protocol == SCARD_PROTOCOL_T1 ? IFD_SUCCESS
																		  : IFD_PROTOCOL_NOT_SUPPORTED;
}

static RESPONSECODE failure(int status) {
	return status == GHOST_IFD_NO_CARD ? IFD_ICC_NOT_PRESENT : IFD_COMMUNICATION_ERROR;
}

RESPONSECODE IFDHPowerICC(DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength) {
	struct reader *r = reader_for(Lun);
	if (!r) {
		return IFD_COMMUNICATION_ERROR;
	}
	uint8_t op;
	switch (Action) {
	case IFD_POWER_UP: op = GHOST_IFD_POWER_UP; break;
	case IFD_RESET: op = GHOST_IFD_RESET; break;
	case IFD_POWER_DOWN: op = GHOST_IFD_POWER_DOWN; break;
	default: return IFD_NOT_SUPPORTED;
	}
	pthread_mutex_lock(&r->mutex);
	unsigned char atr[MAX_ATR_SIZE];
	uint32_t n = sizeof atr;
	int status = call(r, op, NULL, 0, atr, &n);
	RESPONSECODE rv = IFD_SUCCESS;
	r->atr_len = 0;
	*AtrLength = 0;
	if (status != GHOST_IFD_OK) {
		rv = Action == IFD_POWER_DOWN ? IFD_SUCCESS : failure(status);
	} else if (op != GHOST_IFD_POWER_DOWN) {
		if (n == 0) {
			rv = IFD_COMMUNICATION_ERROR;
		} else {
			memcpy(r->atr, atr, n);
			r->atr_len = n;
			memcpy(Atr, atr, n);
			*AtrLength = n;
		}
	}
	pthread_mutex_unlock(&r->mutex);
	return rv;
}

RESPONSECODE IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer,
	PDWORD RxLength, PSCARD_IO_HEADER RecvPci) {
	struct reader *r = reader_for(Lun);
	if (!r) {
		return IFD_COMMUNICATION_ERROR;
	}
	if (TxLength > GHOST_IFD_MAX_PAYLOAD) {
		*RxLength = 0;
		return IFD_COMMUNICATION_ERROR;
	}
	pthread_mutex_lock(&r->mutex);
	uint32_t n = (uint32_t)*RxLength;
	int status = call(r, GHOST_IFD_TRANSMIT, TxBuffer, (uint32_t)TxLength, RxBuffer, &n);
	pthread_mutex_unlock(&r->mutex);
	if (status != GHOST_IFD_OK) {
		*RxLength = 0;
		return failure(status);
	}
	*RxLength = n;
	if (RecvPci) {
		RecvPci->Protocol = SendPci.Protocol;
		RecvPci->Length = 0;
	}
	return IFD_SUCCESS;
}

RESPONSECODE IFDHControl(DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength, PUCHAR RxBuffer,
	DWORD RxLength, LPDWORD pdwBytesReturned) {
	(void)Lun;
	(void)TxBuffer;
	(void)TxLength;
	(void)RxBuffer;
	(void)RxLength;
	*pdwBytesReturned = 0;
	/* No PIN pad and no other reader features: an empty list says so. */
	return dwControlCode == CM_IOCTL_GET_FEATURE_REQUEST ? IFD_SUCCESS : IFD_ERROR_NOT_SUPPORTED;
}

RESPONSECODE IFDHICCPresence(DWORD Lun) {
	struct reader *r = reader_for(Lun);
	if (!r) {
		return IFD_COMMUNICATION_ERROR;
	}
	pthread_mutex_lock(&r->mutex);
	unsigned char present = 0;
	uint32_t n = 1;
	int status = call(r, GHOST_IFD_PRESENCE, NULL, 0, &present, &n);
	pthread_mutex_unlock(&r->mutex);
	return status == GHOST_IFD_OK && n == 1 && present ? IFD_ICC_PRESENT : IFD_ICC_NOT_PRESENT;
}
