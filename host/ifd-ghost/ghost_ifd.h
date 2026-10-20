/* SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
 * SPDX-License-Identifier: GPL-3.0-only */

/* The local protocol between ghost's PC/SC reader driver (ifd_ghost.c,
 * loaded by the session's own pcscd) and wraith (session/smartcards.hpp),
 * over the reader's Unix socket, its DEVICENAME. One request at a time per
 * connection, each answered once:
 *
 *   request: u8 op,     u32 length (little-endian), payload
 *   reply:   u8 status, u32 length (little-endian), payload
 *
 * PRESENCE   -> 1 byte, 1 if a card is in the reader (answered by wraith
 *               from what the client last said, never over the network)
 * POWER_UP   -> the ATR (a powered card is reset)
 * RESET      -> the ATR
 * POWER_DOWN -> nothing
 * TRANSMIT   a command APDU -> the response APDU, status word last
 *
 * C, so the driver needs no C++ runtime inside pcscd. */
#ifndef GHOST_IFD_H
#define GHOST_IFD_H

#define GHOST_IFD_PRESENCE 1
#define GHOST_IFD_POWER_UP 2
#define GHOST_IFD_POWER_DOWN 3
#define GHOST_IFD_TRANSMIT 4
#define GHOST_IFD_RESET 5

#define GHOST_IFD_OK 0
#define GHOST_IFD_NO_CARD 1
#define GHOST_IFD_FAILED 2

#define GHOST_IFD_HEADER 5
/* An extended command APDU, the largest payload either way. */
#define GHOST_IFD_MAX_PAYLOAD 65544

#endif
