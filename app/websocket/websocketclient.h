/* Websocket client implementation
 *
 * Copyright (c) 2016 Luís Fonseca <miguelluisfonseca@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _WEBSOCKET_H_
#define _WEBSOCKET_H_

#include "osapi.h"
#include "user_interface.h"
#include "espconn.h"
#include "mem.h"
#include "limits.h"
#include "stdlib.h"

#if defined(USES_SDK_BEFORE_V140)
#define espconn_send espconn_sent
#define espconn_secure_send espconn_secure_sent
#endif

struct wsc_info; // client info
struct wss_info; // server info

typedef void (*wsc_onConnectionCallback)(struct wsc_info *wscInfo);
typedef void (*wsc_onReceiveCallback)(struct wsc_info *wscInfo, char *message, int opCode);
typedef void (*wsc_onFailureCallback)(struct wsc_info *wscInfo, int errorCode);

typedef struct wsc_info *(*wss_onNewClientConnectionCallback)(void *reservedData);

typedef struct wss_info {
  int state;

  int port;

  struct espconn *conn;
  void *reservedData;

  wss_onNewClientConnectionCallback onNewClientConnection;
} wss_info;

typedef struct wsc_info {
  int connectionState;

  bool isSecure;
  char *hostname;
  int port;
  char *path;
  char *expectedSecKey;
  bool applyMask;

  struct espconn *conn;
  wss_info *serverInfo;
  void *reservedData;
  int knownFailureCode;

  char *frameBuffer;
  int frameBufferLen;

  char *payloadBuffer;
  int payloadBufferLen;
  int payloadOriginalOpCode;

  os_timer_t  timeoutTimer;
  int unhealthyPoints;

  wsc_onConnectionCallback onConnection;
  wsc_onReceiveCallback onReceive;
  wsc_onFailureCallback onFailure;
} wsc_info;


/*
 * Attempts to estabilish a websocket connection to the given url.
 */
void wsc_connect(wsc_info *wscInfo, const char *url);

/*
 * Sends a message with a given opcode.
 */
void wsc_send(wsc_info *wscInfo, int opCode, const char *message, unsigned short length);

/*
 * Disconnects existing conection and frees memory.
 */
void wsc_close(wsc_info *wscInfo);

/*
 * Starts the server to listen to the configured port.
 */
void wss_start(wss_info *wssInfo);

/*
 * Closes all existing websockets connections and then the server itself.
 */
void wss_close(wss_info *wssInfo);

#endif // _WEBSOCKET_H_
