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

#include "osapi.h"
#include "user_interface.h"
#include "espconn.h"
#include "mem.h"
#include "limits.h"
#include "stdlib.h"

#include "c_types.h"
#include "c_string.h"
#include "c_stdlib.h"
#include "c_stdio.h"

#include "websocketclient.h"

// Depends on 'crypto' module for sha1
#include "../crypto/digests.h"
#include "../crypto/mech.h"

#define PROTOCOL_SECURE "wss://"
#define PROTOCOL_INSECURE "ws://"

#define PORT_SECURE 443
#define PORT_INSECURE 80
#define PORT_MAX_VALUE 65535

#define SSL_BUFFER_SIZE 5120

// TODO: user agent configurable
#define WS_INIT_HEADERS  "GET %s HTTP/1.1\r\n"\
                         "Host: %s:%d\r\n"\
                         "Upgrade: websocket\r\n"\
                         "Connection: Upgrade\r\n"\
                         "User-Agent: ESP8266\r\n"\
                         "Sec-Websocket-Key: %s\r\n"\
                         "Sec-WebSocket-Protocol: chat\r\n"\
                         "Sec-WebSocket-Version: 13\r\n"\
                         "\r\n"
#define WS_INIT_HEADERS_LENGTH 169

#define WS_INIT_SERVER_HEADERS "HTTP/1.1 101 Switching Protocols\r\n"\
                               "Upgrade: websocket\r\n"\
                               "Connection: Upgrade\r\n"\
                               "Sec-WebSocket-Accept: %s\r\n"\
                               "%s"\
                               "\r\n"
#define WS_INIT_SERVER_HEADERS_LENGTH 129

#define WS_HTTP_UPGRADE_WEBSOCKET "Upgrade: websocket\r\n"
#define WS_HTTP_CONNECTION_UPGRADE "Connection: Upgrade\r\n"
#define WS_HTTP_SEC_WEBSOCKET_KEY "Sec-Websocket-Key:"
#define WS_HTTP_SEC_WEBSOCKET_KEY_LENGTH 21

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_GUID_LENGTH 36

#define WS_HTTP_SWITCH_PROTOCOL_HEADER "HTTP/1.1 101"
#define WS_HTTP_SEC_WEBSOCKET_ACCEPT "Sec-WebSocket-Accept:"

#define WS_SERVER_CONNECT_TIMEOUT_MS 30 * 1000
#define WS_CONNECT_TIMEOUT_MS 10 * 1000
#define WS_PING_INTERVAL_MS 30 * 1000
#define WS_FORCE_CLOSE_TIMEOUT_MS 5 * 1000
#define WS_UNHEALTHY_THRESHOLD 2

#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA

static char *cryptoSha1(char *data, unsigned int len) {
  SHA1_CTX ctx;
  SHA1Init(&ctx);
  SHA1Update(&ctx, data, len);
  
  uint8_t *digest = (uint8_t *) c_zalloc(20);
  SHA1Final(digest, &ctx);
  return (char *) digest; // Requires free
}

static const char *bytes64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64Encode(char *data, unsigned int len) {
  int blen = (len + 2) / 3 * 4;

  char *out = (char *) c_zalloc(blen + 1);
  out[blen] = '\0';
  int j = 0, i;
  for (i = 0; i < len; i += 3) {
    int a = data[i];
    int b = (i + 1 < len) ? data[i + 1] : 0;
    int c = (i + 2 < len) ? data[i + 2] : 0;
    out[j++] = bytes64[a >> 2];
    out[j++] = bytes64[((a & 3) << 4) | (b >> 4)];
    out[j++] = (i + 1 < len) ? bytes64[((b & 15) << 2) | (c >> 6)] : 61;
    out[j++] = (i + 2 < len) ? bytes64[(c & 63)] : 61;
  }

  return out; // Requires free
}

static void generateSecAcceptKey(const char *key, char **expectedKey) {
  // expectedKey = b64(sha1(keyB64 + GUID))
  char keyWithGuid[24 + WS_GUID_LENGTH];
  memcpy(keyWithGuid, key, 24);
  memcpy(keyWithGuid + 24, WS_GUID, WS_GUID_LENGTH);

  char *keyEncrypted = cryptoSha1(keyWithGuid, 24 + WS_GUID_LENGTH);
  *expectedKey = base64Encode(keyEncrypted, 20);

  os_free(keyEncrypted);
}

static void generateSecKeys(char **key, char **expectedKey) {
  char rndData[16];
  int i;
  for (i = 0; i < 16; i++) {
    rndData[i] = (char) os_random();
  }

  *key = base64Encode(rndData, 16);

  generateSecAcceptKey(*key, expectedKey);
}

static void sent_noop(void *arg) {
  NODE_DBG("sent_noop \n");
}

static void wsc_closeSentCallback(void *arg) {
  NODE_DBG("wsc_closeSentCallback \n");
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  if (ws == NULL) {
    NODE_DBG("ws is unexpectly null\n");
    return;
  }

  ws->knownFailureCode = -6;

  if (ws->isSecure)
    espconn_secure_disconnect(conn);
  else
    espconn_disconnect(conn);
}

static void wsc_sendFrame(struct espconn *conn, int opCode, const char *data, unsigned short len) {
  NODE_DBG("wsc_sendFrame %d %d\n", opCode, len);
  wsc_info *ws = (wsc_info *) conn->reverse;
  
  if (ws->connectionState == 4) {
    NODE_DBG("already in closing state\n");
    return;
  } else if (ws->connectionState != 3) {
    NODE_DBG("can't send message while not in a connected state\n");
    return;
  }

  char *b = c_zalloc(10 + len); // 10 bytes = worst case scenario for framming
  if (b == NULL) {
    NODE_DBG("Out of memory when receiving message, disconnecting...\n");

    ws->knownFailureCode = -16;
    if (ws->isSecure)
      espconn_secure_disconnect(conn);
    else
      espconn_disconnect(conn);
    return;
  }

  b[0] = 1 << 7; // has fin
  b[0] += opCode;
  b[1] = ws->applyMask << 7; // mask bit
  int bufOffset;
  if (len < 126) {
    b[1] += len;
    bufOffset = 2;
  } else if (len < 0x10000) {
    b[1] += 126;
    b[2] = len >> 8;
    b[3] = len;
    bufOffset = 4;
  } else {
    b[1] += 127;
    b[2] = len >> 24;
    b[3] = len >> 16;
    b[4] = len >> 8;
    b[5] = len;
    bufOffset = 6;
  }

  // Random mask, if needed
  if (ws->applyMask) {
    b[bufOffset] = (char) os_random();
    b[bufOffset + 1] = (char) os_random();
    b[bufOffset + 2] = (char) os_random();
    b[bufOffset + 3] = (char) os_random();
    bufOffset += 4;
  }

  // Copy data to buffer
  memcpy(b + bufOffset, data, len);

  // Apply mask to encode payload, if needed
  if (ws->applyMask) {
    int i;
    for (i = 0; i < len; i++) {
      b[bufOffset + i] ^= b[bufOffset - 4 + i % 4];
    }
  }
  bufOffset += len;

  NODE_DBG("b[0] = %d \n", b[0]);
  NODE_DBG("b[1] = %d \n", b[1]);
  NODE_DBG("b[2] = %d \n", b[2]);
  NODE_DBG("b[3] = %d \n", b[3]);
  NODE_DBG("b[4] = %d \n", b[4]);
  NODE_DBG("b[5] = %d \n", b[5]);
  NODE_DBG("b[6] = %d \n", b[6]);
  NODE_DBG("b[7] = %d \n", b[7]);
  NODE_DBG("b[8] = %d \n", b[8]);
  NODE_DBG("b[9] = %d \n", b[9]);

  NODE_DBG("sending message\n");
  if (ws->isSecure)
    espconn_secure_send(conn, (uint8_t *) b, bufOffset);
  else
    espconn_send(conn, (uint8_t *) b, bufOffset);

  os_free(b);
}

static void wsc_sendPingTimeout(void *arg) {
  NODE_DBG("wsc_sendPingTimeout \n");
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  if (ws->unhealthyPoints == WS_UNHEALTHY_THRESHOLD) {
    // several pings were sent but no pongs nor messages
    ws->knownFailureCode = -19;

    if (ws->isSecure)
      espconn_secure_disconnect(conn);
    else
      espconn_disconnect(conn);
    return;
  }

  wsc_sendFrame(conn, WS_OPCODE_PING, NULL, 0);
  ws->unhealthyPoints += 1;
}

static void wsc_receiveCallback(void *arg, char *buf, unsigned short len) {
  NODE_DBG("wsc_receiveCallback %d \n", len);
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  ws->unhealthyPoints = 0; // received data, connection is healthy
  os_timer_disarm(&ws->timeoutTimer); // reset ping check
  os_timer_arm(&ws->timeoutTimer, WS_PING_INTERVAL_MS, true);


  char *b = buf;
  if (ws->frameBuffer != NULL) { // Append previous frameBuffer with new content
    NODE_DBG("Appending new frameBuffer to old one \n");

    ws->frameBuffer = c_realloc(ws->frameBuffer, ws->frameBufferLen + len);
    if (ws->frameBuffer == NULL) {
      NODE_DBG("Failed to allocate new framebuffer, disconnecting...\n");

      ws->knownFailureCode = -8;
      if (ws->isSecure)
        espconn_secure_disconnect(conn);
      else
        espconn_disconnect(conn);
      return;
    }
    memcpy(ws->frameBuffer + ws->frameBufferLen, b, len);

    ws->frameBufferLen += len;

    len = ws->frameBufferLen;
    b = ws->frameBuffer;
    NODE_DBG("New frameBufferLen: %d\n", len);
  }

  while (b != NULL) { // several frames can be present, b pointer will be moved to the next frame
    NODE_DBG("b[0] = %d \n", b[0]);
    NODE_DBG("b[1] = %d \n", b[1]);
    NODE_DBG("b[2] = %d \n", b[2]);
    NODE_DBG("b[3] = %d \n", b[3]);
    NODE_DBG("b[4] = %d \n", b[4]);
    NODE_DBG("b[5] = %d \n", b[5]);
    NODE_DBG("b[6] = %d \n", b[6]);
    NODE_DBG("b[7] = %d \n", b[7]);

    int isFin = b[0] & 0x80 ? 1 : 0;
    int opCode = b[0] & 0x0f;
    int hasMask = b[1] & 0x80 ? 1 : 0;
    uint64_t payloadLength = b[1] & 0x7f;
    int bufOffset = 2;
    if (payloadLength == 126) {
      payloadLength = (b[2] << 8) + b[3];
      bufOffset = 4;
    } else if (payloadLength == 127) { // this will clearly not hold in heap, abort??
      payloadLength = (b[2] << 24) + (b[3] << 16) + (b[4] << 8) + b[5];
      bufOffset = 6;
    }

    if (hasMask) {
      int maskOffset = bufOffset;
      bufOffset += 4;

      int i;
      for (i = 0; i < payloadLength; i++) {
        b[bufOffset + i] ^= b[maskOffset + i % 4]; // apply mask to decode payload
      }
    }

    if (payloadLength > len - bufOffset) {
      NODE_DBG("INCOMPLETE Frame \n");
      if (ws->frameBuffer == NULL) {
        NODE_DBG("Allocing new frameBuffer \n");
        ws->frameBuffer = c_zalloc(len);
        if (ws->frameBuffer == NULL) {
          NODE_DBG("Failed to allocate framebuffer, disconnecting... \n");

          ws->knownFailureCode = -9;
          if (ws->isSecure)
            espconn_secure_disconnect(conn);
          else
            espconn_disconnect(conn);
          return;
        }
        memcpy(ws->frameBuffer, b, len);
        ws->frameBufferLen = len;
      }
      break; // since the buffer were already concat'ed, wait for the next receive
    }

    if (!isFin) {
      NODE_DBG("PARTIAL frame! Should concat payload and later restore opcode\n");
      if(ws->payloadBuffer == NULL) {
        NODE_DBG("Allocing new payloadBuffer \n");
        ws->payloadBuffer = c_zalloc(payloadLength);
        if (ws->payloadBuffer == NULL) {
          NODE_DBG("Failed to allocate payloadBuffer, disconnecting...\n");

          ws->knownFailureCode = -10;
          if (ws->isSecure)
            espconn_secure_disconnect(conn);
          else
            espconn_disconnect(conn);
          return;
        }
        memcpy(ws->payloadBuffer, b + bufOffset, payloadLength);
        ws->frameBufferLen = payloadLength;
        ws->payloadOriginalOpCode = opCode;
      } else {
        NODE_DBG("Appending new payloadBuffer to old one \n");
        ws->payloadBuffer = c_realloc(ws->payloadBuffer, ws->payloadBufferLen + payloadLength);
        if (ws->payloadBuffer == NULL) {
          NODE_DBG("Failed to allocate new framebuffer, disconnecting...\n");

          ws->knownFailureCode = -11;
          if (ws->isSecure)
            espconn_secure_disconnect(conn);
          else
            espconn_disconnect(conn);
          return;
        }
        memcpy(ws->payloadBuffer + ws->payloadBufferLen, b + bufOffset, payloadLength);

        ws->payloadBufferLen += payloadLength;
      }
    } else {
      char *payload;
      if (opCode == WS_OPCODE_CONTINUATION) {
        NODE_DBG("restoring original opcode\n");
        if (ws->payloadBuffer == NULL) {
          NODE_DBG("Got FIN continuation frame but didn't receive any beforehand, disconnecting...\n");

          ws->knownFailureCode = -15;
          if (ws->isSecure)
            espconn_secure_disconnect(conn);
          else
            espconn_disconnect(conn);
          return;
        }
        // concat buffer with payload
        payload = c_zalloc(ws->payloadBufferLen + payloadLength);

        if (payload == NULL) {
          NODE_DBG("Failed to allocate new framebuffer, disconnecting...\n");

          ws->knownFailureCode = -12;
          if (ws->isSecure)
            espconn_secure_disconnect(conn);
          else
            espconn_disconnect(conn);
          return;
        }
        memcpy(payload, ws->payloadBuffer, ws->payloadBufferLen);
        memcpy(payload + ws->payloadBufferLen, b + bufOffset, payloadLength);

        os_free(ws->payloadBuffer); // free previous buffer
        ws->payloadBuffer = NULL;

        payloadLength += ws->payloadBufferLen;
        ws->payloadBufferLen = 0;

        opCode = ws->payloadOriginalOpCode;
        ws->payloadOriginalOpCode = 0;
      } else {
        int extensionDataOffset = 0;

        if (opCode == WS_OPCODE_CLOSE && payloadLength > 0) {
          unsigned int reasonCode = b[bufOffset] << 8 + b[bufOffset + 1];
          NODE_DBG("Closing due to: %d\n", reasonCode); // Must not be shown to client as per spec
          extensionDataOffset += 2;
        }

        payload = c_zalloc(payloadLength - extensionDataOffset + 1);
        if (payload == NULL) {
          NODE_DBG("Failed to allocate payload, disconnecting...\n");

          ws->knownFailureCode = -13;
          if (ws->isSecure)
            espconn_secure_disconnect(conn);
          else
            espconn_disconnect(conn);
          return;
        }

        memcpy(payload, b + bufOffset + extensionDataOffset, payloadLength - extensionDataOffset);
        payload[payloadLength - extensionDataOffset] = '\0';
      }

      NODE_DBG("isFin %d \n", isFin);
      NODE_DBG("opCode %d \n", opCode);
      NODE_DBG("hasMask %d \n", hasMask);
      NODE_DBG("payloadLength %d \n", payloadLength);
      NODE_DBG("len %d \n", len);
      NODE_DBG("bufOffset %d \n", bufOffset);

      if (opCode == WS_OPCODE_CLOSE) {
        NODE_DBG("Closing message: %s\n", payload); // Must not be shown to client as per spec

        espconn_regist_sentcb(conn, wsc_closeSentCallback);
        wsc_sendFrame(conn, WS_OPCODE_CLOSE, (const char *) (b + bufOffset), (unsigned short) payloadLength);
        ws->connectionState = 4;
      } else if (opCode == WS_OPCODE_PING) {
        wsc_sendFrame(conn, WS_OPCODE_PONG, (const char *) (b + bufOffset), (unsigned short) payloadLength);
      } else if (opCode == WS_OPCODE_PONG) {
        // ping alarm was already reset...
      } else {
        if (ws->onReceive) ws->onReceive(ws, payload, opCode);
      }
      os_free(payload);
    }

    bufOffset += payloadLength;
    NODE_DBG("bufOffset %d \n", bufOffset);
    if (bufOffset == len) { // (bufOffset > len) won't happen here because it's being checked earlier
      b = NULL;
      if (ws->frameBuffer != NULL) { // the last frame inside buffer was processed
        os_free(ws->frameBuffer);
        ws->frameBuffer = NULL;
        ws->frameBufferLen = 0;
      }
    } else {
      len -= bufOffset;
      b += bufOffset; // move b to next frame
      if (ws->frameBuffer != NULL) {
        NODE_DBG("Reallocing frameBuffer to remove consumed frame\n");

        ws->frameBuffer = c_realloc(ws->frameBuffer, ws->frameBufferLen + len);
        if (ws->frameBuffer == NULL) {
          NODE_DBG("Failed to allocate new frame buffer, disconnecting...\n");

          ws->knownFailureCode = -14;
          if (ws->isSecure)
            espconn_secure_disconnect(conn);
          else
            espconn_disconnect(conn);
          return;
        }
        memcpy(ws->frameBuffer + ws->frameBufferLen, b, len);

        ws->frameBufferLen += len;
        b = ws->frameBuffer;
      }
    }
  }
}

static void wsc_initReceiveCallback(void *arg, char *buf, unsigned short len) {
  NODE_DBG("wsc_initReceiveCallback %d \n", len);
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  // Check server is switch protocols
  if (strstr(buf, WS_HTTP_SWITCH_PROTOCOL_HEADER) == NULL) {
      NODE_DBG("Server is not switching protocols\n");
      ws->knownFailureCode = -17;
    if (ws->isSecure)
      espconn_secure_disconnect(conn);
    else
      espconn_disconnect(conn);
    return;
  }

  // Check server has valid sec key
  if (strstr(buf, WS_HTTP_SEC_WEBSOCKET_ACCEPT) == NULL || strstr(buf, ws->expectedSecKey) == NULL) {
    NODE_DBG("Server has invalid response\n");
    ws->knownFailureCode = -7;
    if (ws->isSecure)
      espconn_secure_disconnect(conn);
    else
      espconn_disconnect(conn);
    return;
  }

  NODE_DBG("Server response is valid, it's now a websocket!\n");

  os_timer_disarm(&ws->timeoutTimer);
  os_timer_setfn(&ws->timeoutTimer, (os_timer_func_t *) wsc_sendPingTimeout, conn);
  os_timer_arm(&ws->timeoutTimer, WS_PING_INTERVAL_MS, true);

  espconn_regist_recvcb(conn, wsc_receiveCallback);

  if (ws->onConnection) ws->onConnection(ws);

  char *data = strstr(buf, "\r\n\r\n");
  unsigned short dataLength = len - (data - buf) - 4;

  NODE_DBG("dataLength = %d\n", len - (data - buf) - 4);

  if (data != NULL && dataLength > 0) { // handshake already contained a frame
    wsc_receiveCallback(arg, data + 4, dataLength);
  }
}

static void connect_callback(void *arg) {
  NODE_DBG("Connected\n");
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;
  ws->connectionState = 3;

  espconn_regist_recvcb(conn, wsc_initReceiveCallback);

  char *key;
  generateSecKeys(&key, &ws->expectedSecKey);

  char buf[WS_INIT_HEADERS_LENGTH + strlen(ws->path) + strlen(ws->hostname) + strlen(key)];
  int len = os_sprintf(buf, WS_INIT_HEADERS, ws->path, ws->hostname, ws->port, key);

  os_free(key);

  NODE_DBG("connecting\n");
  if (ws->isSecure)
    espconn_secure_send(conn, (uint8_t *) buf, len);
  else
    espconn_send(conn, (uint8_t *) buf, len);
}

static void disconnect_callback(void *arg) {
  NODE_DBG("disconnect_callback\n");
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  NODE_DBG("wsc_info *ws = %d\n", ws);
  NODE_DBG("conn %d\n", conn);

  if (ws == NULL) {
    // expected when server got an invalid connection
    return;
  }
  NODE_DBG("conn2 = %d\n", ws->conn);

  ws->connectionState = 4;

  os_timer_disarm(&ws->timeoutTimer);

  if (ws->hostname != NULL) {
    NODE_DBG("ws->hostname %d\n", ws->hostname);
    os_free(ws->hostname);
  }

  if (ws->path != NULL) {
    NODE_DBG("ws->path %d\n ", ws->path);
    os_free(ws->path);
  }

  if (ws->expectedSecKey != NULL) {
    os_free(ws->expectedSecKey);
  }

  if (ws->frameBuffer != NULL) {
    os_free(ws->frameBuffer);
  }

  if (ws->payloadBuffer != NULL) {
    os_free(ws->payloadBuffer);
  }

  if (ws->conn == conn) {
    // this will not be the case for websocketserver created connections
    // where the conn apparently is the server espconn and not the client...
    // connections created by the server are also freed internally
    if (conn->proto.tcp != NULL) {
      os_free(conn->proto.tcp);
    }

    espconn_delete(conn);

    NODE_DBG("freeing conn1 \n");

    os_free(conn);
    ws->conn = NULL;
  } else {
    // why are they reusing conns?? :(. The state should at the very least be cleared.
    NODE_DBG("Restoring serverinfo = %d \n", ws->serverInfo);
    conn->reverse = ws->serverInfo;
    espconn_regist_sentcb(conn, sent_noop); // no other way to unregister the wsc_closeSentCallback
  }

  if (ws->onFailure) {
    if (ws->knownFailureCode) ws->onFailure(ws, ws->knownFailureCode);
    else ws->onFailure(ws, -99);
  }
}

static void ws_connectTimeout(void *arg) {
  NODE_DBG("ws_connectTimeout\n");
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  ws->knownFailureCode = -18;
  disconnect_callback(arg);
}

static void error_callback(void * arg, sint8 errType) {
  NODE_DBG("error_callback %d\n", errType);
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  ws->knownFailureCode = ((int) errType) - 100;
  disconnect_callback(arg);
}

static void dns_callback(const char *hostname, ip_addr_t *addr, void *arg) {
  NODE_DBG("dns_callback\n");
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  if (ws->conn == NULL || ws->connectionState == 4) {
  	return;
  }

  if (addr == NULL)  {
    ws->knownFailureCode = -5;
    disconnect_callback(arg);
    return;
  }

  ws->connectionState = 2;

  os_memcpy(conn->proto.tcp->remote_ip, addr, 4);

  espconn_regist_connectcb(conn, connect_callback);
  espconn_regist_disconcb(conn, disconnect_callback);
  espconn_regist_reconcb(conn, error_callback);

  // Set connection timeout timer
  os_timer_disarm(&ws->timeoutTimer);
  os_timer_setfn(&ws->timeoutTimer, (os_timer_func_t *) ws_connectTimeout, conn);
  os_timer_arm(&ws->timeoutTimer, WS_CONNECT_TIMEOUT_MS, false);

  if (ws->isSecure) {
    NODE_DBG("secure connecting \n");
    espconn_secure_set_size(ESPCONN_CLIENT, SSL_BUFFER_SIZE);
    espconn_secure_connect(conn);
  }
  else {
    NODE_DBG("insecure connecting \n");
    espconn_connect(conn);
  }

  NODE_DBG("DNS found %s " IPSTR " \n", hostname, IP2STR(addr));
}

void wsc_connect(wsc_info *ws, const char *url) {
  NODE_DBG("wsc_connect called\n");

  if (ws == NULL) {
    NODE_DBG("wsc_connect wsc_info argument is null!");
    return;
  }

  if (url == NULL) {
    NODE_DBG("url is null!");
    return;
  }

  // Extract protocol - either ws or wss
  bool isSecure = c_strncasecmp(url, PROTOCOL_SECURE, strlen(PROTOCOL_SECURE)) == 0;

  if (isSecure) {
    url += strlen(PROTOCOL_SECURE);
  } else {
    if (c_strncasecmp(url, PROTOCOL_INSECURE, strlen(PROTOCOL_INSECURE)) != 0) {
      NODE_DBG("Failed to extract protocol from: %s\n", url);
      if (ws->onFailure) ws->onFailure(ws, -1);
      return;
    }
    url += strlen(PROTOCOL_INSECURE);
  }

  // Extract path - it should start with '/'
  char *path = c_strchr(url, '/');

  // Extract hostname, possibly including port
  char hostname[256];
  if (path) {
    if (path - url >= sizeof(hostname)) {
      NODE_DBG("Hostname too large");
      if (ws->onFailure) ws->onFailure(ws, -2);
      return;
    }
    memcpy(hostname, url, path - url);
    hostname[path - url] = '\0';
  } else {
    // no path found, assuming the url only refers to the hostname and possibly the port
    memcpy(hostname, url, strlen(url));
    hostname[strlen(url)] = '\0';
    path = "/";
  }

  // Extract port from hostname, if available
  char *portInHostname = strchr(hostname, ':');
  int port;
  if (portInHostname) {
    port = atoi(portInHostname + 1);
    if (port <= 0 || port > PORT_MAX_VALUE) {
      NODE_DBG("Invalid port number\n");
      if (ws->onFailure) ws->onFailure(ws, -3);
      return;
    }
    hostname[strlen(hostname) - strlen(portInHostname)] = '\0'; // remove port from hostname
  } else {
    port = isSecure ? PORT_SECURE : PORT_INSECURE;
  }

  if (strlen(hostname) == 0) {
    NODE_DBG("Failed to extract hostname\n");
    if (ws->onFailure) ws->onFailure(ws, -4);
    return;
  }

  NODE_DBG("secure protocol = %d\n", isSecure);
  NODE_DBG("hostname = %s\n", hostname);
  NODE_DBG("port = %d\n", port);
  NODE_DBG("path = %s\n", path);

  // Prepare internal wsc_info
  ws->connectionState = 1;
  ws->isSecure = isSecure;
  ws->hostname = c_strdup(hostname);
  ws->port = port;
  ws->path = c_strdup(path);
  ws->expectedSecKey = NULL;
  ws->applyMask = true;
  ws->knownFailureCode = 0;
  ws->frameBuffer = NULL;
  ws->frameBufferLen = 0;
  ws->payloadBuffer = NULL;
  ws->payloadBufferLen = 0;
  ws->payloadOriginalOpCode = 0;
  ws->unhealthyPoints = 0;
  ws->serverInfo = NULL;

  // Prepare espconn
  struct espconn *conn = (struct espconn *) c_zalloc(sizeof(struct espconn));
  conn->type = ESPCONN_TCP;
  conn->state = ESPCONN_NONE;
  conn->proto.tcp = (esp_tcp *) c_zalloc(sizeof(esp_tcp));
  conn->proto.tcp->local_port = espconn_port();
  conn->proto.tcp->remote_port = ws->port;
  
  conn->reverse = ws;
  ws->conn = conn;

  // Attempt to resolve hostname address
  ip_addr_t  addr;
  err_t result = espconn_gethostbyname(conn, hostname, &addr, dns_callback);

  if (result == ESPCONN_INPROGRESS) {
    NODE_DBG("DNS pending\n");
  } else {
    dns_callback(hostname, &addr, conn);
  }

  return;
}

void wsc_send(wsc_info *ws, int opCode, const char *message, unsigned short length) {
  NODE_DBG("wsc_send\n");
  wsc_sendFrame(ws->conn, opCode, message, length);
}

static void wsc_forceCloseTimeout(void *arg) {
  NODE_DBG("wsc_forceCloseTimeout\n");
  struct espconn *conn = (struct espconn *) arg;
  wsc_info *ws = (wsc_info *) conn->reverse;

  if (ws->connectionState == 0 || ws->connectionState == 4) {
    return;
  }

  if (ws->isSecure)
    espconn_secure_disconnect(ws->conn);
  else
    espconn_disconnect(ws->conn);
}

void wsc_close(wsc_info *ws) {
  NODE_DBG("wsc_close\n");

  if (ws->connectionState == 0 || ws->connectionState == 4) {
    return;
  }

  ws->knownFailureCode = 0; // no error as user requested to close
  if (ws->connectionState == 1) {
    disconnect_callback(ws->conn);
  } else {
    wsc_sendFrame(ws->conn, WS_OPCODE_CLOSE, NULL, 0);

    os_timer_disarm(&ws->timeoutTimer);
    os_timer_setfn(&ws->timeoutTimer, (os_timer_func_t *) wsc_forceCloseTimeout, ws->conn);
    os_timer_arm(&ws->timeoutTimer, WS_FORCE_CLOSE_TIMEOUT_MS, false);
  }
}

bool check_header_present(const char *headers,
                          const char *header, const char *headerLowercase,
                          const char *value, const char *valueLowercase) {
  char *cursor = strstr(headers, header);
  if (cursor == NULL) {
    cursor = strstr(headers, headerLowercase);
  }

  if (cursor == NULL) {
    NODE_DBG("HEADER NOT FOUND \n");
    return false;
  }

  cursor += strlen(header);
  cursor += 1; // skipping the ':'

  // skip spaces, if any
  while (*cursor == ' ') {
    cursor++;
  }

  int valueLength = strlen(value);

  return c_strncmp(cursor, value, valueLength) == 0 ||
         c_strncmp(cursor, valueLowercase, valueLength) == 0;
}

void wss_initReceiveCallback(void *arg, char *buf, unsigned short len) {
  NODE_DBG("wss_initReceiveCallback %d \n", len);
  NODE_DBG("conn %d \n", arg);
  struct espconn *conn = (struct espconn *) arg;
  wss_info *wss = (wss_info *) conn->reverse;
  NODE_DBG("wss = %d\n", wss);
  NODE_DBG("conn2 = %d\n", wss->conn); // server conns
  //conn->reverse = NULL; //todo: change this; remove wss_info reference, but will store wsc_info later

  // Check if it's a get request and HTTP/1.1
  if (c_strncasecmp(buf, "GET ", 4) != 0 || strstr(buf, "HTTP/1.1\r\n") == NULL) {
    NODE_DBG("Rejecting client for invalid request (not a GET request nor HTTP/1.1).\n");
    espconn_disconnect(conn);
    return;
  }

  // Check if contains headers
  if (!check_header_present(buf, "\r\nUpgrade", "\r\nupgrade", "Websocket", "websocket") ||
      !check_header_present(buf, "\r\nConnection", "\r\nconnection", "Upgrade", "upgrade")) {
    NODE_DBG("Rejecting client for missing headers.\n");
    espconn_disconnect(conn);
    return;
  }

  // Extract key
  char *secKey = strstr(buf, "Sec-WebSocket-Key:");
  if (secKey == NULL) {
    secKey = strstr(buf, "sec-websocket-key:");
  }

  if (secKey == NULL) {
    NODE_DBG("Rejecting client for missing Sec-WebSocket-Key.\n");
    espconn_disconnect(conn);
    return;
  }

  secKey += strlen("Sec-WebSocket-Key:");

  // skip spaces, if any
  while (*secKey == ' ') {
    secKey++;
  }

  char *secKeyEnd = c_strchr(secKey, '\r');
  *secKeyEnd = '\0';

  // Extract the path
  char *path = buf + strlen("GET ");
  char *pathEnd = c_strchr(path, ' ');
  *pathEnd = '\0';

  if (strlen(path) == 0) {
    NODE_DBG("Rejecting client for missing path.\n");
    espconn_disconnect(conn);
    return;
  }

  NODE_DBG("Path = %s \n", path);
  NODE_DBG("SKey(%d) = %s \n", strlen(secKey), secKey);

  // Generate accept key
  char *acceptKey = NULL;
  generateSecAcceptKey(secKey, &acceptKey);
  NODE_DBG("Accept key = %s \n", acceptKey);

  // Send response to client
  char responseBuf[WS_INIT_SERVER_HEADERS_LENGTH + strlen(acceptKey)];
  int responseLen = os_sprintf(responseBuf, WS_INIT_SERVER_HEADERS, acceptKey, "");

  os_free(acceptKey);

  NODE_DBG("sending response...\n");
  espconn_send(conn, (uint8_t *) responseBuf, responseLen);

  // Prepare internal wsc_info
  NODE_DBG("Prepare internal wsc_info...\n");
  wsc_info *ws = wss->onNewClientConnection(wss->reservedData);

  if (ws == NULL) { // most likely due to out of memory
    NODE_DBG("Failed receive wsc_info\n");
    espconn_disconnect(conn);
    return;
  }

  NODE_DBG("Prepare internal wsc_info2...\n");
  ws->connectionState = 3;
  ws->isSecure = false;
  ws->hostname = NULL;
  ws->port = conn->proto.tcp->local_port;
  ws->path = NULL;
  ws->expectedSecKey = NULL;
  ws->applyMask = false; // websocket servers must not apply masking
  ws->knownFailureCode = 0;
  ws->frameBuffer = NULL;
  ws->frameBufferLen = 0;
  ws->payloadBuffer = NULL;
  ws->payloadBufferLen = 0;
  ws->payloadOriginalOpCode = 0;
  ws->unhealthyPoints = 0;
  ws->conn = conn;
  ws->serverInfo = wss;
  conn->reverse = ws;
  NODE_DBG("wsc_info *ws = %d\n", ws);

  os_timer_setfn(&ws->timeoutTimer, (os_timer_func_t *) wsc_sendPingTimeout, conn);
  os_timer_arm(&ws->timeoutTimer, WS_PING_INTERVAL_MS, true);

  espconn_regist_recvcb(conn, wsc_receiveCallback);
}


void server_client_connected_callback(void *arg) {
  NODE_DBG("server_client_connected_callback\n");

  struct espconn *conn = (struct espconn *) arg;
  NODE_DBG("conn %d\n", conn);

  espconn_regist_recvcb(conn, wss_initReceiveCallback);
  espconn_regist_disconcb(conn, disconnect_callback);
  espconn_regist_reconcb(conn, error_callback);
}

void wss_start(wss_info *wss) {
  NODE_DBG("wss_start\n");

  if (wss->state == 1) {
    NODE_DBG("already started...\n");
    return;
  }

  wss->state = 1;

  // Prepare espconn
  struct espconn *conn = (struct espconn *) c_zalloc(sizeof(struct espconn));

  conn->type = ESPCONN_TCP;
  conn->state = ESPCONN_NONE;
  conn->proto.tcp = (esp_tcp *) c_zalloc(sizeof(esp_tcp));
  conn->proto.tcp->local_port = wss->port;

  NODE_DBG("wss = %d and ", wss);

  conn->reverse = wss;
  wss->conn = conn;

  espconn_regist_connectcb(conn, server_client_connected_callback);
  espconn_accept(conn);
  espconn_regist_time(conn, WS_SERVER_CONNECT_TIMEOUT_MS, 0);

  NODE_DBG("conn %d\n", conn);
}

void wss_close(wss_info *wss) {
  NODE_DBG("wss_close\n");

  if (wss->conn == NULL) {
    return;
  }

  NODE_DBG("wss->conn %d\n", wss->conn);

  //TODO: use espconn_get_connection_info(wss->conn) to attempt graceful connections shutdown
  espconn_disconnect(wss->conn);

  if (wss->conn->proto.tcp != NULL) {
    os_free(wss->conn->proto.tcp);
  }

  espconn_delete(wss->conn);

  os_free(wss->conn);

  wss->conn = NULL;
  wss->state = 2;
}
