// Module for websockets

// Example usage:
// ws = websocket.createClient()
// ws:on("connection", function() ws:send('hi') end)
// ws:on("receive", function(_, data, opcode) print(data) end)
// ws:on("close", function(_, reasonCode) print('ws closed', reasonCode) end)
// ws:connect('ws://echo.websocket.org')
//
// wsserver = websocket.createServer(80, function(ws) print('new ws client', ws) end)
// wsserver:close()

#include "lmem.h"
#include "lualib.h"
#include "lauxlib.h"
#include "platform.h"
#include "module.h"

#include "c_types.h"
#include "c_string.h"

#include "websocketclient.h"

#define METATABLE_WSCLIENT "websocket.client"
#define METATABLE_WSSERVER "websocket.server"

typedef struct wsc_data {
  int self_ref;
  int onConnection;
  int onReceive;
  int onClose;
} wsc_data;

typedef struct wss_data {
  int onNewClientConnection;
} wss_data;

// Websocket Client

static void websocketclient_onConnectionCallback(wsc_info *ws) {
  NODE_DBG("websocketclient_onConnectionCallback\n");

  lua_State *L = lua_getstate();

  if (ws == NULL || ws->reservedData == NULL) {
    luaL_error(L, "Client websocket is nil.\n");
    return;
  }
  wsc_data *data = (wsc_data *) ws->reservedData;

  if (data->onConnection != LUA_NOREF) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, data->onConnection); // load the callback function
    lua_rawgeti(L, LUA_REGISTRYINDEX, data->self_ref);  // pass itself, #1 callback argument
    lua_call(L, 1, 0);
  }
}

static void websocketclient_onReceiveCallback(wsc_info *ws, char *message, int opCode) {
  NODE_DBG("websocketclient_onReceiveCallback\n");

  lua_State *L = lua_getstate();

  if (ws == NULL || ws->reservedData == NULL) {
    luaL_error(L, "Client websocket is nil.\n");
    return;
  }
  wsc_data *data = (wsc_data *) ws->reservedData;

  if (data->onReceive != LUA_NOREF) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, data->onReceive); // load the callback function
    lua_rawgeti(L, LUA_REGISTRYINDEX, data->self_ref);  // pass itself, #1 callback argument
    lua_pushstring(L, message); // #2 callback argument
    lua_pushnumber(L, opCode); // #3 callback argument
    lua_call(L, 3, 0);
  }
}

static void websocketclient_onCloseCallback(wsc_info *ws, int errorCode) {
  NODE_DBG("websocketclient_onCloseCallback\n");

  lua_State *L = lua_getstate();

  if (ws == NULL || ws->reservedData == NULL) {
    luaL_error(L, "Client websocket is nil.\n");
    return;
  }
  wsc_data *data = (wsc_data *) ws->reservedData;

  if (data->onClose != LUA_NOREF) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, data->onClose); // load the callback function
    lua_rawgeti(L, LUA_REGISTRYINDEX, data->self_ref);  // pass itself, #1 callback argument
    lua_pushnumber(L, errorCode); // pass the error code, #2 callback argument
    lua_call(L, 2, 0);
  }

  // free self-reference to allow gc (no futher callback will be called until next ws:connect())
  lua_gc(L, LUA_GCSTOP, 0); // required to avoid freeing wsc_data
  luaL_unref(L, LUA_REGISTRYINDEX, data->self_ref);
  data->self_ref = LUA_NOREF;
  lua_gc(L, LUA_GCRESTART, 0);
}

static int websocket_createClient(lua_State *L) {
  NODE_DBG("websocket_createClient\n");

  // create user data
  wsc_data *data = (wsc_data *) luaM_malloc(L, sizeof(wsc_data));
  data->onConnection = LUA_NOREF;
  data->onReceive = LUA_NOREF;
  data->onClose = LUA_NOREF;
  data->self_ref = LUA_NOREF; // only set when ws:connect is called

  wsc_info *ws = (wsc_info *) lua_newuserdata(L, sizeof(wsc_info));
  ws->connectionState = 0;
  ws->onConnection = &websocketclient_onConnectionCallback;
  ws->onReceive = &websocketclient_onReceiveCallback;
  ws->onFailure = &websocketclient_onCloseCallback;
  ws->reservedData = data;

  // set its metatable
  luaL_getmetatable(L, METATABLE_WSCLIENT);
  lua_setmetatable(L, -2);

  return 1;
}

static int websocketclient_on(lua_State *L) {
  NODE_DBG("websocketclient_on\n");

  wsc_info *ws = (wsc_info *) luaL_checkudata(L, 1, METATABLE_WSCLIENT);
  luaL_argcheck(L, ws, 1, "Client websocket expected");

  wsc_data *data = (wsc_data *) ws->reservedData;

  int handle = luaL_checkoption(L, 2, NULL, (const char * const[]){ "connection", "receive", "close", NULL });
  if (lua_type(L, 3) != LUA_TNIL && lua_type(L, 3) != LUA_TFUNCTION && lua_type(L, 3) != LUA_TLIGHTFUNCTION) {
    return luaL_typerror(L, 3, "function or nil");
  }

  switch (handle) {
    case 0:
      NODE_DBG("connection\n");

      luaL_unref(L, LUA_REGISTRYINDEX, data->onConnection);
      data->onConnection = LUA_NOREF;

      if (lua_type(L, 3) != LUA_TNIL) {
        lua_pushvalue(L, 3);  // copy argument (func) to the top of stack
        data->onConnection = luaL_ref(L, LUA_REGISTRYINDEX);
      }
      break;
    case 1:
      NODE_DBG("receive\n");

      luaL_unref(L, LUA_REGISTRYINDEX, data->onReceive);
      data->onReceive = LUA_NOREF;

      if (lua_type(L, 3) != LUA_TNIL) {
        lua_pushvalue(L, 3);  // copy argument (func) to the top of stack
        data->onReceive = luaL_ref(L, LUA_REGISTRYINDEX);
      }
      break;
    case 2:
      NODE_DBG("close\n");

      luaL_unref(L, LUA_REGISTRYINDEX, data->onClose);
      data->onClose = LUA_NOREF;

      if (lua_type(L, 3) != LUA_TNIL) {
        lua_pushvalue(L, 3);  // copy argument (func) to the top of stack
        data->onClose = luaL_ref(L, LUA_REGISTRYINDEX);
      }
      break;
  }

  return 0;
}

static int websocketclient_connect(lua_State *L) {
  NODE_DBG("websocketclient_connect is called.\n");

  wsc_info *ws = (wsc_info *) luaL_checkudata(L, 1, METATABLE_WSCLIENT);
  luaL_argcheck(L, ws, 1, "Client websocket expected");

  wsc_data *data = (wsc_data *) ws->reservedData;

  if (ws->connectionState != 0 && ws->connectionState != 4) {
    return luaL_error(L, "Websocket already connecting or connected.\n");
  }
  ws->connectionState = 0;

  lua_pushvalue(L, 1);  // copy userdata to the top of stack to allow ref
  data->self_ref = luaL_ref(L, LUA_REGISTRYINDEX);

  const char *url = luaL_checkstring(L, 2);
  wsc_connect(ws, url);

  return 0;
}

static int websocketclient_send(lua_State *L) {
  NODE_DBG("websocketclient_send is called.\n");

  wsc_info *ws = (wsc_info *) luaL_checkudata(L, 1, METATABLE_WSCLIENT);
  luaL_argcheck(L, ws, 1, "Client websocket expected");

  wsc_data *data = (wsc_data *) ws->reservedData;

  if (ws->connectionState != 3) {
    // should this be an onFailure callback instead?
    return luaL_error(L, "Websocket isn't connected.\n");
  }

  int msgLength;
  const char *msg = luaL_checklstring(L, 2, &msgLength);

  int opCode = 1; // default: text message
  if (lua_gettop(L) == 3) {
    opCode = luaL_checkint(L, 3);
  }

  wsc_send(ws, opCode, msg, (unsigned short) msgLength);
  return 0;
}

static int websocketclient_close(lua_State *L) {
  NODE_DBG("websocketclient_close.\n");
  wsc_info *ws = (wsc_info *) luaL_checkudata(L, 1, METATABLE_WSCLIENT);
  luaL_argcheck(L, ws, 1, "Client websocket expected");

  wsc_close(ws);
  return 0;
}

static int websocketclient_gc(lua_State *L) {
  NODE_DBG("websocketclient_gc\n");

  wsc_info *ws = (wsc_info *) luaL_checkudata(L, 1, METATABLE_WSCLIENT);
  luaL_argcheck(L, ws, 1, "Client websocket expected");

  wsc_data *data = (wsc_data *) ws->reservedData;

  luaL_unref(L, LUA_REGISTRYINDEX, data->onConnection);
  luaL_unref(L, LUA_REGISTRYINDEX, data->onReceive);

  if (data->onClose != LUA_NOREF) {
    if (ws->connectionState != 4) { // only call if connection open
      lua_rawgeti(L, LUA_REGISTRYINDEX, data->onClose);

      lua_pushnumber(L, -100);
      lua_call(L, 1, 0);
    }
    luaL_unref(L, LUA_REGISTRYINDEX, data->onClose);
  }

  if (data->self_ref != LUA_NOREF) {
    lua_gc(L, LUA_GCSTOP, 0); // required to avoid freeing wsc_data
    luaL_unref(L, LUA_REGISTRYINDEX, data->self_ref);
    data->self_ref = LUA_NOREF;
    lua_gc(L, LUA_GCRESTART, 0);
  }

  NODE_DBG("freeing lua data\n");
  luaM_free(L, data);
  NODE_DBG("done freeing lua data\n");

  return 0;
}

// Websocket Server

static wsc_info *websocketserver_onNewClientCallback(void *reservedData) {
  NODE_DBG("websocketserver_onNewClientCallback");

  wss_data *server_data = (wss_data *) reservedData;

  lua_State *L = lua_getstate();

  // Create client
  websocket_createClient(L);

  lua_pushvalue(L, 1);  // copy userdata to the top of stack to allow ref
  int ws_ref = luaL_ref(L, LUA_REGISTRYINDEX);

  wsc_info *ws = (wsc_info *) luaL_checkudata(L, 1, METATABLE_WSCLIENT);
  wsc_data *client_data = (wsc_data *) ws->reservedData;
  client_data->self_ref = ws_ref;

  // Run server setup function
  lua_rawgeti(L, LUA_REGISTRYINDEX, server_data->onNewClientConnection); // load the callback function
  lua_rawgeti(L, LUA_REGISTRYINDEX, ws_ref);  // pass websocket.client, #1 callback argument
  lua_call(L, 1, 0);

  lua_pop(L, 1);

  return ws;
}

static int websocket_createServer(lua_State *L) {
  NODE_DBG("websocket_createServer\n");

  int port = luaL_checknumber(L, 1);

  if (lua_type(L, 2) != LUA_TFUNCTION && lua_type(L, 2) != LUA_TLIGHTFUNCTION) {
    return luaL_typerror(L, 2, "function");
  }

  // create user data
  wss_data *data = (wss_data *) luaM_malloc(L, sizeof(wss_data));
  lua_pushvalue(L, 2);  // copy argument (func) to the top of stack
  data->onNewClientConnection = luaL_ref(L, LUA_REGISTRYINDEX);

  wss_info *wss = (wss_info *) lua_newuserdata(L, sizeof(wss_info));
  wss->state = 0;
  wss->port = port;
  wss->reservedData = data;
  wss->onNewClientConnection = websocketserver_onNewClientCallback;

  wss_start(wss);

  // set its metatable
  luaL_getmetatable(L, METATABLE_WSSERVER);
  lua_setmetatable(L, -2);

  return 1;
}

static int websocketserver_close(lua_State *L) {
  NODE_DBG("websocketserver_close\n");

  wss_info *wss = (wss_info *) luaL_checkudata(L, 1, METATABLE_WSSERVER);
  luaL_argcheck(L, wss, 1, "Server websocket expected");

  wss_close(wss);

  wss_data *server_data = (wss_data *) wss->reservedData;

  luaL_unref(L, LUA_REGISTRYINDEX, server_data->onNewClientConnection);
  server_data->onNewClientConnection = LUA_NOREF;

  return 0;
}

static int websocketserver_gc(lua_State *L) {
  NODE_DBG("websocketserver_gc\n");

  wss_info *wss = (wss_info *) luaL_checkudata(L, 1, METATABLE_WSSERVER);
  luaL_argcheck(L, wss, 1, "Server websocket expected");

  wss_data *data = (wss_data *) wss->reservedData;

  luaL_unref(L, LUA_REGISTRYINDEX, data->onNewClientConnection);

  NODE_DBG("freeing lua data\n");
  luaM_free(L, data);
  NODE_DBG("done freeing lua data\n");

  return 0;
}

static const LUA_REG_TYPE websocket_map[] =
{
  { LSTRKEY("createClient"), LFUNCVAL(websocket_createClient) },
  { LSTRKEY("createServer"), LFUNCVAL(websocket_createServer) },
  { LNILKEY, LNILVAL }
};

static const LUA_REG_TYPE websocketclient_map[] =
{
  { LSTRKEY("on"), LFUNCVAL(websocketclient_on) },
  { LSTRKEY("connect"), LFUNCVAL(websocketclient_connect) },
  { LSTRKEY("send"), LFUNCVAL(websocketclient_send) },
  { LSTRKEY("close"), LFUNCVAL(websocketclient_close) },
  { LSTRKEY("__gc" ), LFUNCVAL(websocketclient_gc) },
  { LSTRKEY("__index"), LROVAL(websocketclient_map) },
  { LNILKEY, LNILVAL }
};

static const LUA_REG_TYPE websocketserver_map[] =
{
  { LSTRKEY("close"), LFUNCVAL(websocketserver_close) },
  { LSTRKEY("__gc" ), LFUNCVAL(websocketserver_gc) },
  { LSTRKEY("__index"), LROVAL(websocketserver_map) },
  { LNILKEY, LNILVAL }
};

int loadWebsocketModule(lua_State *L) {
  luaL_rometatable(L, METATABLE_WSCLIENT, (void *) websocketclient_map);
  luaL_rometatable(L, METATABLE_WSSERVER, (void *) websocketserver_map);

  return 0;
}

NODEMCU_MODULE(WEBSOCKET, "websocket", websocket_map, loadWebsocketModule);
