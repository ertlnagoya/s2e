/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include "LuaMonitorCommand.h"
#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include <iostream>

extern "C" {
#include <qint.h>
}

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaMonitorCommand, "Execute lua commands on Qemu QMP console", "",);

void LuaMonitorCommand::initialize()
{
	bool ok;
	m_verbose = s2e()->getConfig()->getBool(getConfigKey() + ".verbose", false, &ok);
    s2e()->getCorePlugin()->onMonitorCommand.connect(
            sigc::mem_fun(*this, &LuaMonitorCommand::slotMonitorCommand));
}

void LuaMonitorCommand::createError(QDict* ret, lua_State* L, int err, const char * note)
{
	QDict* error_dict = qdict_new();
	qdict_put(error_dict, "code", qint_from_int(err));
	if (lua_isstring(L, -1)) {
		qdict_put(error_dict, "message", qstring_from_str(lua_tostring(L, -1)));
	}
	qdict_put(error_dict, "note", qstring_from_str(note));
	qdict_put(ret, "error", error_dict);
}

void LuaMonitorCommand::slotMonitorCommand(Monitor* mon, const QDict* args, QDict* ret)
{
	if (qdict_haskey(args, "cmd")) {
		const char * cmd = qdict_get_str(args, "cmd");
		if (cmd && strcmp("lua", cmd) == 0 && qdict_haskey(args, "lua")) {
			const char * lua = qdict_get_str(args, "lua");
			if (lua) {
				lua_State* L = s2e()->getConfig()->getState();
				int stackTop = lua_gettop(L);
				int err;

				if (m_verbose) {
					s2e()->getWarningsStream() << "[LuaMonitorCommand] Executing command  `"
							<< lua << "'" << '\n';
				}

				err = luaL_loadstring(L, lua);
				if (err)  {
					s2e()->getWarningsStream() << "[LuaMonitorCommand] ERROR parsing LUA monitor command `"
							<< lua << "'" << '\n';
					createError(ret, L, err, "error parsing lua command");
					return;
				}

				err = lua_pcall(L, 0, LUA_MULTRET, 0);
				if (err) {
					s2e()->getWarningsStream() << "[LuaMonitorCommand] ERROR executing LUA monitor command `"
							<< lua << "'" << '\n';
					createError(ret, L, err, "error executing lua command");
					return;
				}

				if (lua_gettop(L) > stackTop + 1) {
					s2e()->getWarningsStream() << "[LuaMonitorCommand] ERROR: Too many return values from "
							"lua function on the stack, trying to recover" << '\n';
					lua_pop(L, lua_gettop(L) - stackTop);
				}
				else if (lua_gettop(L) == stackTop + 1) {
					if (lua_isnumber(L, -1)) {
						qdict_put(ret, "result", qint_from_int(lua_tonumber(L, -1)));
					}
					else if (lua_isstring(L, -1)) {
						qdict_put(ret, "result", qstring_from_str(lua_tostring(L, -1)));
					}
					else {
						s2e()->getWarningsStream() << "[LuaMonitorCommand] ERROR: Lua command returned "
								<< "unknown return value type; ignoring return value" << '\n';
						QDict* error_dict = qdict_new();
						qdict_put(error_dict, "message", qstring_from_str("command returned unknown type"));
						qdict_put(error_dict, "code", qint_from_int(-1));
						qdict_put(ret, "error", error_dict);
					}

					lua_pop(L, 1);
				}
			}
		}
	}
}

} // namespace plugins
} // namespace s2e
