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

#include "MemoryInterceptorAnnotation.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

namespace s2e
{
    namespace plugins
    {

        /*
         * OUTDATED
         * Example configuration:
         *      {
         *          RemoteMemory = {
         *              ranges = {
         *                  range1 = {
         *                      range_start = 0x400D3000,
         *                      range_end = 0x400D4000},
         *                      access_type = {"read", "io", "memory", "concrete_address", "concrete_value", "symbolic_value"}
         *                  },
         *                  range2 = {
         *                      range_start = 0x400E000,
         *                      range_end = 0x400DF000}
         *              },
         *
         */

        S2E_DEFINE_PLUGIN(MemoryInterceptorAnnotation,
                "Plugin for lua memory interception annotations",
                "MemoryInterceptorAnnotation", "Annotation",
                "MemoryInterceptor");

        MemoryInterceptorAnnotation::MemoryInterceptorAnnotation(S2E* s2e) :
                Plugin(s2e), m_verbose(false)
        {
        }

        void
        MemoryInterceptorAnnotation::initialize()
        {
            ConfigFile *cfg = s2e()->getConfig();
            bool ok;

            //Check that required plugins are loaded
            MemoryInterceptor* memoryInterceptor =
                    static_cast<MemoryInterceptor *>(s2e()->getPlugin(
                            "MemoryInterceptor"));
            if (!memoryInterceptor)
            {
                s2e()->getWarningsStream()
                        << "[MemoryInterceptorAnnotation] Could not find 'MemoryInterceptor' plugin. Terminating."
                        << '\n';
                exit(1);
            }

            Annotation* annotations =
                    static_cast<Annotation *>(s2e()->getPlugin("Annotation"));
            if (!annotations)
            {
                s2e()->getWarningsStream()
                        << "[MemoryInterceptorAnnotation] Could not find 'Annotation' plugin. Terminating."
                        << '\n';
                exit(1);
            }

            m_verbose =
                    cfg->getBool(getConfigKey() + ".verbose", false, &ok) ?
                            1 : 0;

            std::vector<std::string> plugins_keys = cfg->getListKeys(
                    getConfigKey() + ".interceptors", &ok);

            if (!ok)
            {
                s2e()->getWarningsStream()
                        << "[MemoryInterceptorAnnotation] Error reading subkey .interceptors"
                        << '\n';
                return;
            }

            for (std::vector<std::string>::iterator plugins_itr =
                    plugins_keys.begin(); plugins_itr != plugins_keys.end();
                    plugins_itr++)
            {
                std::vector<std::string> ranges_keys = cfg->getListKeys(
                        getConfigKey() + ".interceptors." + *plugins_itr, &ok);
                if (!ok)
                {
                    s2e()->getWarningsStream()
                            << "[MemoryInterceptorAnnotation] Error reading subkey .interceptors."
                            << *plugins_itr << '\n';
                    return;
                }

                std::string interceptor_key = getConfigKey() + ".interceptors." + *plugins_itr;

                if (!cfg->hasKey(interceptor_key + ".address")
                        || !cfg->hasKey(interceptor_key + ".size")
                        || !cfg->hasKey(interceptor_key + ".access_type"))
                {
                    s2e()->getWarningsStream()
                            << "[MemoryInterceptorAnnotation] Error: subkey .address, .size "
                            << "or .access_type for key " << interceptor_key
                            << " missing!" << '\n';
                    return;
                }

                uint64_t address = cfg->getInt(
                        interceptor_key + ".address");
                uint64_t size = cfg->getInt(interceptor_key + ".size");
                ConfigFile::string_list access_types =
                        cfg->getStringList(interceptor_key + ".access_type",
                                ConfigFile::string_list(), &ok);
                if (!ok)
                {
                    s2e()->getWarningsStream()
                            << "[MemoryInterceptorAnnotation] Error reading subkey "
                            << interceptor_key
                            << ".access_type"
                            << '\n';
                    return;
                }

                int access_type = 0;
                for (ConfigFile::string_list::const_iterator access_type_itr =
                        access_types.begin();
                        access_type_itr != access_types.end();
                        access_type_itr++)
                {
                    if (*access_type_itr == "read")
                        access_type |= ACCESS_TYPE_READ;
                    else if (*access_type_itr == "write")
                        access_type |= ACCESS_TYPE_WRITE;
                    else if (*access_type_itr == "execute")
                        access_type |= ACCESS_TYPE_EXECUTE;
                    else if (*access_type_itr == "io")
                        access_type |= ACCESS_TYPE_IO;
                    else if (*access_type_itr == "memory")
                        access_type |= ACCESS_TYPE_NON_IO;
                    else if (*access_type_itr == "concrete_value")
                        access_type |= ACCESS_TYPE_CONCRETE_VALUE;
//TODO: Symbolic values not yet supported
//                else if (*access_type_itr == "symbolic_value")
//                    access_type |= ACCESS_TYPE_SYMBOLIC_VALUE;
                    else if (*access_type_itr == "concrete_address")
                        access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;
//TODO: Symbolic values not yet supported
//                else if (*access_type_itr == "symbolic_address")
//                    access_type |= ACCESS_TYPE_SYMBOLIC_ADDRESS;
                }

                //Add some sane defaults while symbolic values are disabled
                //User can select concrete, concrete+symbolic, symbolic for address and value, default is concrete
                if (!(access_type & ACCESS_TYPE_SYMBOLIC_VALUE))
                    access_type |= ACCESS_TYPE_CONCRETE_VALUE;
                if (!(access_type & ACCESS_TYPE_SYMBOLIC_ADDRESS))
                    access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;

                //If none of read, write, execute is specified, all are assumed
                if (!(access_type
                        & (ACCESS_TYPE_READ | ACCESS_TYPE_WRITE
                                | ACCESS_TYPE_EXECUTE)))
                {
                    access_type |= ACCESS_TYPE_READ | ACCESS_TYPE_WRITE
                            | ACCESS_TYPE_EXECUTE;
                }

                if (!(access_type & ACCESS_TYPE_SIZE_ANY))
                {
                	access_type |= ACCESS_TYPE_SIZE_ANY;
                }

                //If no IO or non-IO is specified, both are assumed
                if (!(access_type & (ACCESS_TYPE_IO | ACCESS_TYPE_NON_IO)))
                {
                    access_type |= ACCESS_TYPE_IO | ACCESS_TYPE_NON_IO;
                }

                std::string read_handler;
                std::string write_handler;

                if (access_type & (ACCESS_TYPE_READ | ACCESS_TYPE_EXECUTE))
                {
                    if (!cfg->hasKey(interceptor_key + ".read_handler"))
                    {
                        s2e()->getWarningsStream()
                            << "[MemoryInterceptorAnnotation] .read_handler attribute must be set in annotation "
                            << interceptor_key
                            << " when access type is specified as read or execute."
                            << '\n';
                        exit(1);
                    }
                    else
                    {
                        read_handler = cfg->getString(
                                interceptor_key + ".read_handler", "", &ok);
                        if (!ok)
                        {
                            s2e()->getWarningsStream()
                                    << "[MemoryInterceptorAnnotation] Error reading subkey "
                                    << interceptor_key + ".read_handler"
                                    << '\n';
                            return;
                        }
                    }
                }

                if (access_type & ACCESS_TYPE_WRITE)
                {
                    if (!cfg->hasKey(interceptor_key + ".write_handler"))
                    {
                        s2e()->getWarningsStream()
                            << "[MemoryInterceptorAnnotation] .write_handler attribute must be set in annotation "
                            << interceptor_key
                            << " when access type is specified as write."
                            << '\n';
                        exit(1);
                    }
                    else
                    {
                        write_handler = cfg->getString(
                                interceptor_key + ".write_handler", "", &ok);
                        if (!ok)
                        {
                            s2e()->getWarningsStream()
                                    << "[MemoryInterceptorAnnotation] Error reading subkey "
                                    << interceptor_key + ".write_handler"
                                    << '\n';
                            return;
                        }
                    }
                }

                s2e()->getDebugStream()
                        << "[MemoryInterceptorAnnotation] Adding annotation "
                        << "for memory range " << hexval(address) << "-"
                        << hexval(address + size) << " with access type "
                        << hexval(access_type) << ", read handler '"
                        << read_handler << "', write handler '"
                        << write_handler << "'" << '\n';

                memoryInterceptor->addInterceptor(
                        new MemoryInterceptorAnnotationHandler(s2e(), address,
                                size, access_type, read_handler,
                                write_handler));
            }
        }

        MemoryInterceptorAnnotationHandler::MemoryInterceptorAnnotationHandler(
                S2E* s2e, uint64_t address, uint64_t size, int mask,
                std::string read_handler, std::string write_handler) 
            : MemoryInterceptorListener(s2e, address, size, mask),
              m_readHandler(read_handler), 
              m_writeHandler(write_handler)
        {
            m_annotation = static_cast<Annotation *>(m_s2e->getPlugin(
                    "Annotation"));
            assert(m_annotation);
        }

        klee::ref<klee::Expr>
        MemoryInterceptorAnnotationHandler::read(S2EExecutionState *state,
                klee::ref<klee::Expr> virtaddr /* virtualAddress */,
                klee::ref<klee::Expr> hostaddr /* hostAddress */, unsigned size,
                bool is_io, bool is_code)
        {
            lua_State *L = m_s2e->getConfig()->getState();
            LUAAnnotation luaAnnotation(m_annotation, state);
            S2ELUAExecutionState lua_s2e_state(state);
            uint64_t address = cast < klee::ConstantExpr > (virtaddr)->getZExtValue();

            assert(
                    !m_readHandler.empty()
                            && "Read handler must be set in MemoryInterceptorAnnotation configuration when read is allowed");

            lua_getglobal(L, m_readHandler.c_str());
            Lunar<LUAAnnotation>::push(L, &luaAnnotation);
            Lunar<S2ELUAExecutionState>::push(L, &lua_s2e_state);
            lua_pushnumber(L, address);
            lua_pushnumber(L, size / 8);
            lua_pushboolean(L, is_io);
            lua_pushboolean(L, is_code);

            lua_call(L, 6, 2);

            int resulttype = lua_tonumber(L, lua_gettop(L) - 1);

            switch (resulttype)
            {
            case 0: //Do not hijack memory read
                {
                    lua_pop(L, 2);
                    return klee::ref<klee::Expr>();
                }
            case 1: //Concrete value passed in second return argument
                {
                    uint64_t value = lua_tonumber(L, lua_gettop(L));
                    lua_pop(L, 2);
                    return klee::ConstantExpr::create(value, size);
                }
            case 2: //Unconstrained symbolic value; name of symbolic value is in 2nd argument
                {
                	std::string name = lua_tostring(L, lua_gettop(L));
                	lua_pop(L, 2);

                	return this->createSymbolicValue(state, name, size);
                }
            case 3: //Unconstrained symbolic value; the value is injected only once,
            	//A new symbolic value is created on the first return with this value,
            	//for all further returns the same symbolic value is used.
            	//Name of symbolic value is in 2nd argument
			{
				std::string name = lua_tostring(L, lua_gettop(L));
				lua_pop(L, 2);

				std::map< uint64_t, klee::ref< klee::Expr > >::const_iterator itr =
						m_writtenSymbolicValues.find(address);
				//Check if this memory location has already been accessed
				if ( itr != m_writtenSymbolicValues.end() )
				{
					assert(itr->second->getWidth() == size);

					return itr->second;
				}
				else
				{
					klee::ref< klee::Expr > symbolicValue = this->createSymbolicValue(state, name, size);
					//TODO: Address type hardcoded
					this->m_writtenSymbolicValues[address] = symbolicValue;
					return symbolicValue;
				}
			}
            default:
                {
                    m_s2e->getWarningsStream()
                            << "[MemoryInterceptorAnnotation] Lua annotation returned unnkown result type "
                            << resulttype << '\n';
                    lua_pop(L, 2);
                    return klee::ref<klee::Expr>();
                }

            }
        }

        klee::ref< klee::Expr >
        MemoryInterceptorAnnotationHandler::createSymbolicValue(
        		S2EExecutionState *state,
        		std::string name,
        		unsigned size)
        {
        	//Check already here if state is concrete to avoid creating unused symbolic values
			if (state->isRunningConcrete())
			{
				if (state->getPc() != state->getTb()->pc) {
					m_s2e->getWarningsStream() << "Switching to symbolic mode because a "
							<< "MemoryInterceptorAnnotation lua read annotation "
							<< "returned a symbolic value in concrete mode.\n"
							<< "This most likely happened "
							<< "because one of your plugins wants to switch "
							<< "to symbolic mode. The problem is that some instructions\n"
							<< "already have been executed in the current translation block and will "
							<< "be reexecuted in symbolic mode. This is fine as long as\n"
							<< "those instructions do not have any undesired side effects. Verify the "
							<< "translation block containing PC " << hexval(state->getPc())
							<< " does not have any\n"
							<< "side effects or switch to symbolic execution mode before "
							<< "if it does (e.g., by placing an Annotation at the beginning of the\n"
							<< "translation block)."
							<< '\n';
				}


				g_s2e->getDebugStream() << "[MemoryInterceptorAnnotation] read annotation returned symbolic "
						<< "value in concrete mode at PC " << hexval(state->getPc())
						<< ", switching to symbolic mode" << '\n';
				state->jumpToSymbolicCpp();
			}
			else
			{
				return state->createSymbolicValue(name, size);
			}

			assert(false && "This point should never be reached");
			return klee::ref< klee::Expr >();
        }

        bool
        MemoryInterceptorAnnotationHandler::write(S2EExecutionState *state,
                klee::ref<klee::Expr> virtaddr /* virtualAddress */,
                klee::ref<klee::Expr> hostaddr /* hostAddress */,
                klee::ref<klee::Expr> value, bool is_io)
        {
            lua_State *L = m_s2e->getConfig()->getState();
            LUAAnnotation luaAnnotation(m_annotation, state);
            S2ELUAExecutionState lua_s2e_state(state);

            assert(
                    !m_writeHandler.empty()
                            && "Write handler must be set in MemoryInterceptorAnnotation configuration when read is allowed");

            lua_getglobal(L, m_writeHandler.c_str());
            Lunar<LUAAnnotation>::push(L, &luaAnnotation);
            Lunar<S2ELUAExecutionState>::push(L, &lua_s2e_state);
            lua_pushnumber(L,
                    cast < klee::ConstantExpr > (virtaddr)->getZExtValue());
            lua_pushnumber(L, value->getWidth() / 8);
            lua_pushnumber(L,
                    cast < klee::ConstantExpr > (value)->getZExtValue());
            lua_pushboolean(L, is_io);

            lua_call(L, 6, 1);

            bool hijack = lua_toboolean(L, lua_gettop(L));
            lua_pop(L, 1);

            return hijack;
        }

    } // namespace plugins
} // namespace s2e
