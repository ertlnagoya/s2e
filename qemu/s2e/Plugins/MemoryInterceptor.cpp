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

#include "MemoryInterceptor.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

namespace s2e {
namespace plugins {


/*
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

S2E_DEFINE_PLUGIN(MemoryInterceptor, "Plugin to coordinate which other plugins can intercept which memory ranges",
        "MemoryInterceptor", "Annotation");

MemoryInterceptor::MemoryInterceptor(S2E* s2e)
    : Plugin(s2e),
      m_readInterceptorRegistered(false),
      m_writeInterceptorRegistered(false)
{
}

void MemoryInterceptor::initialize()
{
    ConfigFile *cfg = s2e()->getConfig();
    bool ok;

    m_verbose =
          cfg->getBool(getConfigKey() + ".verbose", false, &ok) ? 1 : 0;
}

klee::ref<klee::Expr> MemoryInterceptor::slotMemoryRead(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        unsigned size,
        bool is_io, bool is_code)
{
    int access_type = 0;
    uint64_t address = 0;

    if (is_code)
        access_type |= ACCESS_TYPE_EXECUTE;
    else
        access_type |= ACCESS_TYPE_READ;

    if (is_io)
        access_type |= ACCESS_TYPE_IO;
    else
        access_type |= ACCESS_TYPE_NON_IO;

    if (isa<klee::ConstantExpr>(virtaddr))
    {
        address = cast<klee::ConstantExpr>(virtaddr)->getZExtValue();
        access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;
    }
    else
        access_type |= ACCESS_TYPE_SYMBOLIC_ADDRESS;

    if (this->m_verbose)
    {
        s2e()->getDebugStream()
                << "[MemoryInterceptor] slotMemoryRead called with address "
                << hexval(address)
                << ((access_type & ACCESS_TYPE_CONCRETE_ADDRESS) ? " [concrete]" : " [symbolic]")
                << ", access_type " << hexval(access_type)
                << '\n';
    }

    for (std::vector< MemoryInterceptorPlugin* >::iterator listener_itr = this->m_listeners.begin();
         listener_itr != this->m_listeners.end();
         listener_itr++)
    {
        if (
                //If access type matches desired mask and either address is symbolic or matches the given range
                ((*listener_itr)->getAccessMask() & access_type) == access_type &&
                (
                    (access_type & ACCESS_TYPE_SYMBOLIC_ADDRESS) ||
                    ((*listener_itr)->getAddress() <= address &&
                     (*listener_itr)->getAddress() + (*listener_itr)->getSize() > address)
                )
            )
        {
            return (*listener_itr)->read(state, virtaddr, hostaddr, size, is_io, is_code);
        }
    }

    //No handler found
    return klee::ref<klee::Expr>();
}

bool MemoryInterceptor::slotMemoryWrite(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value,
        bool is_io)
{
    int access_type = ACCESS_TYPE_WRITE;
    uint64_t address = 0;

    if (is_io)
        access_type |= ACCESS_TYPE_IO;
    else
        access_type |= ACCESS_TYPE_NON_IO;

    if (isa<klee::ConstantExpr>(virtaddr))
    {
        address = cast<klee::ConstantExpr>(virtaddr)->getZExtValue();
        access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;
    }
    else
        access_type |= ACCESS_TYPE_SYMBOLIC_ADDRESS;

    if (isa<klee::ConstantExpr>(value))
    {
        access_type |= ACCESS_TYPE_CONCRETE_VALUE;
    }
    else
        access_type |= ACCESS_TYPE_SYMBOLIC_VALUE;

    if (this->m_verbose)
    {
        s2e()->getDebugStream()
                << "[MemoryInterceptor] slotMemoryWrite called with address "
                << hexval(address)
                << ((access_type & ACCESS_TYPE_CONCRETE_ADDRESS) ? " [concrete]" : " [symbolic]")
                << ", access_type " << hexval(access_type)
                << '\n';
    }

    for (std::vector< MemoryInterceptorPlugin* >::iterator listener_itr = this->m_listeners.begin();
         listener_itr != this->m_listeners.end();
         listener_itr++)
    {
        if (
                //If access type matches desired mask and either address is symbolic or matches the given range
                ((*listener_itr)->getAccessMask() & access_type) == access_type &&
                (
                    (access_type & ACCESS_TYPE_SYMBOLIC_ADDRESS) ||
                    ((*listener_itr)->getAddress() <= address &&
                     (*listener_itr)->getAddress() + (*listener_itr)->getSize() > address)
                )
            )
        {
            return (*listener_itr)->write(state, virtaddr, hostaddr, value, is_io);
        }
    }

    //No handler found
    return false;
}

void MemoryInterceptor::addInterceptorPlugin(MemoryInterceptorPlugin * listener)
{
    //TODO: Check that there is no intersection with an already added plugin
    m_listeners.push_back(listener);

    if ((listener->getAccessMask() & (ACCESS_TYPE_READ | ACCESS_TYPE_EXECUTE)) && !m_readInterceptorRegistered)
    {
        s2e()->getCorePlugin()->onHijackMemoryRead.connect(sigc::mem_fun(*this, &MemoryInterceptor::slotMemoryRead));
        m_readInterceptorRegistered = true;
    }

    if ((listener->getAccessMask() & ACCESS_TYPE_WRITE) && !m_writeInterceptorRegistered)
    {
        s2e()->getCorePlugin()->onHijackMemoryWrite.connect(sigc::mem_fun(*this, &MemoryInterceptor::slotMemoryWrite));
        m_writeInterceptorRegistered = true;
    }
}



} // namespace plugins
} // namespace s2e
