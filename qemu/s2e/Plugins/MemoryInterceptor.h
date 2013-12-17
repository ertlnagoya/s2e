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

#ifndef S2E_PLUGINS_MEMORY_INTERCEPTOR_H
#define S2E_PLUGINS_MEMORY_INTERCEPTOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {
enum AccessType
{
    ACCESS_TYPE_READ = 0x1,
    ACCESS_TYPE_WRITE = 0x2,
    ACCESS_TYPE_EXECUTE = 0x4,
    ACCESS_TYPE_CONCRETE_VALUE = 0x8,
    ACCESS_TYPE_SYMBOLIC_VALUE = 0x10,
    ACCESS_TYPE_CONCRETE_ADDRESS = 0x20,
    ACCESS_TYPE_SYMBOLIC_ADDRESS = 0x40,
    ACCESS_TYPE_NON_IO = 0x80,
    ACCESS_TYPE_IO = 0x100
};

class MemoryInterceptorListener
{
public:
    MemoryInterceptorListener(S2E* s2e, uint64_t address, uint64_t size, uint64_t mask)
        : m_s2e(s2e),
          m_address(address),
          m_size(size),
          m_mask(mask)
    {
    }

    virtual uint64_t getAddress() 
    {
        return m_address;
    }

    virtual uint64_t getSize() 
    {
        return m_size;
    }

    virtual int getAccessMask() 
    {
        return m_mask;
    }

    virtual klee::ref<klee::Expr> read(S2EExecutionState *state,
            klee::ref<klee::Expr> virtaddr,
            klee::ref<klee::Expr> hostaddr,
            unsigned size,
            bool isIO, bool isCode)
    {
        return klee::ref<klee::Expr>();
    }

    virtual bool write(S2EExecutionState *state,
                klee::ref<klee::Expr> virtaddr,
                klee::ref<klee::Expr> hostaddr,
                klee::ref<klee::Expr> value,
                bool isIO)
    {
        return false;
    }
    virtual ~MemoryInterceptorListener() {}
protected:
    S2E* m_s2e;
    uint64_t m_address;
    uint64_t m_size;
    uint64_t m_mask;
};

class MemoryInterceptor : public Plugin
{
    S2E_PLUGIN
public:
    MemoryInterceptor(S2E* s2e);

    klee::ref<klee::Expr> slotMemoryRead(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr,
        klee::ref<klee::Expr> hostaddr,
        unsigned size,
        bool isIO, bool isCode);
    bool slotMemoryWrite(S2EExecutionState *state,
            klee::ref<klee::Expr> virtaddr,
            klee::ref<klee::Expr> hostaddr,
            klee::ref<klee::Expr> value,
            bool isIO);
    void initialize();
    void addInterceptor(MemoryInterceptorListener * listener);
//    void registerInterceptors();

private:
    bool m_readInterceptorRegistered;
    bool m_writeInterceptorRegistered;
    std::vector< MemoryInterceptorListener* > m_listeners;
    bool m_verbose;

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_MEMORY_INTERCEPTOR_H
