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

#ifndef S2E_PLUGINS_ANNOTATION_MEMORY_INTERCEPTOR_H
#define S2E_PLUGINS_ANNOTATION_MEMORY_INTERCEPTOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/MemoryInterceptor.h>
#include <s2e/Plugins/Annotation.h>

namespace s2e {
namespace plugins {

    /*
    class MemoryInterceptorConfiguration
    {
    public:
        MemoryInterceptorConfiguration(
                uint64_t address,
                uint64_t size,
                int access_type,
                MemoryInterceptorType type,
                std::string annotation)
            : address(address),
              size(size),
              access_type(access_type),
              type(type),
              plugin_annotation(annotation) {}

        uint64_t address;
        uint64_t size;
        int access_type;
        MemoryInterceptorType type;
        std::string plugin_annotation;
    };
    */




class AnnotationMemoryInterceptorPlugin : public Plugin
{
    S2E_PLUGIN

public:
    AnnotationMemoryInterceptorPlugin(S2E* s2e);
    virtual void initialize();
private:
    bool m_verbose;
};

class AnnotationMemoryInterceptor : public MemoryInterceptorPlugin
{
public:
    AnnotationMemoryInterceptor(
            S2E* s2e,
            uint64_t address,
            uint64_t size,
            int mask,
            std::string read_handler,
            std::string write_handler);

    virtual uint64_t getAddress() {return m_address;}
    virtual uint64_t getSize() {return m_size;}
    virtual int getAccessMask() {return m_mask;}
    virtual klee::ref<klee::Expr> read(S2EExecutionState *state,
            klee::ref<klee::Expr> virtaddr,
            klee::ref<klee::Expr> hostaddr,
            unsigned size,
            bool isIO, bool isCode);
    virtual bool write(S2EExecutionState *state,
                klee::ref<klee::Expr> virtaddr,
                klee::ref<klee::Expr> hostaddr,
                klee::ref<klee::Expr> value,
                bool isIO);
private:
    uint64_t m_address;
    uint64_t m_size;
    int m_mask;
    std::string m_readHandler;
    std::string m_writeHandler;
    S2E* m_s2e;
    Annotation* m_annotation;

    virtual ~AnnotationMemoryInterceptor() {}
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ANNOTATION_MEMORY_INTERCEPTOR_H
