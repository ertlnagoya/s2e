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

#include "InstructionTracer.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>
#include <list>
#include <sstream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InstructionTracer, "Print each executed instruction and state", "",);

static std::list<std::pair<std::string, unsigned>  > REGISTERS;

void InstructionTracer::initialize()
{
    m_tracer = (ExecutionTracer *)s2e()->getPlugin("ExecutionTracer");

	s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &InstructionTracer::slotTranslateInstructionStart));

}

void InstructionTracer::slotTranslateInstructionStart(
            ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc)
{
    signal->connect(sigc::mem_fun(*this, &InstructionTracer::slotExecuteInstruction));
}

// Retrieve current processor state for tracing
void InstructionTracer::slotExecuteInstruction(
            S2EExecutionState *state,
            uint64_t pc)
{
    ExecutionTraceInstr instrTrace;

    // Current PC
    instrTrace.pc = pc;

    // All user registers, and flag symbolic ones
    instrTrace.symbMask = 0;

    target_ulong * regArray = NULL;
#if defined(TARGET_X86_64)
    instrTrace.arch = s2e::plugins::ExecutionTraceInstr::X86_64;
    regArray = &instrTrace.x64_registers[0];
#elif defined(TARGET_I386)
    instrTrace.arch = s2e::plugins::ExecutionTraceInstr::X86;
    regArray = &instrTrace.x86_registers[0];
#elif defined(TARGET_ARM)
    instrTrace.arch = s2e::plugins::ExecutionTraceInstr::ARM;
    regArray = &instrTrace.arm_registers[0];
#endif

    assert(sizeof(instrTrace.symbMask)*8 >= NR_REG);
    assert(regArray != NULL);

    for (unsigned i = 0; i < NR_REG; ++i) {
        regArray[i] = 0;
        if (!state->readCpuRegisterConcrete(CPU_REG_OFFSET(i), &regArray[i], CPU_REG_SIZE)) {
		regArray[i]  = 0xDEADBEEF;
            instrTrace.symbMask |= 1<<i;
        }
    }

    // Current processor flags
    instrTrace.flags = state->getFlags();

    // Write current state
    m_tracer->writeData(state, &instrTrace, sizeof(instrTrace), TRACE_INSTR_START);

}



} // namespace plugins
} // namespace s2e
