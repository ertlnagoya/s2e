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

#include "InstructionPrinter.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>
#include <list>
#include <sstream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InstructionPrinter, "Print each executed instruction and state", "",);

static std::list<std::pair<std::string, unsigned>  > REGISTERS;

void InstructionPrinter::initialize()
{
	m_exeID = 0;

    REGISTERS.push_back(std::make_pair("r0", CPU_OFFSET(regs[0])));
    REGISTERS.push_back(std::make_pair("r1", CPU_OFFSET(regs[1])));
    REGISTERS.push_back(std::make_pair("r2", CPU_OFFSET(regs[0])));
    REGISTERS.push_back(std::make_pair("r3", CPU_OFFSET(regs[3])));
    REGISTERS.push_back(std::make_pair("r4", CPU_OFFSET(regs[4])));
    REGISTERS.push_back(std::make_pair("r5", CPU_OFFSET(regs[5])));
    REGISTERS.push_back(std::make_pair("r6", CPU_OFFSET(regs[6])));
    REGISTERS.push_back(std::make_pair("r7", CPU_OFFSET(regs[7])));
    REGISTERS.push_back(std::make_pair("r8", CPU_OFFSET(regs[8])));
    REGISTERS.push_back(std::make_pair("r9", CPU_OFFSET(regs[9])));
    REGISTERS.push_back(std::make_pair("r10", CPU_OFFSET(regs[10])));
    REGISTERS.push_back(std::make_pair("r11", CPU_OFFSET(regs[11])));
    REGISTERS.push_back(std::make_pair("r12", CPU_OFFSET(regs[12])));
    REGISTERS.push_back(std::make_pair("sp", CPU_OFFSET(regs[13])));
    REGISTERS.push_back(std::make_pair("lr", CPU_OFFSET(regs[14])));

    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &InstructionPrinter::slotTranslateInstructionStart));

}

void InstructionPrinter::slotTranslateInstructionStart(
            ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t pc)
{
    signal->connect(sigc::mem_fun(*this, &InstructionPrinter::slotExecuteInstruction));
}

void InstructionPrinter::slotExecuteInstruction(
            S2EExecutionState *state,
            uint64_t pc)
{
    std::stringstream ss;

    ss << "{\"event\": \"execute-instruction\", "
       <<  "\"state\": " << state->getID() << ", "
       <<  "\"mode\":  ";
    if (state->isRunningConcrete())
        ss << "\"concrete\", ";
    else
        ss << "\"symbolic\", ";
    ss <<  "\"pc\":    " << "0x" << hexval(pc) << ", ";

    for (std::list<std::pair<std::string, unsigned> >::const_iterator itr = REGISTERS.begin();
         itr != REGISTERS.end();
         itr++)
    {
        uint32_t reg_val;
        ss <<  "\"" << itr->first << "\":    ";
        if (state->readCpuRegisterConcrete(itr->second, &reg_val, sizeof(reg_val)))
            ss << "0x" << hexval(reg_val) << ", ";
        else
            ss << "\"symbolic\", ";
    }

#ifdef TARGET_ARM
    ss << "\"cpsr\":   {";
    // Check the symbolic bits
    uint32_t flag;

    if (state->readCpuRegisterConcrete(CPU_OFFSET(NF), &flag, sizeof(flag)))
    {
        if (flag & 0x80000000)
            ss << "\"N\": true, ";
        else
            ss << "\"N\": false, ";
    }
    else
    {
        ss << "\"N\": \"symbolic\", ";
    }

    if (state->readCpuRegisterConcrete(CPU_OFFSET(ZF), &flag, sizeof(flag)))
    {
        if (flag == 0)
            ss << "\"Z\": true, ";
        else
            ss << "\"Z\": false, ";
    }
    else
    {
        ss << "\"Z\": \"symbolic\", ";
    }

    if (state->readCpuRegisterConcrete(CPU_OFFSET(CF), &flag, sizeof(flag)))
    {
        if (flag)
            ss << "\"C\": true, ";
        else
            ss << "\"C\": false, ";
    }
    else
    {
        ss << "\"C\": \"symbolic\", ";
    }


    if (state->readCpuRegisterConcrete(CPU_OFFSET(VF), &flag, sizeof(flag)))
    {
        if (flag & 0x80000000)
            ss << "\"V\": true, ";
        else
            ss << "\"V\": false, ";
    }
    else
    {
        ss << "\"V\": \"symbolic\", ";
    }

    //TODO
    uint32_t uncached_cpsr = 0;
    uint32_t thumb = 0;
//    state->readCpuRegisterConcrete(CPU_OFFSET(uncached_cpsr), &uncached_cpsr, sizeof(uncached_cpsr));
//    state->readCpuRegisterConcrete(CPU_OFFSET(thumb), &thumb, sizeof(thumb));

    if (uncached_cpsr & (1 << 7))
        ss << "\"IRQ_DISABLED\": true, ";
    else
        ss << "\"IRQ_DISABLED\": false, ";

    if (uncached_cpsr & (1 << 6))
        ss << "\"FIQ_DISABLED\": true, ";
    else
        ss << "\"FIQ_DISABLED\": false, ";

    if (thumb)
        ss << "\"T\": true, ";
    else
        ss << "\"T\": false, ";

    ss << "\"mode\": 0x" << hexval(uncached_cpsr & 0x1f) << "}";
#endif

    ss << " }";

    s2e()->getDebugStream() << "ExeID" << m_exeID++ << " : " << ss.str() << '\n';
}



} // namespace plugins
} // namespace s2e
