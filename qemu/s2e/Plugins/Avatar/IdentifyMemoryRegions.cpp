/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2014, EURECOM
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
 *    Jonas Zaddach <zaddach@eurecom.fr>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include "IdentifyMemoryRegions.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>

#include <iostream>
#include <list>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(IdentifyMemoryRegions, "Identify memory regions", "",);

uint64_t IdentifyMemoryRegions::getPageAddress(uint64_t address)
{
	return (address / m_pageSize) * m_pageSize;
}

void IdentifyMemoryRegions::initialize()
{
    m_traceBlockTranslation = s2e()->getConfig()->getBool(
                        getConfigKey() + ".traceBlockTranslation", false);
    m_traceMemoryAccesses = s2e()->getConfig()->getBool(
                        getConfigKey() + ".traceMemoryAccesses", true);
    m_traceBlockExecution = s2e()->getConfig()->getBool(
            getConfigKey() + ".traceBlockExecution", true);

    m_pageSize = s2e()->getConfig()->getInt(
            getConfigKey() + ".pageSize", 512);

    if (m_traceBlockTranslation || m_traceBlockExecution)
    {
    	s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
            sigc::mem_fun(*this, &IdentifyMemoryRegions::slotTranslateBlockEnd));
    }

    if (m_traceMemoryAccesses)
    {
    	s2e()->getCorePlugin()->onDataMemoryAccess.connect(
			sigc::mem_fun(*this, &IdentifyMemoryRegions::slotDataMemoryAccess));
    }

    s2e()->getCorePlugin()->onStateKill.connect(
    		sigc::mem_fun(*this, &IdentifyMemoryRegions::slotStateKill));

    s2e()->getCorePlugin()->onQemuShutdownRequest.connect(
    		sigc::mem_fun(*this, &IdentifyMemoryRegions::slotQemuShutdownRequest));

}

void IdentifyMemoryRegions::slotTranslateBlockEnd(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t end_pc,
                                      bool isTargetValid,
                                      uint64_t staticTarget)
{
	if (m_traceBlockExecution)
	{
		signal->connect(sigc::mem_fun(*this, &IdentifyMemoryRegions::slotExecuteBlockEnd));
	}
	else
	{
		m_accesses[getPageAddress(tb->pc)].execute += 1;
		m_accesses[getPageAddress(end_pc)].execute += 1;
	}
}

void IdentifyMemoryRegions::slotExecuteBlockEnd(S2EExecutionState *state, uint64_t pc)
{
	m_accesses[getPageAddress(pc)].execute += 1;
	klee::ref<klee::Expr> sp = state->readCpuRegister(CPU_REG_OFFSET(13), CPU_REG_SIZE * 8);
	if (isa<klee::ConstantExpr>(sp))
	{
		m_accesses[getPageAddress(cast<klee::ConstantExpr>(sp)->getZExtValue())].stack += 1;
	}
}

bool IdentifyMemoryRegions::isShadowMemoryIdentical(uint64_t address, unsigned size, uint64_t value)
{
	for (unsigned i = 0; i < size; i++)
	{
#ifdef TARGET_WORDS_BIGENDIAN
		uint8_t val = (value >> (8 * (size - i - 1))) & 0xff;
#else
		uint8_t val = (value >> (8 * i)) & 0xff;
#endif
		if (m_shadowMemory.find(address + i) == m_shadowMemory.end())
			return false;

		if (m_shadowMemory[address + i] != val)
			return false;
	}

	return true;
}

bool IdentifyMemoryRegions::isShadowMemoryInitialized(uint64_t address, unsigned size)
{
	for (unsigned i = 0; i < size; i++)
	{
		if (m_shadowMemory.find(address + i) == m_shadowMemory.end())
			return false;
	}

	return true;
}

void IdentifyMemoryRegions::shadowMemoryWrite(uint64_t address, unsigned size, uint64_t value)
{
	for (unsigned i = 0; i < size; i++)
	{
#ifdef TARGET_WORDS_BIGENDIAN
		uint8_t val = (value >> (8 * (size - i - 1))) & 0xff;
#else
		uint8_t val = (value >> (8 * i)) & 0xff;
#endif
		m_shadowMemory[address + i] = val;
	}
}

void IdentifyMemoryRegions::slotDataMemoryAccess(S2EExecutionState*,
                 klee::ref<klee::Expr> virtualAddress,
                 klee::ref<klee::Expr> hostAddress,
                 klee::ref<klee::Expr> value,
                 bool isWrite, bool isIO, bool isCode)
{
	if (!isa<klee::ConstantExpr>(virtualAddress))
		return;
	if (!isa<klee::ConstantExpr>(value))
		return;

	uint64_t address = cast<klee::ConstantExpr>(virtualAddress)->getZExtValue();
	unsigned size = value->getWidth() / 8;
	uint64_t val = cast<klee::ConstantExpr>(value)->getZExtValue();

	s2e()->getMessagesStream() << "Memory access to " << hexval(address) << ": " << hexval(val)
			<< " " << (isWrite ? "(write)" : "(read)") << '\n';

	if (!isWrite
			&& isShadowMemoryInitialized(address, size)
	        && !isShadowMemoryIdentical(address, size, val))
	{
		m_accesses[getPageAddress(address)].io += 1;
	}

	shadowMemoryWrite(address, size, val);

	if (isWrite)
		m_accesses[getPageAddress(address)].write += 1;
	else
		m_accesses[getPageAddress(address)].read += 1;
}

enum MemoryLabel
{
	LABEL_NONE,
	LABEL_CODE,
	LABEL_DATA,
	LABEL_RODATA,
	LABEL_STACK,
	LABEL_IO,
	LABEL_CODE_RODATA,
	LABEL_UNDECIDED
};

static MemoryLabel getLabel(AccessCount& accessCount)
{
	//TODO: Could print warnings when something seems fishy (LABEL_UNDECIDED)
//	uint64_t allAccesses = accessCount.execute + accessCount.io
//			+ accessCount.stack + accessCount.read + accessCount.write;
	MemoryLabel label;
	if (accessCount.execute > 0)
	{
		if (accessCount.write > 0)
			label = LABEL_UNDECIDED;
		else if (accessCount.stack > 0)
			label = LABEL_UNDECIDED;
		else if (accessCount.io > 0)
			label = LABEL_UNDECIDED;
		else if (accessCount.read > 0)
			label = LABEL_CODE_RODATA;
		else
			label = LABEL_CODE;
	}
	else if (accessCount.stack > 0)
	{
		if (accessCount.io > 0)
			label = LABEL_UNDECIDED;
		else
			label = LABEL_STACK;
	}
	else if (accessCount.io > 0)
	{
		label = LABEL_IO;
	}
	else if (accessCount.write > 0)
	{
		if (accessCount.read == 0)
			//TODO: This is not really correct, as dead variables (that are only initialized but never used)
			//will be marked as IO. Have to think of something better
			label = LABEL_UNDECIDED;
		else
			label = LABEL_DATA;
	}
	else
		label = LABEL_RODATA;

	return label;
}

void IdentifyMemoryRegions::dumpStats()
{
	uint64_t startAddress = 0;
	uint64_t lastAddress = 0;
	MemoryLabel label = LABEL_NONE;

	s2e()->getWarningsStream() << "[IdentifyMemoryRegions] dumpStats called" << '\n';

	//Label regions as code, ro-data, data, stack, io
	std::list< std::pair< std::pair<uint64_t, uint64_t>, MemoryLabel > > labelledRegions;
	for (std::map<uint64_t, AccessCount>::iterator itr = m_accesses.begin();
		 itr != m_accesses.end();
		 itr++)
	{
		MemoryLabel curLabel = getLabel(itr->second);

		if (itr->first == lastAddress + m_pageSize && curLabel == label && label != LABEL_NONE)
		{
			lastAddress = itr->first;
		}
		else
		{
			if (label != LABEL_NONE)
			{
				labelledRegions.push_back(std::make_pair(std::make_pair(startAddress, lastAddress + m_pageSize), label));
			}

			startAddress = itr->first;
			lastAddress = itr->first;
			label = curLabel;
		}
	}

	if (label != LABEL_NONE)
	{
		labelledRegions.push_back(std::make_pair(std::make_pair(startAddress, lastAddress + m_pageSize), label));
	}
	std::string filename = s2e()->getOutputFilename("memory_regions.csv");
	std::ofstream fout(filename.c_str());

	for (std::list< std::pair< std::pair< uint64_t, uint64_t >, MemoryLabel > >::iterator itr = labelledRegions.begin();
		 itr != labelledRegions.end();
		 itr++)
	{
		fout << "0x";
		fout << std::setfill('0') << std::setw(8) << std::hex << itr->first.first;
		fout << ", 0x";
		fout << std::setfill('0') << std::setw(8) << std::hex << (itr->first.second - itr->first.first);
		fout << ", ";
		switch(itr->second)
		{
		case LABEL_UNDECIDED:
			fout << "undecided";
			break;
		case LABEL_STACK:
			fout << "stack";
			break;
		case LABEL_IO:
			fout << "io";
			break;
		case LABEL_CODE:
			fout << "code";
			break;
		case LABEL_CODE_RODATA:
			fout << "code+rodata";
			break;
		case LABEL_RODATA:
			fout << "rodata";
			break;
		case LABEL_DATA:
			fout << "data";
			break;
		case LABEL_NONE:
			fout << "error";
			break;
		}

		fout << "\n";
	}

	fout.close();


}


void IdentifyMemoryRegions::slotStateKill(S2EExecutionState* state)
{
	if (s2e()->getExecutor()->getStatesCount() <= 1)
	{
		dumpStats();
	}
}

void IdentifyMemoryRegions::slotQemuShutdownRequest(int signal, unsigned pid)
{
	dumpStats();
}

} // namespace plugins
} // namespace s2e
