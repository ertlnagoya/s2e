/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2014, EURECOM
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
 *    Jonas Zaddach <zaddach@eurecom.fr>
 *    Lucian Cojocar <lucian.cojocar@vu.nl>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include "ConcolicForkTracer.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/ExecutionTracers/TraceEntries.h>
#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>

#include <iostream>
#include <vector>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ConcolicForkTracer, "Trace symbolic state forks based on concolic values", "ConcolicForkTracer",);

void ConcolicForkTracer::initialize()
{
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &ConcolicForkTracer::slotStateFork));
    std::string outFileName = s2e()->getOutputFilename("ConcolicForkTrace.dat");
    m_logFile.open(outFileName.c_str(), std::ios::out | std::ios::binary);
}

class ConcolicForkTraceEntry
{
private:
	uint64_t m_pc;
	uint64_t m_killedStateId;
	std::string m_condition;
public:
	ConcolicForkTraceEntry(uint64_t pc, uint64_t killed_state_id, const std::string& condition)
	  : m_pc(pc), m_killedStateId(killed_state_id), m_condition(condition)
	{

	}

	uint64_t getPc() const {return m_pc;}
	uint64_t getKilledStateId() const {return m_killedStateId;}
	const std::string& getCondition() const {return m_condition;}
};
void operator<<(std::ostream& stream, const ConcolicForkTraceEntry& entry);
void operator<<(std::ostream& stream, const ConcolicForkTraceEntry& entry)
{
	uint32_t size;
	uint32_t opcode = 0;
	uint16_t stringlen = entry.getCondition().size();
	uint64_t pc = entry.getPc();
	uint64_t id = entry.getKilledStateId();
	stream.write(reinterpret_cast<const char *>(&size), 4);
	stream.write(reinterpret_cast<const char *>(&opcode), 4);
	stream.write(reinterpret_cast<const char *>(&pc), 8);
	stream.write(reinterpret_cast<const char *>(&id), 8);
	stream.write(reinterpret_cast<const char *>(&stringlen), 2);
	stream.write(entry.getCondition().c_str(), stringlen);
}

void ConcolicForkTracer::slotStateFork(S2EExecutionState* originalState,
    		           const std::vector<S2EExecutionState*>& newStates,
                       const std::vector<klee::ref<klee::Expr> >& newConditions)
{
	//print new states
	std::vector<S2EExecutionState*>::const_iterator state_itr = newStates.begin();
	std::vector< klee::ref< klee::Expr > >::const_iterator cond_itr = newConditions.begin();
	for (;state_itr != newStates.end() && cond_itr != newConditions.end(); state_itr++, cond_itr++)
	{
		if ((*state_itr)->getID() != originalState->getID())
		{
			//TODO: [J] I think this should always be true, to be verified in mixed symbolic/concolic execution
			assert(!(*state_itr)->concolics.evaluate(*cond_itr)->isTrue());

			std::string serialized_condition;
			llvm::raw_string_ostream ss(serialized_condition);
			ss << **cond_itr;
			ss.flush();

			uint64_t entry_offset = m_logFile.tellp();

			ConcolicForkTraceEntry ourTraceEntry(
					(*state_itr)->getPc(),
					(*state_itr)->getID(),
					serialized_condition);
			m_logFile << ourTraceEntry;

			ExecutionTracer* execution_tracer = static_cast<ExecutionTracer *>(s2e()->getPlugin("ExecutionTracer"));
			if (execution_tracer)
			{
				ExecutionTraceConcolicForkKill traceEntry;

				traceEntry.pc = ourTraceEntry.getPc();
				traceEntry.killed_state_id = ourTraceEntry.getKilledStateId();
				traceEntry.condition_size = ourTraceEntry.getCondition().size();
				traceEntry.condition_offset = entry_offset + 26;

				execution_tracer->writeData(*state_itr, &traceEntry, sizeof(ExecutionTraceConcolicForkKill), TRACE_CONCOLIC_FORK_KILL);
			}
			else
			{
				s2e()->getDebugStream()
						<< "[ConcolicForkTracer] Cannot get plugin ExecutionTracer, "
						<< "not logging concolic state kill" << '\n';
			}

			//TODO: Check if state fork was due to concolic value
			s2e()->getExecutor()->terminateStateEarly(**state_itr, "Killed concolic state fork");
		}
	}
}

} // namespace plugins
} // namespace s2e
