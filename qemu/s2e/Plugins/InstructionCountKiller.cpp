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

#include "InstructionCountKiller.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InstructionCountKiller, "Count per-state and global executed instructions and terminate when limit is reached", "",);

PluginState* InstructionCountKillerState::clone() const
{
	return new InstructionCountKillerState(this->m_globalInstructionCount, 0);
}

PluginState *InstructionCountKillerState::factory(Plugin *p, S2EExecutionState *s)
{
	return new InstructionCountKillerState(0, 0);
}

void InstructionCountKiller::initialize()
{
    m_maxGlobalInstructions = s2e()->getConfig()->getInt(
            getConfigKey() + ".maxGlobalInstructionCount", 0);
    m_maxStateInstructions = s2e()->getConfig()->getInt(
    		getConfigKey() + ".maxPerStateInstructionCount", 0);

    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
            sigc::mem_fun(*this, &InstructionCountKiller::slotTranslateInstructionStart));
}

void InstructionCountKiller::slotTranslateInstructionStart(
		ExecutionSignal* signal,
		S2EExecutionState* state,
		TranslationBlock* tb,
		uint64_t pc)
{
	signal->connect(sigc::mem_fun(*this, &InstructionCountKiller::slotExecuteInstructionStart));
}

void InstructionCountKiller::slotExecuteInstructionStart(S2EExecutionState* state, uint64_t pc)
{
	DECLARE_PLUGINSTATE(InstructionCountKillerState, state);

	plgState->m_globalInstructionCount += 1;
	plgState->m_stateInstructionCount += 1;

//	s2e()->getDebugStream() << "[InstructionCountKiller] state = " << state->getID()
//			<< ", globalCount = " << plgState->m_globalInstructionCount
//			<< ", stateCount = " << plgState->m_stateInstructionCount << '\n';

	if (m_maxGlobalInstructions != 0 && plgState->m_globalInstructionCount > m_maxGlobalInstructions)
	{
		s2e()->getDebugStream() << "State " << state->getID() << " terminated because "
				<< "global maximum number of instructions has been executed" << '\n';
		s2e()->getExecutor()->terminateStateEarly(*state, "Killed because global instruction count limit has been reached");
	}
	else if (m_maxStateInstructions != 0 && plgState->m_globalInstructionCount > m_maxStateInstructions)
	{
		s2e()->getDebugStream() << "State " << state->getID() << " terminated because "
						<< "state maximum number of instructions has been executed" << '\n';
		s2e()->getExecutor()->terminateStateEarly(*state, "Killed because per-state instruction count limit has been reached");
	}
}

} // namespace plugins
} // namespace s2e
