#include "StatGenerator.h"

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/RemoteMemory.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StatGenerator, "StatGenerator -- generate blocks statics", "StatGenerator", "RemoteMemory");

void StatGenerator::initialize()
{
	m_traceBlockTranslation = s2e()->getConfig()->getBool(
			getConfigKey() + ".traceBlockTranslation");
	m_traceBlockExecution = s2e()->getConfig()->getBool(
			getConfigKey() + ".traceBlockExecution");
	m_verbose = s2e()->getConfig()->getBool(
			getConfigKey() + ".verbose", false);
	m_remoteMemory = static_cast<RemoteMemory*>(s2e()->getPlugin("RemoteMemory"));

	s2e()->getCorePlugin()->onTranslateBlockStart.connect(
			sigc::mem_fun(*this, &StatGenerator::slotTranslateBlockStart));
	s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
			sigc::mem_fun(*this, &StatGenerator::slotTranslateBlockEnd));
	s2e()->getDebugStream() << "[StatGenerator]: initialized" << '\n';
}

void StatGenerator::slotTranslateBlockStart(ExecutionSignal *signal, 
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc)
{
	if(m_traceBlockTranslation)
		std::cout << "Translating block START at " << std::hex << pc << std::dec << std::endl;
	if(m_traceBlockExecution)
		signal->connect(sigc::mem_fun(*this, &StatGenerator::slotExecuteBlockStart));
}

void StatGenerator::slotTranslateBlockEnd(ExecutionSignal *signal, 
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t end_pc,
									  bool target_is_valid,
									  uint64_t target_pc
									  )
{
	if(m_traceBlockTranslation)
		std::cout << "Translating block END at " << std::hex << end_pc << std::dec << std::endl;
	if(m_traceBlockExecution)
		signal->connect(sigc::mem_fun(*this, &StatGenerator::slotExecuteBlockEnd));
}

void StatGenerator::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
	if (m_verbose)
		std::cout << "Executing block START at " << std::hex << pc << std::dec
			<< std::endl;

	++m_numberOfExecutedBB;
	++m_bbExecutionFrequency[pc];
	std::map<uint64_t, bool>::const_iterator it = m_bbHasIOAccesses.find(pc);
	if (it == m_bbHasIOAccesses.end()) {
		/* basic block might be IO */
		m_remoteMemory->resetHit();
	} else {
		/* basic block already mapped as IO */
		std::cout << "BB is IO @START at " << std::hex << pc << std::dec
			<< " times " << m_bbExecutionFrequency[pc] << std::endl;
	}
	/* process the pc */
	if (m_verbose)
		std::cout << "Frequency for bb at " << std::hex << pc << " " <<
			m_bbExecutionFrequency[pc] << std::dec << std::endl;
	m_bb_start_pc = pc;
}

void StatGenerator::slotExecuteBlockEnd(S2EExecutionState *state, uint64_t pc)
{
	if (m_verbose)
		std::cout << "Executing block END at " << std::hex << pc << std::dec
			<< std::endl;
	if (m_remoteMemory->wasHit()) {
		m_bbHasIOAccesses[m_bb_start_pc] = true;
		m_remoteMemory->resetHit();
		if (m_verbose)
			std::cout << "BB is IO @END at " << std::hex << pc << std::dec
				<< std::endl;
		/* TODO evaluate BB score for migration */
	}
	/* save the length of the BB,
	 * asume each instruction takes 4 bytes
	 */
	m_bbLen[m_bb_start_pc] = (pc - m_bb_start_pc) >> 2;
}

void StatGenerator::printStat(uint64_t pc)
{
	std::map<uint64_t, uint64_t>::const_iterator it = m_bbLen.find(pc);
	if (it == m_bbLen.end()) {
		std::cout << "Basic Block @ " << std::hex << pc << std::dec
			<< " does not exists or it wasn't yet explored" << std::endl;
		return;
	}
	/* TODO: print */
}

}
}
