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
	m_remoteMemory->resetHit();

	++m_numberOfExecutedBB;
	m_bbExecutionFrequency[pc]++;
	/* process the pc */
	if (m_verbose)
		std::cout << "Frequency for bb at " << std::hex << pc << " " <<
			m_bbExecutionFrequency[pc] << std::dec << std::endl;
}

void StatGenerator::slotExecuteBlockEnd(S2EExecutionState *state, uint64_t pc)
{
	if (m_verbose)
		std::cout << "Executing block END at " << std::hex << pc << std::dec
			<< std::endl;
	if (m_remoteMemory->wasHit()) {
		std::cout << "BB is IO @END at " << std::hex << pc << std::dec
			<< std::endl;
	}
}

}
}
