/*
 * Copyright 2014 Lucian Cojocar <lucian.cojocar@vu.nl> VU
 */

#ifndef S2E_STATISTICS_GENERATOR_H
#define S2E_STATISTICS_GENERATOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/RemoteMemory.h>

namespace s2e {
namespace plugins {
class StatGenerator : public Plugin
{
	S2E_PLUGIN
	public:
		StatGenerator(S2E* s2e): Plugin(s2e) {}
		void initialize();
		void slotTranslateBlockStart(ExecutionSignal*, S2EExecutionState
				*state, TranslationBlock *tb, uint64_t pc);
		void slotTranslateBlockEnd(ExecutionSignal*, S2EExecutionState
				*state, TranslationBlock *tb, uint64_t end_pc, bool isValid, uint64_t target_pc);
		void slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc);
		void slotExecuteBlockEnd(S2EExecutionState* state, uint64_t pc);
		void printStat(uint64_t pc);

	private:
		bool m_traceBlockTranslation;
		bool m_traceBlockExecution;
		bool m_verbose;
		RemoteMemory *m_remoteMemory;

		std::map<uint64_t, uint64_t> m_bbExecutionFrequency;
		std::map<uint64_t, bool> m_bbHasIOAccesses;
		std::map<uint64_t, uint64_t> m_bbLen;
		uint64_t m_numberOfExecutedBB;

		uint64_t m_bb_start_pc; /* the start of BB is cached */
};

}
}
#endif
