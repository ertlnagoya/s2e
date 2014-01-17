/*
 * Copyright 2014 Lucian Cojocar <lucian.cojocar@vu.nl> VU
 */

#ifndef S2E_STATISTICS_GENERATOR_H
#define S2E_STATISTICS_GENERATOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

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
		void slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc);

	private:
		bool m_traceBlockTranslation;
		bool m_traceBlockExecution;
		bool m_verbose;

		std::map<uint64_t, uint64_t> m_bbExecutionFrequency;
		std::map<uint64_t, bool> m_bbHasIOAccesses;
		uint64_t m_numberOfExecutedBB;
};

}
}
#endif
