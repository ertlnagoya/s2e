
/*
 * Copyright 2014 Lucian Cojocar <lucian.cojocar@vu.nl> VU
 */

#ifndef S2E_STATE_MIGRATION_H
#define S2E_STATE_MIGRATION_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/RemoteMemory.h>

namespace s2e {
namespace plugins {
class StateMigration : public Plugin
{
	S2E_PLUGIN
	public:
		StateMigration(S2E* s2e): Plugin(s2e) {}
		void initialize();

		void slotTranslateBlockStart(ExecutionSignal*, S2EExecutionState
				*state, TranslationBlock *tb, uint64_t pc);
		void slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc);

	private:
		uint64_t m_start_pc;
		uint64_t m_end_pc;
		bool m_verbose;
		RemoteMemory *m_remoteMemory;
};

}
}
#endif
