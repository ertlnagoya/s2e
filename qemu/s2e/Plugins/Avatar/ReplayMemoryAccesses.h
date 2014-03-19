#ifndef S2E_PLUGINS_REPLAY_MEMORY_ACCESSES_H
#define S2E_PLUGINS_REPLAY_MEMORY_ACCESSES_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <fstream>
#include <istream>

#include "../ExecutionTracers/TraceEntries.h"

namespace s2e {
namespace plugins {

class ReplayMemoryAccesses : public Plugin
	{
		S2E_PLUGIN
		public:
			ReplayMemoryAccesses(S2E* s2e): Plugin(s2e) {m_s2e = s2e;}
			void initialize();
		private:
			S2E* m_s2e;
			std::string m_inputFileName;
			bool m_verbose;

			std::ifstream m_inputFile;
			bool updateNextMemoryAccess();

			int m_stateId;
			ExecutionTraceMemory *m_nextToMatch;
			ExecutionTraceItemHeader mLastHdr;

			bool slotMemoryWrite(S2EExecutionState *state,
					klee::ref<klee::Expr> virtaddr /* virtualAddress */,
					klee::ref<klee::Expr> hostaddr /* hostAddress */,
					klee::ref<klee::Expr> value,
					bool is_io);
			klee::ref<klee::Expr> slotMemoryRead(S2EExecutionState *state,
					klee::ref<klee::Expr> virtaddr /* virtualAddress */,
					klee::ref<klee::Expr> hostaddr /* hostAddress */,
					unsigned size,
					bool is_io, bool is_code);

			/* return true if the ret value is meaningful */
			bool setValueFromNext(uint64_t address, bool isWrite,
					unsigned size, /* size in bits */
					uint64_t *valueRet);
	};

}
}

#endif
