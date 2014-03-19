#ifndef S2E_PLUGINS_REPLAY_MEMORY_ACCESSES_H
#define S2E_PLUGINS_REPLAY_MEMORY_ACCESSES_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <fstream>
#include <istream>

#include "../ExecutionTracers/TraceEntries.h"
#include "../MemoryInterceptor.h"

namespace s2e {
namespace plugins {

class ReplayMemoryAccesses : public Plugin
	{
		S2E_PLUGIN
		public:
			ReplayMemoryAccesses(S2E* s2e): Plugin(s2e) {m_s2e = s2e;}
			void initialize();
			friend class MemoryInterceptorReplayHandler;
		private:
			S2E* m_s2e;
			std::string m_inputFileName;
			bool m_verbose;
			bool m_skipCode;
			MemoryInterceptor* m_memoryInterceptor;

			std::ifstream m_inputFile;
			bool updateNextMemoryAccess();

			int m_stateId;
			ExecutionTraceMemory *m_nextToMatch;
			ExecutionTraceItemHeader mLastHdr;

			/* return true if the ret value is meaningful */
			bool setValueFromNext(uint64_t address, bool isWrite,
					unsigned size, /* size in bits */
					uint64_t *valueRet);

			/* return true if setup succeeded */
			bool setupRangeListeners();
	};

class MemoryInterceptorReplayHandler : public MemoryAccessHandler
	{
		public:
			MemoryInterceptorReplayHandler(
					S2E* s2e,
					uint64_t address,
					uint64_t size,
					int mask);

			virtual klee::ref<klee::Expr> read(S2EExecutionState *state,
					klee::ref<klee::Expr> virtaddr,
					klee::ref<klee::Expr> hostaddr,
					unsigned size,
					bool isIO, bool isCode);
			virtual bool write(S2EExecutionState *state,
					klee::ref<klee::Expr> virtaddr,
					klee::ref<klee::Expr> hostaddr,
					klee::ref<klee::Expr> value,
					bool isIO);
		private:
			S2E* m_s2e;
			ReplayMemoryAccesses *m_replayMemoryAccesses;
			virtual ~MemoryInterceptorReplayHandler() {}
	};

}
}

#endif
