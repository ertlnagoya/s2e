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


class ReplayMemoryAccessesState : public PluginState
{
    friend class ReplayMemoryAccesses;
    friend class MemoryInterceptorReplayHandler;
private:
    ReplayMemoryAccessesState() : m_forked(false) {}
    bool m_forked;
public:
    ReplayMemoryAccessesState* clone() const {return new ReplayMemoryAccessesState(*this);}
    static PluginState* factory(Plugin* p, S2EExecutionState* s) {return new ReplayMemoryAccessesState();}

};

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
			bool m_insertSymbol;
            bool m_returnSymbolicAfterFork;
			MemoryInterceptor* m_memoryInterceptor;

			std::istream *m_inputFile;
			bool updateNextMemoryAccess();

			int m_stateId;
			ExecutionTraceMemory *m_nextToMatch;
			ExecutionTraceItemHeader mLastHdr;

			/* return true if the ret value is meaningful */
			bool setValueFromNext(uint64_t address, bool isWrite,
					unsigned size, /* size in bits */
					uint64_t *valueRet);

			/* return true if setup succeeded */
			bool setupRangeListeners(bool *atLeastOneIsConcolic);

			void slotTranslateBlockStart(ExecutionSignal *signal,
					S2EExecutionState *state,
					TranslationBlock *tb,
					uint64_t pc);
			void slotExecuteBlockStart(S2EExecutionState *state,
				 	uint64_t pc);

            void slotStateFork(S2EExecutionState* originalState,
                    const std::vector<S2EExecutionState*>& newStates,
                    const std::vector<klee::ref<klee::Expr> >& newConditions);
	};

class MemoryInterceptorReplayHandler : public MemoryAccessHandler
	{
		public:
			MemoryInterceptorReplayHandler(
					S2E* s2e,
					uint64_t address,
					uint64_t size,
					int mask);
			MemoryInterceptorReplayHandler(
					S2E* s2e,
					uint64_t address,
					uint64_t size,
					int mask,
					bool replayConcolic);

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

			bool m_replayConcolic;
	};

}
}

#endif
