#ifndef S2E_PLUGINS_CHECK_MEMORY_ACCESSES_ACCESSES_H
#define S2E_PLUGINS_CHECK_MEMORY_ACCESSES_ACCESSES_H 1

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
void s2e_symbolic_write_to_concrete_memory(
		const klee::MemoryObject* mo,
		klee::ref< klee::Expr > offset,
		klee::ref< klee::Expr > value);
namespace plugins {

class CheckMemoryAccesses : public Plugin
	{
		S2E_PLUGIN
		public:
			CheckMemoryAccesses(S2E* s2e): Plugin(s2e) {m_s2e = s2e;}
			bool checkAddress(S2EExecutionState *state, klee::ref<klee::Expr> addr);
			void initialize();
		private:
			S2E* m_s2e;
			/* this can be made public */
			typedef std::pair<std::string, std::vector<unsigned char> > VarValuePair;
			typedef std::vector<VarValuePair> ConcreteInputs;
			bool loadMemoryMap(std::istream *fin);
			bool m_verbose;
			klee::ConstraintManager *map_constraints;
			void onDataMemoryAccess(S2EExecutionState *state,
					klee::ref<klee::Expr> virtualAddress,
					klee::ref<klee::Expr> hostAddress,
					klee::ref<klee::Expr> value,
					bool isWrite, bool isIO, bool isCode);
			struct range {
				uint32_t start;
				uint32_t size;
			};
			std::vector<struct range> m_validRanges;
			void printSolutions(S2EExecutionState *state);
			bool isOneMemoryAccessValid(uint64_t addr);
	};
}
}

#endif
