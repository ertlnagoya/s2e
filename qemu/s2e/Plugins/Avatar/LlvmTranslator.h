#ifndef S2E_PLUGINS_LLVM_TRANSLATOR_H
#define S2E_PLUGINS_LLVM_TRANSLATOR_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class LlvmTranslator : public Plugin
	{
		S2E_PLUGIN
		public:
			LlvmTranslator(S2E* s2e): Plugin(s2e) {m_s2e = s2e;}
			llvm::Function *get_llvm_func(TranslationBlock *tb);
			void initialize();
		private:
			S2E* m_s2e;
			struct TCGLLVMContext* m_llvm_ctx;
	};

}
}

#endif
