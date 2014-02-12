#include "LlvmTranslator.h"

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <llvm/Function.h>

#include <iostream>

#include "tcg-llvm.h"
#include "tcg.h"
#include "exec-all.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LlvmTranslator, "LlvmTranslator -- transform code to LLVM IR", "LlvmTranslator");

void LlvmTranslator::initialize()
{
	m_llvm_ctx = m_s2e->getTcgLLVMContext();
}

llvm::Function *LlvmTranslator::get_llvm_func(TranslationBlock *tb)
{
	TranslationBlock new_block;
	llvm::Function *ret;
	TCGContext *s = &tcg_ctx;

	memcpy(&new_block, tb, sizeof *tb);

	tcg_llvm_tb_alloc(&new_block);
	tcg_llvm_gen_code(m_llvm_ctx, s, &new_block);
	//const char* tcg_llvm_get_func_name(struct TranslationBlock *tb);

	/* erase from parent */
	tcg_llvm_tb_free(tb);

	ret = static_cast<llvm::Function *>(new_block.llvm_function);
	return ret;
}

llvm::Function *LlvmTranslator::filter_llvm_func(llvm::Function *func)
{
	using namespace llvm;

	for (Function::iterator bb = func->begin(), bbe = func->end(); bb != bbe; ++bb) {
		BasicBlock& b = *bb;
		printf("llvm_bb\n");
		for (BasicBlock::iterator ins = b.begin(), ie = b.end(); ins != ie; ++ins) {
			std::string msg("llvm_ins: ");
			llvm::raw_string_ostream s(msg);
			if (CallInst *ci = dyn_cast<CallInst>(&*ins)) {
				Function *called_func = ci->getCalledFunction();
				s << "llvm_call: ";
				s << *ci << "->" << *called_func;
			} else {
				s << "llvm_ins: " << *ins;
			}
			printf("%s\n", s.str().c_str());
		}
	}
	return func;
}

}
}


