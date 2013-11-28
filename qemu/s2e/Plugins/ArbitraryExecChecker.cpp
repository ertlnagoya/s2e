/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Currently maintained by:
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

//#define NDEBUG

extern "C" {
#include "config.h"
#include "qemu-common.h"
}


#include <sstream>
#include <s2e/ConfigFile.h>



#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <klee/Context.h>
#include <klee/Memory.h>
#include <klee/Solver.h>
#include "ArbitraryExecChecker.h"

using namespace s2e;
using namespace plugins;

S2E_DEFINE_PLUGIN(ArbitraryExecChecker,
                  "Plugin for detecting symbolic values leaked to control flow",
                  "ArbitraryExecChecker");

ArbitraryExecChecker::~ArbitraryExecChecker()
{

}

void ArbitraryExecChecker::initialize()
{
    //Attach the signals
    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &ArbitraryExecChecker::onTranslateInstructionStart));


}

void ArbitraryExecChecker::onTranslateInstructionStart(
    ExecutionSignal *signal,
    S2EExecutionState* state,
    TranslationBlock *tb,
    uint64_t pc)
{

    signal->connect(sigc::mem_fun(*this, &ArbitraryExecChecker::beforeInstruction));
}

/*
 * Before all instructions, we check if some potentially exploitable
 * situations have arosen, ie. if some symbolically injected bits are
 * going to be leaked to SP/PC/LR.
 */
void ArbitraryExecChecker::beforeInstruction(
    S2EExecutionState* state,
    uint64_t pc)
{
    // Abort checks if not running in symbolic mode
    if (state->isRunningConcrete()) {
        return;
    }

    std::stringstream ss;
    bool all_concrete = true;
    target_ulong buf;

    // Check if new LR is symbolic
    if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[14]), &buf, sizeof(buf))) {
      s2e()->getWarningsStream()
          << "[ArbitraryExec]: Symbolic value will into LR at the end of "
          << hexval(state->getPc())  << '\n';
      ss << "Found symbolic LR at instruction" << hexval(pc);
      all_concrete = false;
    }

    // Check if new SP is symbolic
    if (all_concrete && !state->readCpuRegisterConcrete(CPU_OFFSET(regs[13]), &buf, sizeof(buf))) {
      s2e()->getWarningsStream()
          << "[ArbitraryExec]: Symbolic value will leak into SP at the end of "
          << hexval(state->getPc())  << '\n';
      ss << "Found symbolic SP at instruction 0x" << hexval(pc);
      all_concrete = false;
    }

    // Check if we are branching to a symbolic destination
    klee::ref<klee::Expr> expr = state->readMemory(pc, klee::Expr::Int32,
        s2e::S2EExecutionState::PhysicalAddress);
    if (all_concrete && isSymbolicTargetJump(state, expr)) {
        s2e()->getWarningsStream()
            << "[ArbitraryExec]: Will branch to a symbolic destination at the end of "
            << hexval(state->getPc())  << '\n';
        ss << "Symbolic jump target at instruction 0x" << hexval(pc);
        all_concrete = false;
    }

    ArbitraryExecChecker::TaintDetails ret;
    // Check if this is a Load with symbolic source address
    if (all_concrete && (ret = isSymbolicTargetLoad(state, expr)).obj != ArbitraryExecChecker::None) {
        s2e()->getWarningsStream()
            << "[ArbitraryExec]: Loading from a symbolic address at instruction "
            << hexval(pc)  << '\n';
        ss << "Symbolic address for load at 0x" << hexval(pc) << ", coming from ";
        switch (ret.obj) {
        case ArbitraryExecChecker::BaseRegister :
            ss << "base register";
            break;
        case ArbitraryExecChecker::OffsetRegister :
            ss << "offset register";
            break;
        default:
            assert (false && "Unreachable case!");
        }
        //all_concrete = false;
    }

    // Check if this is a Store with symbolic destination address
    if (all_concrete && (ret = isSymbolicTargetStore(state, expr)).obj != ArbitraryExecChecker::None) {
        s2e()->getWarningsStream()
            << "[ArbitraryExec]: Storing to a symbolic address at instruction "
            << hexval(pc)  << '\n';
        ss << "Symbolic address for store at 0x" << hexval(pc) << ", coming from ";
        switch (ret.obj) {
        case ArbitraryExecChecker::BaseRegister :
            ss << "base register\n";
            break;
        case ArbitraryExecChecker::OffsetRegister :
            ss << "offset register\n";
            break;
        default:
            assert (false && "Unreachable case!");
        }
        all_concrete = false;
    }

    s2e()->getWarningsStream().flush();

    if (!all_concrete) {
        // Loading TestCaseGenerator you will get a nice testcase to reach this state
        s2e()->getCorePlugin()->onTestCaseGeneration.emit(state, ss.str());
        s2e()->getExecutor()->terminateStateEarly(*state, ss.str());
        return;
    }

}

/*
 * This function checks if next instruction is going to modify the PC, and then
 * if any symbolic values will leak in it. Return true if so, false otherwise.
 */
bool ArbitraryExecChecker::isSymbolicTargetJump(
    S2EExecutionState* state,
    klee::ref<klee::Expr> expr)
{
    // Start assuming the target is concrete
    bool conc_target = true;
    assert(isa<klee::ConstantExpr>(expr));
#if defined(TARGET_ARM)
    bool isThumb = state->getFlags() & 0x20;
    target_ulong opcode = static_cast<target_ulong>(cast<klee::ConstantExpr>(expr)->getZExtValue());
    target_ulong reg = -1;
    target_ulong buf = 0;
    if (!isThumb) {
        // BLX<reg> register
        if ((opcode & 0x0FF000F0) == 0x01200030) {
            reg = opcode & 0xf;
            if (reg < 15)
                conc_target &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[reg]), &buf, sizeof(buf));
        }
        // TODO: a lot more cases
    } else {
        // BL/BLX register
        uint16_t thumb_opc = opcode & 0x0000FFFF;
        if ((thumb_opc & 0xFF00) == 0x4700) {
            reg = (thumb_opc >> 3) & 0xf;
            if (reg < 15)
                conc_target &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[reg]), &buf, sizeof(buf));
        } else
        // ADD/MOV pc, <Rm>
        if ((thumb_opc & 0xFD47) == 0x4447) {
            reg = (thumb_opc >> 7) & 0x1;
            reg = reg << 4;
            reg |= (thumb_opc >> 3) & 0x7;
            if (reg < 15)
                conc_target &= state->readCpuRegisterConcrete(CPU_OFFSET(regs[reg]), &buf, sizeof(buf));
        } else
        // POP {<Rm>, pc}
        if ((thumb_opc & 0xFF00) == 0xBD00) {
            target_ulong sp = 0;
            target_ulong reg_list = thumb_opc & 0xFF;
            int nreg=0;
            for (int i=0; i < 8; i++) {
                if (reg_list & 0x1)
                  nreg++;
                reg_list >>= 1;
            }
            // Note: SP is guaranteed concrete by previous checks
            state->readCpuRegisterConcrete(CPU_OFFSET(regs[13]), &sp, sizeof(sp));
            // Stack walking to get the stored PC
            conc_target &= state->readMemoryConcrete(sp + nreg*CPU_REG_SIZE, &buf, sizeof(buf));
        }
    }
#endif
    return !conc_target;

}

/*
 * This function checks if next instruction is a Load, and then if any symbolic values
 * have leaked into part of the target address (base register or offset).
 */
ArbitraryExecChecker::TaintDetails ArbitraryExecChecker::isSymbolicTargetLoad(
    S2EExecutionState* state,
    klee::ref<klee::Expr> expr)
{
  // Start assuming the target is concrete
  TaintDetails symb_target = { ArbitraryExecChecker::None, "" } ;
  assert(isa<klee::ConstantExpr>(expr));
  klee::ref<klee::Expr> owned_input;
#if defined(TARGET_ARM)
    bool isThumb = state->getFlags() & 0x20;
    target_ulong opcode = static_cast<target_ulong>(cast<klee::ConstantExpr>(expr)->getZExtValue());
    target_ulong regN = -1;
    target_ulong regM = -1;
    target_ulong buf = 0;
    if (!isThumb) {
        /* LOAD
        if ((opcode & 0xFFFFFFFF) == 0x0) {
            regN = opcode & 0xf;
            if (state->readCpuRegisterConcrete(CPU_OFFSET(regs[regN]), &buf, sizeof(buf)))
                symb_target = ArbitraryExecChecker::BaseRegister;
        }*/
        // TODO: all ARM cases
    } else {
        uint16_t thumb_opc = opcode & 0x0000FFFF;
        if ((thumb_opc & 0xFE00) == 0x5600 ||   // LDRSB Rd, [Rn+Rm]
            (thumb_opc & 0xF800) == 0x5800) {   // LDR<w> Rd, [Rn+Rm]
            regN = (thumb_opc >> 3) & 0x7;
            regM = (thumb_opc >> 6) & 0x7;
            if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[regN]), &buf, sizeof(buf))) {
				symb_target.obj = ArbitraryExecChecker::BaseRegister;
				owned_input = state->readCpuRegister(CPU_OFFSET(regs[regN]), sizeof(buf)*8);
				std::pair< klee::ref<klee::Expr>, klee::ref<klee::Expr> > res = s2e()->getExecutor()->getSolver()->getRange(klee::Query(state->constraints, owned_input));
				std::string ss1, ss2;
				llvm::raw_string_ostream start(ss1), end(ss2);
				cast<klee::ConstantExpr>(res.first)->print(start);
				cast<klee::ConstantExpr>(res.second)->print(end);
				s2e()->getWarningsStream()
					<< "[ArbitraryExec]: Controlled value, input range from "
					<< start.str() << " to " << end.str() << "\n";
            }
            if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[regM]), &buf, sizeof(buf))) {
                symb_target.obj = ArbitraryExecChecker::OffsetRegister;
                owned_input = state->readCpuRegister(CPU_OFFSET(regs[regM]), sizeof(buf)*8);
                std::pair< klee::ref<klee::Expr>, klee::ref<klee::Expr> > res = s2e()->getExecutor()->getSolver()->getRange(klee::Query(state->constraints, owned_input));
				std::string ss1, ss2;
				llvm::raw_string_ostream start(ss1), end(ss2);
				cast<klee::ConstantExpr>(res.first)->print(start);
				cast<klee::ConstantExpr>(res.second)->print(end);
				s2e()->getWarningsStream()
					<< "[ArbitraryExec]: Controlled value, input range from "
					<< start.str() << " to " << end.str() << "\n";
            }

        } else
        if ((thumb_opc & 0xF800) == 0x6800 ||   // LDR Rd, [Rn+offset]
            (thumb_opc & 0xF800) == 0x7800 ||   // LDRB Rd, [Rn+offset]
            (thumb_opc & 0xF800) == 0x8800) {   // LDRH Rd, [Rn+offset]

              regN = (thumb_opc >> 3) & 0x7;
              if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[regN]), &buf, sizeof(buf))) {
		  symb_target.obj = ArbitraryExecChecker::BaseRegister;
		  owned_input = state->readCpuRegister(CPU_OFFSET(regs[regN]), sizeof(buf)*8);
		  std::pair< klee::ref<klee::Expr>, klee::ref<klee::Expr> > res = s2e()->getExecutor()->getSolver()->getRange(klee::Query(state->constraints, owned_input));
		  std::string ss1, ss2;
		  llvm::raw_string_ostream start(ss1), end(ss2);
		  cast<klee::ConstantExpr>(res.first)->print(start);
		  cast<klee::ConstantExpr>(res.second)->print(end);
                  s2e()->getWarningsStream()
                      << "[ArbitraryExec]: Controlled value, input range from "
                      << start.str() << " to " << end.str() << "\n";
              }

        }
        // Otherwise, this is not at interesting Load
      }
#endif
  return symb_target;
}

/*
 * This function checks if next instruction is a STORE, and then if any symbolic values
 * have leaked into part of the target address (base register or offset).
 */
ArbitraryExecChecker::TaintDetails ArbitraryExecChecker::isSymbolicTargetStore(
    S2EExecutionState* state,
    klee::ref<klee::Expr> expr)
{
  // Start assuming the target is concrete
	TaintDetails symb_target = { ArbitraryExecChecker::None, "" } ;
  assert(isa<klee::ConstantExpr>(expr));
#if defined(TARGET_ARM)
    bool isThumb = state->getFlags() & 0x20;
    target_ulong opcode = static_cast<target_ulong>(cast<klee::ConstantExpr>(expr)->getZExtValue());
    target_ulong regN = -1;
    target_ulong regM = -1;
    target_ulong buf = 0;
    if (!isThumb) {
        /* STORE
        if ((opcode & 0xFFFFFFFF) == 0x0) {
            reg = opcode & 0xf;
            if (state->readCpuRegisterConcrete(CPU_OFFSET(regs[regN]), &buf, sizeof(buf)))
                            symb_target = ArbitraryExecChecker::BaseRegister;
        }*/
        // TODO: all ARM cases
    } else {
        uint16_t thumb_opc = opcode & 0x0000FFFF;
        if ((thumb_opc & 0xFE00) == 0x5000 ||   // STR Rd, [Rn+Rm]
            (thumb_opc & 0xF800) == 0x5200 ||   // STRH Rd, [Rn+Rm]
            (thumb_opc & 0xF800) == 0x5400) {   // STRB Rd, [Rn+Rm]
            regN = (thumb_opc >> 3) & 0x7;
            regM = (thumb_opc >> 6) & 0x7;
            if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[regN]), &buf, sizeof(buf)))
                symb_target.obj = ArbitraryExecChecker::BaseRegister;
            if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[regM]), &buf, sizeof(buf)))
                symb_target.obj = ArbitraryExecChecker::OffsetRegister;

        } else
        if ((thumb_opc & 0xF800) == 0x6000 ||   // STR Rd, [Rn+offset]
            (thumb_opc & 0xF800) == 0x7000 ||   // STRB Rd, [Rn+offset]
            (thumb_opc & 0xF800) == 0x8000) {   // STRH Rd, [Rn+offset]

              regN = (thumb_opc >> 3) & 0x7;
              if (!state->readCpuRegisterConcrete(CPU_OFFSET(regs[regN]), &buf, sizeof(buf)))
                  symb_target.obj = ArbitraryExecChecker::BaseRegister;
        }
        // Otherwise, this is not at interesting Load
      }
#endif
  return symb_target;
}
