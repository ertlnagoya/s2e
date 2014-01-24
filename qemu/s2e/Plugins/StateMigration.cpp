#include "StateMigration.h"

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/RemoteMemory.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/cajun/json/reader.h>
#include <s2e/cajun/json/writer.h>

#include <iostream>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StateMigration, "StateMigration -- migrate code from emulator to phisycal device", "StateMigration", "RemoteMemory");

void StateMigration::initialize()
{
	m_start_pc = (uint64_t) s2e()->getConfig()->getInt(
			getConfigKey() + ".startPc");
	m_end_pc = (uint64_t) s2e()->getConfig()->getInt(
			getConfigKey() + ".endPc");
	m_verbose = s2e()->getConfig()->getBool(
			getConfigKey() + ".verbose");
	m_remoteMemory = static_cast<RemoteMemory*>(s2e()->getPlugin("RemoteMemory"));

	s2e()->getCorePlugin()->onTranslateBlockStart.connect(
			sigc::mem_fun(*this, &StateMigration::slotTranslateBlockStart));
	s2e()->getDebugStream() << "[StateMigration]: initialized" << '\n';
}

void StateMigration::slotTranslateBlockStart(ExecutionSignal *signal, 
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc)
{
	if (pc == m_start_pc) {
		s2e()->getDebugStream() << "[StateMigration]: found BB" << '\n';
		signal->connect(sigc::mem_fun(*this, &StateMigration::slotExecuteBlockStart));
	}
}

bool StateMigration::copyToDevice(S2EExecutionState* state,
		uint64_t addr, uint32_t len)
{
	uint8_t *data = (uint8_t *)malloc(len);
	bool ret = state->readMemoryConcrete(addr, data, len);

	printf("[StateMigration]: copying %d bytes from emulator to "
			"device from 0x%08lx\n", len, addr);

	for (int i = 0; i < len; i += 4) {
		uint64_t x = 0;
		x = data[i];
		x = (x << 8) | data[i+1];
		x = (x << 8) | data[i+2];
		x = (x << 8) | data[i+3];
		m_remoteMemory->getInterface()->writeMemory(state, addr+i, 4, x);
	}
	/* issue a dummy read for flushing the writes */
	m_remoteMemory->getInterface()->readMemory(state, addr+len-4, 4);
	printf("[StateMigration]: done copying data to device\n");

	return ret;
}

void StateMigration::putBreakPoint(S2EExecutionState *state, uint64_t addr)
{
	const uint32_t brk_isn = 0xe1200472;
	for (int i = 3; i >= 0; --i) {
		/* XXX: write big endian */
		m_remoteMemory->getInterface()->writeMemory(state, addr+(3-i), 1, (uint64_t)(0xff & (brk_isn >> (8*i))));
	}
	m_remoteMemory->getInterface()->readMemory(state, addr, 4);
	printf("[StateMigration]: done inserting the breakpoint at 0x%08lx\n",
			addr);
}

bool StateMigration::transferStateToDevice(S2EExecutionState *state,
				uint32_t src_regs[16])
{
#ifdef TARGET_ARM
	json::Object request;
	std::tr1::shared_ptr<json::Object> response;
	json::Object cpu_state;
	printf("[StateMigration]: start transfering registers\n");
	/* r0->r14, r15 is pc */
	for (int i = 0; i < 15; i++)
	{
		std::stringstream ss;

		ss << "r";
		ss << i;
		cpu_state.Insert(json::Object::Member(ss.str(),
					json::String(intToHex(src_regs[i]))));
	}
	cpu_state.Insert(json::Object::Member("pc",
				json::String(intToHex(src_regs[15]))));

	request.Insert(json::Object::Member("cmd", json::String("set_cpu_state")));
	request.Insert(json::Object::Member("cpu_state", cpu_state));

	m_remoteMemory->getInterface()->submitAndWait(state, request, response);
	printf("[StateMigration]: done transfering registers\n");
#endif
	return true;
}

bool StateMigration::transferStateFromDevice(S2EExecutionState *state,
				uint32_t dst_regs[16])
{
#ifdef TARGET_ARM
	json::Object request;
	std::tr1::shared_ptr<json::Object> response;
	printf("[StateMigration]: start transfering registers from device\n");
	request.Insert(json::Object::Member("cmd", json::String("get_cpu_state")));
	m_remoteMemory->getInterface()->submitAndWait(state, request, response);

	/* r0->r14, r15 is pc */
	for (int i = 0; i < 15; i++)
	{
		std::stringstream ss;

		ss << "cpu_state_r";
		ss << i;
		json::String &value = (*response)[ss.str()];
		dst_regs[i] = strtol((static_cast<std::string>(value)).c_str(), NULL, 16);
		printf("got val for %s->%08x\n", ss.str().c_str(), dst_regs[i]);
	}
	json::String &value = (*response)["cpu_state_pc"];
	printf("got val for %s->%08x\n", "pc", dst_regs[15]);
	dst_regs[15] = strtol((static_cast<std::string>(value)).c_str(), NULL, 16);

	printf("[StateMigration]: done transfering registers\n");
#endif
	return true;
}

void StateMigration::resumeExecution(S2EExecutionState* state)
{
	json::Object request;
	std::tr1::shared_ptr<json::Object> response;

	printf("[StateMigration]: send continue\n");
	request.Insert(json::Object::Member("cmd", json::String("continue")));
	/* this will wait until the operation is submited, and *not* until
	 * the code reaches a breakpoint
	 */
	m_remoteMemory->getInterface()->submitAndWait(state, request, response);
}

bool StateMigration::getRegsFromState(S2EExecutionState *state,
				uint32_t dst_regs[16])
{
	bool ret = true;

#ifdef TARGET_ARM
#define CPU_NB_REGS 16
#endif
	for (int i = 0; i < CPU_NB_REGS - 1; i++)
	{
		klee::ref<klee::Expr> exprReg =
			state->readCpuRegister(CPU_REG_OFFSET(i),
					CPU_REG_SIZE << 3);
		if (isa<klee::ConstantExpr>(exprReg))
		{
			dst_regs[i] = cast<klee::ConstantExpr>(exprReg)->getZExtValue();
		} else {
			uint32_t example =
				m_s2e->getExecutor()->toConstantSilent(*state,
							exprReg)->getZExtValue();
			dst_regs[i] = example;
			m_s2e->getWarningsStream() << "[RemoteMemory] Register "
				<< i << " was symbolic at "
				<< hexval(state->getPc()) << ", taking " <<
				example << " as an example" << '\n';
			ret = false;
		}
	}
	dst_regs[15] = state->getPc();

	return ret;
}

bool StateMigration::setRegsToState(S2EExecutionState *state,
				uint32_t src_regs[16])
{
#ifdef TARGET_ARM
#define CPU_NB_REGS 16
#endif
	for (int i = 0; i < CPU_NB_REGS - 1; i++) {
		state->writeCpuRegisterConcrete(CPU_REG_OFFSET(i),
				&src_regs[i],
				CPU_REG_SIZE);
	}
	return true;
}

void StateMigration::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
	/* TODO:
	 * 1. migrate data
	 * 2. migrate code
	 * 3. insert trap isn
	 * 4. restore memory (on the device) to previous state
	 * 5. restore state of the emulator
	 */
	/* XXX: asume ARM code */
	uint32_t regs[16];

#if 0
	if (m_verbose) {
		if (ret == false) {
			printf("[StateMigration]: failed to read symbolic mem\n");
		} else {
			printf("[StateMigration]: read concrete mem OK 0x%02hhx%02hhx%02hhx%02hhx\n",
					((uint8_t *) code)[0],
					((uint8_t *) code)[1],
					((uint8_t *) code)[2],
					((uint8_t *) code)[3]);
		}
	}
#endif

	printf("[StateMigration]: start\n");
#if 0
	uint64_t data_len = m_end_pc - m_start_pc + 4; /* including last instruction */
	copyToDevice(state, pc, data_len);
	/* TODO: backup instruction */
	putBreakPoint(state, pc+data_len-4);
#endif

#if 0
	uint32_t backup_isn;
	uint32_t brk_isn = 0xe1200472;
	printf("[StateMigration]: copying %ld bytes from emulator to "
			"device\n", data_len);
	backup_isn = *((uint32_t *)(&code[data_len-4]));
	for (int i = 0; i < data_len-4; ++i)
		remoteMemoryInterface->writeMemory(state, pc+i, 1, (uint64_t)code[i]);
	*((uint32_t *)(&code[data_len-4])) = brk_isn;
	for (int i = 3; i >= 0; --i) {
		/* XXX: write big endian */
		remoteMemoryInterface->writeMemory(state, pc+data_len-4+(3-i), 1, (uint64_t)(0xff & (brk_isn >> (8*i))));
	}
	uint64_t dummy = remoteMemoryInterface->readMemory(state, pc+data_len-4, 4);
	/* issue a dummy read for flushing the writes */
	//printf("[StateMigration]: read done: 0x%016lx\n", dummy);
	printf("[StateMigration]: done copying the code and inserting the"
			" breakpoint: 0x%016lx\n", dummy);
#endif

#if 0
	printf("[StateMigration]: submitting dummy request\n");
	json::Object request;
	std::tr1::shared_ptr<json::Object> response;
	request.Insert(json::Object::Member("cmd", json::String("ping")));
	remoteMemoryInterface->submitAndWait(state, request, response);
	printf("[StateMigration]: waiting reply\n");
	json::String &r = (*response)["reply"];
	printf("[StateMigration]: got reply: %s\n",
			(static_cast<std::string>(r)).c_str());
#endif

#if 1
	uint32_t brk_isn = 0xe1200472;
	for (int i = 3; i >= 0; --i) {
		/* XXX: write big endian */
		/* write two break instructions because the bootloader checks if
		 * there's a break ins
		 */
		printf("[StateMigration]: ptr\n");
		m_remoteMemory->getInterface()->writeMemory(state, 0x18004+(3-i), 1, (uint64_t)(0xff & (brk_isn >> (8*i))));
		m_remoteMemory->getInterface()->writeMemory(state, 0x18000+(3-i), 1, (uint64_t)(0xff & (brk_isn >> (8*i))));
	}
#endif

	getRegsFromState(state, regs);
	regs[15] = 0x18000;
	transferStateToRegisters(state, regs);

	/* continue */
	resumeExecution(state);
	m_remoteMemory->getInterface()->readMemory(state, 0x18000, 4);
	printf("[StateMigration]: done\n");
	assert(0);

	/* This is a test */
# if 0
	val = remoteMemoryInterface->readMemory(state, 0x12f38, 4);
	printf("[StateMigration]: read through remote mem: 0x%016lx\n",
			val);

	remoteMemoryInterface->writeMemory(state, 0x12f38, 1, (uint64_t)'A');
	val = remoteMemoryInterface->readMemory(state, 0x12f38, 4);
	printf("[StateMigration]: read after write: 0x%016lx\n",
			val);
#endif
}

}
}

