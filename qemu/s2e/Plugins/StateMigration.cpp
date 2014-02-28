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

bool StateMigration::addFunc(const std::string &entry)
{
	std::stringstream ss;
	std::string sk;
	struct target_function new_func;
	ss << getConfigKey() + ".funcs_to_migrate" << "." << entry;
	sk = ss.str();

	new_func.func_name = entry;
	new_func.start_pc = (uint64_t) s2e()->getConfig()->getInt(
			sk + ".startPc");
	new_func.end_pc = (uint64_t) s2e()->getConfig()->getInt(
			sk + ".endPc");
	new_func.pre_addr = (uint64_t) s2e()->getConfig()->getInt(sk + ".pre_addr");
	new_func.pre_len = (uint32_t) s2e()->getConfig()->getInt(sk + ".pre_len");
	new_func.migrate_stack = s2e()->getConfig()->getBool(sk + ".migrate_stack");
	new_func.migrate_code = s2e()->getConfig()->getBool(sk + ".migrate_code", true);
	if (new_func.migrate_stack)
		new_func.stack_size = (uint32_t) s2e()->getConfig()->getInt(sk + ".stack_size", 256);

	m_functions.push_back(new_func);
	return true;
}

void StateMigration::initialize()
{
	std::vector<std::string> functions;
	functions = s2e()->getConfig()->getListKeys(getConfigKey()+".funcs_to_migrate");

	foreach2(it, functions.begin(), functions.end()) {
		addFunc(*it);
	}

	m_verbose = s2e()->getConfig()->getBool(
			getConfigKey() + ".verbose");
	m_remoteTargetHasCRC = s2e()->getConfig()->getBool(
			getConfigKey() + ".remoteTargetHasCRC", false);
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
	for (std::vector<struct target_function>::iterator it = m_functions.begin();
			it != m_functions.end();
			++it) {
		if (pc == it->start_pc) {
			s2e()->getDebugStream() << "[StateMigration]: found BB" << '\n';
			signal->connect(sigc::mem_fun(*this,
						&StateMigration::slotExecuteBlockStart));
		}
	}
}

bool StateMigration::areTheBuffersInSync(S2EExecutionState *state,
		uint64_t addr, uint32_t len)
{
	if (len == 0)
		return true;
	if (len <= 4)
		return false;
	if (m_remoteTargetHasCRC == false)
		return false;

	uint8_t *data = (uint8_t *)malloc(len);
	state->readMemoryConcrete(addr, data, len);
	uint8_t local_crc = CRC::crc_calc_buf(data, len);
	uint8_t remote_crc = getRemoteChecksum(state, addr, len);

	if (local_crc != remote_crc) {
		free(data);
		return false;
	} else {
		/* crc the same, reduce probability of collision by
		 * computing the CRC for half of the buffer
		 */
		int mid = len/2;
		if (CRC::crc_calc_buf(data, mid) !=
				getRemoteChecksum(state, addr, mid)) {
			free(data);
			return false;
		} else if (CRC::crc_calc_buf(&data[mid], len-mid) !=
				getRemoteChecksum(state, addr+mid, len-mid)) {
			free(data);
			return false;
		}
	}
	free(data);
	return true;
}

bool StateMigration::copyToDevice(S2EExecutionState* state,
		uint64_t addr, uint32_t len)
{
	bool should_copy = !areTheBuffersInSync(state, addr, len);

	//printf("[StateMigration]: copying %d bytes from emulator to "
	//		"device from 0x%08lx\n", len, addr);

	if (!should_copy) {
		printf("[StateMigration]: copy_to_device: DO not copy!\n");
		return false;
	} else
		printf("[StateMigration]: copy_to_device: DO copy!\n");

	uint8_t *data = (uint8_t *)malloc(len);
	bool ret = state->readMemoryConcrete(addr, data, len);
	for (int i = 0; i < len; i += 4) {
		uint64_t x = 0;
#ifdef TARGET_WORDS_BIGENDIAN
		x = (x << 8) | data[i+0];
		x = (x << 8) | data[i+1];
		x = (x << 8) | data[i+2];
		x = (x << 8) | data[i+3];
#else
		x = (x << 8) | data[i+3];
		x = (x << 8) | data[i+2];
		x = (x << 8) | data[i+1];
		x = (x << 8) | data[i+0];
#endif
		m_remoteMemory->getInterface()->writeMemory(state, addr+i, 4, x);
	}
	/* issue a dummy read for flushing the writes */
	m_remoteMemory->getInterface()->readMemory(state, addr+len-4, 4);
	//printf("[StateMigration]: done copying data to device\n");

	free(data);

	return ret;
}

bool StateMigration::copyFromDevice(S2EExecutionState* state,
		uint64_t addr, uint32_t len)
{
	bool ret;
	bool should_copy = !areTheBuffersInSync(state, addr, len);
	//printf("[StateMigration]: copy from device \n");

	if (!should_copy) {
		printf("[StateMigration]: copy_from_device: DO not copy!\n");
		return false;
	} else
		printf("[StateMigration]: copy_from_device: DO copy!\n");

	assert(len % 4 == 0);
	uint8_t *data = (uint8_t *)malloc(len);
	for (int i = 0; i < len; i += 4) {
		uint64_t x;
		x = m_remoteMemory->getInterface()->readMemory(state, addr+i, 4);
#ifdef TARGET_WORDS_BIGENDIAN
		data[i+3] = (uint8_t)((x >> 0 ) & 0xff);
		data[i+2] = (uint8_t)((x >> 8 ) & 0xff);
		data[i+1] = (uint8_t)((x >> 16) & 0xff);
		data[i+0] = (uint8_t)((x >> 24) & 0xff);
#else
		data[i+0] = (uint8_t)((x >> 0 ) & 0xff);
		data[i+1] = (uint8_t)((x >> 8 ) & 0xff);
		data[i+2] = (uint8_t)((x >> 16) & 0xff);
		data[i+3] = (uint8_t)((x >> 24) & 0xff);
#endif
	}

	ret = state->writeMemoryConcrete(addr, data, len);
	free(data);

	return ret;
}


uint32_t StateMigration::writeMemory32(S2EExecutionState *state,
		uint64_t addr, const uint32_t val)
{
#ifdef TARGET_WORDS_BIGENDIAN
	return writeMemoryBe_32(state, addr, val);
#else
	return writeMemoryLe_32(state, addr, val);
#endif
}

uint32_t StateMigration::writeMemoryLe_32(S2EExecutionState *state,
		uint64_t addr, const uint32_t val)
{
	uint32_t old_data;
	old_data = m_remoteMemory->getInterface()->readMemory(state, addr, 4);
	for (int i = 3; i >= 0; --i) {
		m_remoteMemory->getInterface()->writeMemory(state, addr+i, 1, (uint64_t)(0xff & (val >> (8*i))));
	}
	m_remoteMemory->getInterface()->readMemory(state, addr, 4);
	return old_data;
}

uint32_t StateMigration::writeMemoryBe_32(S2EExecutionState *state, uint64_t addr, const uint32_t val)
{
	uint32_t old_data;
	old_data = m_remoteMemory->getInterface()->readMemory(state, addr, 4);
	for (int i = 3; i >= 0; --i) {
		m_remoteMemory->getInterface()->writeMemory(state, addr+(3-i), 1, (uint64_t)(0xff & (val >> (8*i))));
	}
	m_remoteMemory->getInterface()->readMemory(state, addr, 4);
	return old_data;
}

uint32_t StateMigration::putBreakPoint(S2EExecutionState *state, uint64_t addr)
{
	const uint32_t brk_isn = 0xe1200472;
	uint32_t ret;
	ret = this->writeMemory32(state, addr, brk_isn);
	printf("[StateMigration]: done inserting the breakpoint at 0x%08lx\n",
			addr);
	return ret;
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
	dst_regs[15] = strtol((static_cast<std::string>(value)).c_str(), NULL, 16);
	printf("got val for %s->%08x\n", "pc", dst_regs[15]);

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

uint32_t StateMigration::getEmulatorChecksum(S2EExecutionState* state,
		uint32_t addr,
		uint32_t len)
{
	uint8_t *data = (uint8_t *)malloc(len);
	bool ret = state->readMemoryConcrete(addr, data, len);
	uint8_t crc;
	if (!ret) {
		printf("[StateMigration]: failed to get crc\n");
		return 0;
	}
	crc = CRC::crc_calc_buf(data, len);
	free(data);
	printf("[StateMigration]: local checksum: %08hhx\n", crc);
	return crc;
}

uint32_t StateMigration::getRemoteChecksum(S2EExecutionState* state,
		uint32_t address,
		uint32_t size)
{
	json::Object request;
	json::Object params;
	std::tr1::shared_ptr<json::Object> response;

	assert(m_remoteTargetHasCRC == true);
	printf("[StateMigration]: send checksum request\n");
	request.Insert(json::Object::Member("cmd", json::String("get_checksum")));
	params.Insert(json::Object::Member("address", json::String(intToHex(address))));
	params.Insert(json::Object::Member("size", json::String(intToHex(size))));
	request.Insert(json::Object::Member("params", params));
	m_remoteMemory->getInterface()->submitAndWait(state, request, response);
	json::String &value = (*response)["value"];
	uint32_t ret = (uint32_t)strtol((static_cast<std::string>(value)).c_str(), NULL, 16);
	printf("[StateMigration]: got checksum: 0x%08x\n", ret);
	return ret;
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
	for (int i = 0; i < CPU_NB_REGS-1; i++) {
		state->writeCpuRegisterConcrete(CPU_REG_OFFSET(i),
				&src_regs[i],
				CPU_REG_SIZE);
	}
	state->setPc(src_regs[15]);
	return true;
}

void StateMigration::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
{
	/* XXX: this might be too slow */
	for (std::vector<struct target_function>::iterator it = m_functions.begin();
			it != m_functions.end();
			++it) {
		if (pc == it->start_pc) {
			doMigration(state, *it);
			return;
		}
	}
}

void StateMigration::doMigration(S2EExecutionState *state,
		struct target_function func)
{
#ifndef TARGET_ARM
	assert(0 && "only arch arm is supported");
#endif

	/* XXX: func is copied
	 * 1. migrate data
	 * 2. migrate code
	 * 3. insert trap isn
	 * 4. restore memory (on the device) to previous state
	 * 5. restore state of the emulator
	 */
	/* XXX: asume ARM code */
	uint32_t regs[16];

	printf("[StateMigration]: start [%s]\n", func.func_name.c_str());

	getRegsFromState(state, regs);

	/* migrate pre buffer */
	printf("[StateMigration]: migrate some data\n");
	copyToDevice(state, func.pre_addr, func.pre_len);

	if (func.migrate_stack) {
		/* migrate some stack */
		uint32_t sp = regs[13];
		printf("[StateMigration]: migrate some stack: 0x%08x\n", sp);
		copyToDevice(state, sp, func.stack_size);
	}

	/* migrate code */
	assert(func.start_pc < func.end_pc);
	/* code_len including last instruction */
	uint64_t code_len = func.end_pc - func.start_pc + 4;
	if (func.migrate_code) {
		/* we might want to skip code migration
		 * something is broken and we're reading 0's if the code is not
		 * mapped into the host emulator
		 */
		printf("[StateMigration]: migrate some code\n");
		copyToDevice(state, func.start_pc, code_len);
	}
	/* XXX: backup instruction, we don't really need this */
	uint32_t old_isn = putBreakPoint(state, func.end_pc);

	/* migrate code state */
	transferStateToDevice(state, regs);

	/* continue */
	printf("[StateMigration]: resuming\n");
	resumeExecution(state);
	/* XXX: remove this fake read */
	m_remoteMemory->getInterface()->readMemory(state, 0x18000, 4);

	printf("[StateMigration]: transfering state from device\n");
	transferStateFromDevice(state, regs);
	setRegsToState(state, regs);

	if (func.migrate_stack) {
		uint32_t new_sp = regs[13];
		printf("[StateMigration]: migrate some stack back\n");
		copyFromDevice(state, new_sp, func.stack_size);
	}
	/* restore instruction */
	this->writeMemory32(state, func.end_pc, old_isn);
	/* XXX: remove */
	getRegsFromState(state, regs);
	/* migrate back the stack */
	printf("[StateMigration]: resuming @0x%08x [%s]\n", regs[15], func.func_name.c_str());
	throw CpuExitException();
}

}
}

