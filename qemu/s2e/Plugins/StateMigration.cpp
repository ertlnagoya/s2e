#include "StateMigration.h"

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/RemoteMemory.h>

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
	uint64_t data_len = m_end_pc - m_start_pc + 4; /* including last instruction */
	uint8_t *code = (uint8_t *)malloc(data_len);
	//void *data = NULL; /* TODO, copy data */
	bool ret = state->readMemoryConcrete(pc, code, data_len);
	std::tr1::shared_ptr<RemoteMemoryInterface> remoteMemoryInterface = m_remoteMemory->getInterface();

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

	//uint64_t val = remoteMemoryInterface->readMemory(state, pc, 4);
	uint32_t backup_isn;
	uint32_t brk_isn = 0xe1200472;
		/*
	printf("[StateMigration]: read through remote mem: 0x%016lx\n",
			val);
			*/
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
	printf("[StateMigration]: done\n");
	uint64_t dummy = remoteMemoryInterface->readMemory(state, pc+data_len-4, 4);
	/* issue a dummy read for flushing the writes */
	printf("[StateMigration]: read done: 0x%016lx\n", dummy);
	//while (1)
	//	;
	assert(0);
	//printf("[StateMigration]: adding instruction 0x%02hhx%02hhx%02hhx%02hhx\n",
	//		((uint8_t *) code)[data_len-4],
	//		((uint8_t *) code)[data_len-3],
	//		((uint8_t *) code)[data_len-2],
	//		((uint8_t *) code)[data_len-1]);

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

