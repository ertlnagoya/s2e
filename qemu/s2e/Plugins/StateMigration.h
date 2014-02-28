
/*
 * Copyright 2014 Lucian Cojocar <lucian.cojocar@vu.nl> VU
 */

#ifndef S2E_STATE_MIGRATION_H
#define S2E_STATE_MIGRATION_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/RemoteMemory.h>

namespace s2e {
namespace plugins {
class StateMigration : public Plugin
{
	S2E_PLUGIN
	public:
		StateMigration(S2E* s2e): Plugin(s2e) {m_s2e = s2e;}
		void initialize();

		void slotTranslateBlockStart(ExecutionSignal*, S2EExecutionState
				*state, TranslationBlock *tb, uint64_t pc);
		void slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc);

	private:
		bool m_verbose;
		bool m_remoteTargetHasCRC;
		RemoteMemory *m_remoteMemory;
		std::tr1::shared_ptr<RemoteMemoryInterface> m_remoteMemoryInterface;
		bool copyToDevice(S2EExecutionState* state, uint64_t addr, uint32_t len);
		bool copyFromDevice(S2EExecutionState* state, uint64_t addr, uint32_t len);
		uint32_t putBreakPoint(S2EExecutionState* state, uint64_t addr);
		void resumeExecution(S2EExecutionState* state);
		bool transferStateToDevice(S2EExecutionState *state,
				uint32_t src_regs[16]);
		bool transferStateFromDevice(S2EExecutionState *state,
				uint32_t dst_regs[16]);
		bool getRegsFromState(S2EExecutionState *state,
				uint32_t dst_regs[16]);
		bool setRegsToState(S2EExecutionState *state,
				uint32_t src_regs[16]);
		uint32_t getRemoteChecksum(S2EExecutionState* state, uint32_t addr, uint32_t len);
		uint32_t getEmulatorChecksum(S2EExecutionState* state, uint32_t addr, uint32_t len);
		S2E *m_s2e;
		uint32_t writeMemoryBe_32(S2EExecutionState *state,
				uint64_t addr, const uint32_t val);
		uint32_t writeMemory32(S2EExecutionState *state,
				uint64_t addr, const uint32_t val);
		uint32_t writeMemoryLe_32(S2EExecutionState *state,
				uint64_t addr, const uint32_t val);
		/* return true if the buffers are the same */
		bool areTheBuffersInSync(S2EExecutionState *state,
				uint64_t addr, uint32_t len);
		bool addFunc(const std::string &entry);
		struct target_function {
			std::string func_name;
			uint64_t start_pc;
			uint64_t end_pc;
			/* TODO: migrate post buffer migration */
			uint64_t pre_addr;
			uint32_t pre_len;

			uint64_t post_addr;
			uint32_t post_len;

			bool migrate_stack;
			uint32_t stack_size;
		};
		void doMigration(S2EExecutionState *state, struct target_function func);
		std::vector<struct target_function> m_functions;
		class CRC {
			/**
			 * Calculate CRC8 of the data.
			 * The polynom used is the same as for Dallas iButton products.
			 */
			public:
				static unsigned char crc_calc(uint8_t * crc, uint8_t data) {
					static const unsigned char r1[16] = {
						0x00, 0x5e, 0xbc, 0xe2, 0x61, 0x3f, 0xdd, 0x83,
						0xc2, 0x9c, 0x7e, 0x20, 0xa3, 0xfd, 0x1f, 0x41,
					};

					static const unsigned char r2[16] = {
						0x00, 0x9d, 0x23, 0xbe, 0x46, 0xdb, 0x65, 0xf8,
						0x8c, 0x11, 0xaf, 0x32, 0xca, 0x57, 0xe9, 0x74
					};
					int i = (data ^ *crc) & 0xff;

					*crc = r1[i&0xf] ^ r2[i>>4];
					return *crc;
				}
				static uint8_t crc_calc_buf(uint8_t *buf, uint32_t len) {
					uint8_t crc = 0;
					for (int i = 0; i < len; ++i) {
						CRC::crc_calc(&crc, buf[i]);
					}
					return crc;
				}
		};
};

}
}
#endif
