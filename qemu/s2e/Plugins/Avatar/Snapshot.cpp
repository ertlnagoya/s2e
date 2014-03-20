/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2014, EURECOM
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
 *    Jonas Zaddach <zaddach@eurecom.fr>
 *    Lucian Cojocar <lucian.cojocar@vu.nl>
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

#include "Snapshot.h"
#include <s2e/S2E.h>
#include <s2e/Utils.h>

extern "C" {
#include <sysemu.h>
}

#include <llvm/Support/Path.h>
#include <llvm/Support/FileSystem.h>

#include <stdexcept>

extern "C" CPUArchState* env;

static const uint32_t S2E_SS_FILE_MAGIC = 0x51533245;
static const uint32_t S2E_SS_FILE_VERSION = 1;

enum S2ESnapshotSectionTypes
{
	S2E_SS_SECTION_TYPE_CPU = 0,
	S2E_SS_SECTION_TYPE_MACHINE = 1
};

enum S2ESnapshotSectionMarkers
{
	S2E_SS_EOF = 0,
	S2E_SS_SECTION_START = 0xfe,
};

//Architecture; entries are compatible to ELF e_machine field
enum S2ESnapshotArchitectures
{
	S2E_SS_ARCH_I386 = 0x03,
	S2E_SS_ARCH_X86_64 = 0x3e,
	S2E_SS_ARCH_ARM = 0x28,
};

enum S2ESnapshotEndianess
{
	S2E_SS_ENDIAN_LITTLE = 0,
	S2E_SS_ENDIAN_BE32 = 1,
	S2E_SS_ENDIAN_BE8 = 2
};

static const char* S2E_SS_SECTION_NAME_CPU = "cpu";
static const char* S2E_SS_SECTION_NAME_MACHINE = "machine";

static const unsigned MAX_SNAPSHOT_FILES = 1000;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Snapshot, "Snapshot taking and reverting from S2E", "Snapshot",);

Snapshot* Snapshot::s_self = NULL;

int Snapshot::luaTakeSnapshot(lua_State* L)  {
	assert(s_self);

	std::string name = lua_tostring(L, lua_gettop(L));
	unsigned flags = lua_tointeger(L, lua_gettop(L) - 1);
	s_self->takeSnapshot((S2EExecutionState*) g_s2e_state, name, flags);

	return 0;
}

Snapshot::Snapshot(S2E* s2e) : Plugin(s2e), m_verbose(false)
{
	s_self = this;
}

typedef int (*LuaFunctionPointer)(lua_State*);

static void lua_register_c_function(lua_State* L, char const * const tableName, char const * const funcName, LuaFunctionPointer funcPointer)
{
    lua_getglobal(L, tableName);  // push table onto stack
    if (!lua_istable(L, lua_gettop(L)))                       // not a table, create it
    {
        lua_createtable(L, 0, 1);      // create new table
        lua_setglobal(L, tableName);  // add it to global context

        // reset table on stack
        lua_pop(L, 1);                  // pop table (nil value) from stack
        lua_getglobal(L, tableName);    // push table onto stack
    }

    lua_pushstring(L, funcName);       // push key onto stack
    lua_pushcclosure(L, funcPointer, 0); // push value onto stack
    lua_settable(L, lua_gettop(L) - 2);               // add key-value pair to table

    lua_pop(L, 1);                     // pop table from stack
}


void Snapshot::initialize()
{
	bool existed;
	m_verbose = s2e()->getConfig()->getBool(getConfigKey() + ".verbose", false);
	m_snapshotFolder = s2e()->getOutputFilename("snapshots");
	llvm::sys::fs::create_directories(m_snapshotFolder, existed);

	//register lua functions
	lua_register_c_function(s2e()->getConfig()->getState(), "Snapshot", "takeSnapshot", &Snapshot::luaTakeSnapshot);

	m_restoreFile = s2e()->getConfig()->getString(
	                        getConfigKey() + ".restore", "");

	if (m_restoreFile != "")  {
		m_connection = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
				sigc::mem_fun(*this, &Snapshot::slotTranslateBlockStart));
	}
	if (m_verbose) {
		s2e()->getDebugStream() << "[Snapshot] initialized, saving snapshot in "
				<< m_snapshotFolder << " "
				<< (existed ? "(existed)" : "(created)") << '\n';
	}

 //   m_traceBlockTranslation = s2e()->getConfig()->getBool(
 //                       getConfigKey() + ".traceBlockTranslation");
 //   m_traceBlockExecution = s2e()->getConfig()->getBool(
 //                       getConfigKey() + ".traceBlockExecution");

//    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
//            sigc::mem_fun(*this, &Example::slotTranslateBlockStart));
}

//void Example::slotTranslateBlockStart(ExecutionSignal *signal,
//                                      S2EExecutionState *state,
//                                      TranslationBlock *tb,
//                                      uint64_t pc)
//{
//    if(m_traceBlockTranslation)
//        std::cout << "Translating block at " << std::hex << pc << std::dec << std::endl;
//    if(m_traceBlockExecution)
//        signal->connect(sigc::mem_fun(*this, &Example::slotExecuteBlockStart));
//}
//
//void Example::slotExecuteBlockStart(S2EExecutionState *state, uint64_t pc)
//{
//    std::cout << "Executing block at " << std::hex << pc << std::dec << std::endl;
//}


void Snapshot::slotTranslateBlockStart(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            TranslationBlock *tb,
            uint64_t pc)
{
	m_connection.disconnect();
	m_connection = signal->connect(sigc::mem_fun(*this, &Snapshot::slotExecuteBlockStart));
}

void Snapshot::slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc)
{
	m_connection.disconnect();
	s2e()->getDebugStream() << "[Snapshot] DEBUG: Restoring snapshot from file " << m_restoreFile << '\n';
	restoreSnapshot(m_restoreFile);
}

class QemuSnapshotError : public std::runtime_error
{
public:
	QemuSnapshotError(std::string message, int errorCode) : runtime_error(message), m_errorCode(errorCode) {}
	virtual int getErrorCode() {return m_errorCode;}
private:
	int m_errorCode;
};

void Snapshot::saveStart(QEMUFile* fh)
{
	qemu_put_be32(fh, S2E_SS_FILE_MAGIC);
	qemu_put_be32(fh, S2E_SS_FILE_VERSION);
}

static void qemu_put_string(QEMUFile* fh, const char * str)
{
	uint16_t len = strlen(str);
	qemu_put_be16(fh, len);
	qemu_put_buffer(fh, reinterpret_cast<const uint8_t *>(str), len);
}

void Snapshot::saveMachine(QEMUFile* fh)
{
	uint32_t section_start = qemu_ftell(fh);
	qemu_put_byte(fh, S2E_SS_SECTION_START);
	qemu_put_be32(fh, 0); //dummy length field
	qemu_put_be32(fh, S2E_SS_SECTION_TYPE_MACHINE);
	qemu_put_string(fh, S2E_SS_SECTION_NAME_MACHINE);
	qemu_put_be32(fh, 0); //Currently we only have version 0 for this section
	qemu_put_string(fh, s2e_machine_name);
	qemu_put_byte(fh, getSystemEndianness());
	uint32_t section_end = qemu_ftell(fh);
	qemu_fseek(fh, section_start + 1, SEEK_SET);
	//Write correct section size
	qemu_put_be32(fh, section_end - section_start);
	qemu_fseek(fh, section_end, SEEK_SET);
}

void Snapshot::saveCpu(QEMUFile* fh)
{
	/* Section type */
	uint32_t section_start = qemu_ftell(fh);
	qemu_put_byte(fh, S2E_SS_SECTION_START);
	qemu_put_be32(fh, 0); //dummy length field
	qemu_put_be32(fh, S2E_SS_SECTION_TYPE_CPU);
	//Section ID string
	qemu_put_string(fh, S2E_SS_SECTION_NAME_CPU);
    qemu_put_be32(fh, CPU_SAVE_VERSION);
    qemu_put_byte(fh, getSystemArchitecture());
	/* ID string */
	qemu_put_string(fh, s2e_cpu_name);
	cpu_save(fh, env);

	uint32_t section_end = qemu_ftell(fh);
	qemu_fseek(fh, section_start + 1, SEEK_SET);
	//Write correct section size
	qemu_put_be32(fh, section_end - section_start);
	qemu_fseek(fh, section_end, SEEK_SET);
}

uint8_t Snapshot::getSystemEndianness()
{
#ifdef TARGET_WORDS_BIGENDIAN
	return S2E_SS_ENDIAN_BE8;
#else
	return S2E_SS_ENDIAN_LITTLE;
#endif /* TARGET_WORDS_BIGENDIAN */

}

uint8_t Snapshot::getSystemArchitecture()
{
#ifdef TARGET_I386
	return 2E_SS_ARCH_I386;
#elif defined(TARGET_X86_64)
	return S2E_SS_ARCH_X86_64;
#elif defined(TARGET_ARM)
	return S2E_SS_ARCH_ARM;
#else
#error "Unknown architecture"
	return 0;
#endif /* TARGET_I386 */
}

void Snapshot::restoreMachine(QEMUFile* fh, uint32_t size)
{
	uint32_t version = qemu_get_be32(fh); size -= 4;
	if (version != 0)  {
		throw std::runtime_error("Unknown version for section machine");
	}
	uint16_t name_len = qemu_get_be16(fh); size -= 2;
	char name[name_len + 1];
	qemu_get_buffer(fh, (unsigned char *) name, name_len); size -= name_len;
	name[name_len] = 0;
	uint8_t endianness = qemu_get_byte(fh); size -= 1;

	if (strcmp(name, s2e_machine_name) != 0)  {
		throw std::runtime_error("Current QEMU machine does not match machine from snapshot");
	}

	if (getSystemEndianness() != endianness)  {
		throw std::runtime_error("Current QEMU machine endianness does not match machine endianness from snapshot");
	}

	if (size != 0)  {
		s2e()->getWarningsStream() << "Machine section size: " << size << '\n';
		throw std::runtime_error("Machine section has wrong size");
	}
}

void Snapshot::restoreCpu(QEMUFile* fh, uint32_t size)
{
	uint32_t version = qemu_get_be32(fh); size -= 4;
	uint8_t architecture = qemu_get_byte(fh); size -= 1;
	uint16_t model_len = qemu_get_be16(fh); size -= 2;
	char model[model_len + 1];
	qemu_get_buffer(fh, (unsigned char *) model, model_len); size -= model_len;
	model[model_len] = 0;

	if (version != CPU_SAVE_VERSION || architecture != getSystemArchitecture())  {
		throw std::runtime_error("Version or architecture of snapshot file wrong or not implemented");
	}

	uint32_t pos_before = qemu_ftell(fh);
	cpu_load(fh, env, version);
	size -= (qemu_ftell(fh) - pos_before);

	if (size != 0)  {
		s2e()->getWarningsStream() << "Cpu section size: " << size << '\n';
		throw std::runtime_error("Cpu section has wrong size");
	}
}

void Snapshot::restoreSnapshot(std::string filename)
{
	QEMUFile* fh = qemu_fopen(filename.c_str(), "rb");

	//Check header
	if (qemu_get_be32(fh) != S2E_SS_FILE_MAGIC)  {
		throw std::runtime_error("Invalid snapshot file magic");
	}

	uint32_t version = qemu_get_be32(fh);
	if (version != S2E_SS_FILE_VERSION)  {
		throw std::runtime_error("Invalid snapshot file version");
	}

	while (true)  {
		uint8_t section_type = qemu_get_byte(fh);
		if (section_type == S2E_SS_EOF)  {
			break;
		}

		if (section_type != S2E_SS_SECTION_START)  {
			throw std::runtime_error("Unexpected section marker");
		}

		uint32_t section_size = qemu_get_be32(fh);
		uint32_t section_id = qemu_get_be32(fh);
		uint16_t name_len = qemu_get_be16(fh);
		char section_name[name_len + 1];
		qemu_get_buffer(fh, (unsigned char *) section_name, name_len);
		section_name[name_len] = 0;

		uint32_t remaining_size = section_size - (11 + name_len);

		if (section_id == S2E_SS_SECTION_TYPE_MACHINE && strcmp(section_name, S2E_SS_SECTION_NAME_MACHINE) == 0)  {
			restoreMachine(fh, remaining_size);
		}
		else if (section_id == S2E_SS_SECTION_TYPE_CPU && strcmp(section_name, S2E_SS_SECTION_NAME_CPU) == 0)  {
			restoreCpu(fh, remaining_size);
		}
		else  {
			throw std::runtime_error("Unknown section in snapshot file");
		}
	}

	qemu_fclose(fh);
}

void Snapshot::takeSnapshot(S2EExecutionState* state, std::string name, unsigned flags)
{
	QEMUFile* fh;
	std::string filename;
	unsigned i;

	if (name == "")
	{
		llvm::sys::TimeValue llvm_time = llvm::sys::TimeValue::now();
		name = "s2e-" + llvm_time.str();
	}

	s2e()->getDebugStream() << "[Snapshot] DEBUG: Taking snapshot with name " << name << '\n';

	llvm::SmallString<1024> snapshotFile(m_snapshotFolder);
	llvm::sys::path::append(snapshotFile, name);
	llvm::sys::path::replace_extension(snapshotFile, ".snapshot");

	//Create unique output file name
	for (i = 0; i < MAX_SNAPSHOT_FILES && llvm::sys::fs::exists(snapshotFile.str()); i++)
	{
		std::stringstream ss;

		ss << name << "_" << std::setfill('0') << std::setw(3) << i;
		snapshotFile = m_snapshotFolder;
		llvm::sys::path::append(snapshotFile, ss.str());
		llvm::sys::path::replace_extension(snapshotFile, ".snapshot");
	}

	assert(i < MAX_SNAPSHOT_FILES && "Too many snapshot files");

	fh = qemu_fopen(snapshotFile.str().data(), "wb");
	if (!fh) {
		throw std::runtime_error("File could not be opened");
	}

//	int saved_vm_running = runstate_is_running();
//	vm_stop(RUN_STATE_SAVE_VM); //maybe use vm_stop_force_state(RUN_STATE_FINISH_MIGRATE); instead

	try
	{
		saveStart(fh);
		saveMachine(fh);
		saveCpu(fh);
	}
	catch (QemuSnapshotError& err)
	{
		qemu_fclose(fh);
//		if (saved_vm_running)
//		{
//			vm_start();
//		}


		s2e()->getWarningsStream() << "[Snapshot] ERROR: during snapshotting" << '\n';

		throw err;
	}

	qemu_fclose(fh);

//	if (saved_vm_running)
//	{
//		vm_start();
//	}
	s2e()->getDebugStream() << "[Snapshot] DEBUG: Snapshot done" << '\n';
}

} // namespace plugins
} // namespace s2e
