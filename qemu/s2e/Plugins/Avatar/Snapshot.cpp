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
#include <cpu-all.h>
#include <qemu-queue.h>
#include <memory.h>
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
	S2E_SS_SECTION_TYPE_MACHINE = 1,
	S2E_SS_SECTION_TYPE_RAM = 2
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
static const char* S2E_SS_SECTION_NAME_RAM = "memory";

static const unsigned MAX_SNAPSHOT_FILES = 1000;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Snapshot, "Snapshot taking and reverting from S2E", "Snapshot",);

Snapshot* Snapshot::s_self = NULL;
Snapshot::MemoryRangeList Snapshot::s_defaultSnapshotMemoryRanges;

static Snapshot::MemoryRangeList getRanges(lua_State* L)
{
	Snapshot::MemoryRangeList ranges;

	lua_pushnil(L);  /* first key */
	while (lua_next(L, -2) != 0)
	{
	   /* uses 'key' (at index -2) and 'value' (at index -1) */
	   lua_getfield(L, -1, "address");
	   uint64_t address = lua_tointeger(L, -1);
	   lua_getfield(L, -2, "size");
	   uint64_t size = lua_tointeger(L, -1);
	   lua_pop(L, 3);

	   ranges.push_back(std::make_pair(address, size));
	}

	return ranges;
}

int Snapshot::luaTakeSnapshot(lua_State* L)  {
	assert(s_self);

	std::string name;
	unsigned flags;
	std::list< std::pair< uint64_t, uint64_t> > ranges;

	s_self->s2e()->getWarningsStream() <<"LUA args: " << lua_gettop(L) << '\n';

	if (lua_gettop(L) == 1)  {
		name = lua_tointeger(L, lua_gettop(L) - 0);
		//TODO: Update this default when more snapshot stuff is available
		flags = SNAPSHOT_MACHINE | SNAPSHOT_CPU | SNAPSHOT_MEMORY;
		ranges = s_defaultSnapshotMemoryRanges;
	}
	else if (lua_gettop(L) == 2)  {
		name = lua_tostring(L, lua_gettop(L) - 1);
		flags = lua_tointeger(L, lua_gettop(L) - 0);
		ranges = s_defaultSnapshotMemoryRanges;
	}
	else if (lua_gettop(L) == 3)  {
		name = lua_tostring(L, lua_gettop(L) - 2);
		flags = lua_tointeger(L, lua_gettop(L) - 1);
		ranges = getRanges(L);
	}
	else  {
		assert(false && "LUA function called with invalid number of parameters");
	}

	std::stringstream ss;
	ss << "[";
	bool sep = false;
	for (MemoryRangeList::const_iterator itr = ranges.begin();
		 itr != ranges.end();
		 itr++)
	{
		if (sep)  {
			ss << ", ";
		}
		sep = true;
		ss << "(0x" << hexval(itr->first) << ", 0x" << hexval(itr->second) << ")";
	}
	ss << "]";

	s_self->s2e()->getWarningsStream() << "[Snapshot] calling take_snapshot(\""
			<< name << "\", " << hexval(flags) << ", "
			<< ss.str() << ")" << '\n';

	s_self->takeSnapshot((S2EExecutionState*) g_s2e_state, name, flags, ranges);

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
	                        getConfigKey() + ".restore_file", "");
	bool ok;
	ConfigFile::string_list keys = s2e()->getConfig()->getListKeys(getConfigKey() + ".snapshot_ranges", &ok);
	if (!ok)  {
		s2e()->getWarningsStream() << "[Snapshot] ERROR: reading config key "
				<< getConfigKey() << ".snapshot_ranges" << '\n';
	}
	else  {
		for (ConfigFile::string_list::const_iterator itr = keys.begin();
			 itr != keys.end();
			 itr++)
		{
			bool ok2;
			uint64_t address = s2e()->getConfig()->getInt(getConfigKey() + "." + *itr + ".address", 0, &ok);
			uint64_t size = s2e()->getConfig()->getInt(getConfigKey() + "." + *itr + ".size", 0, &ok2);

			if (!ok)  {
				s2e()->getWarningsStream() << "[Snapshot] ERROR: reading config key "
						<< getConfigKey() << ".snapshot_ranges" << "."
						<< *itr << ".address" << '\n';
				break;
			}
			if (!ok2)  {
				s2e()->getWarningsStream() << "[Snapshot] ERROR: reading config key "
						<< getConfigKey() << ".snapshot_ranges" << "."
						<< *itr << ".size" << '\n';
				break;
			}

			s_defaultSnapshotMemoryRanges.push_back(std::make_pair(address, size));
		}
	}

	ConfigFile::string_list keys2 = s2e()->getConfig()->getListKeys(getConfigKey() + ".restore_ranges", &ok);
	if (!ok)  {
		s2e()->getWarningsStream() << "[Snapshot] ERROR: reading config key "
				<< getConfigKey() << ".restore_ranges" << '\n';
	}
	else  {
		for (ConfigFile::string_list::const_iterator itr = keys2.begin();
			 itr != keys2.end();
			 itr++)
		{
			bool ok2;
			uint64_t address = s2e()->getConfig()->getInt(getConfigKey() + "." + *itr + ".address", 0, &ok);
			uint64_t size = s2e()->getConfig()->getInt(getConfigKey() + "." + *itr + ".size", 0, &ok2);

			if (!ok)  {
				s2e()->getWarningsStream() << "[Snapshot] ERROR: reading config key "
						<< getConfigKey() << ".restore_ranges" << "."
						<< *itr << ".address" << '\n';
				break;
			}
			if (!ok2)  {
				s2e()->getWarningsStream() << "[Snapshot] ERROR: reading config key "
						<< getConfigKey() << ".restore_ranges" << "."
						<< *itr << ".size" << '\n';
				break;
			}

			m_restoreMemoryRanges.push_back(std::make_pair(address, size));
		}
	}

	if (s_defaultSnapshotMemoryRanges.empty()) {
		s_defaultSnapshotMemoryRanges.push_back(std::make_pair(0, 0xffffffffffffffffULL));
	}

	if (m_restoreMemoryRanges.empty()) {
		m_restoreMemoryRanges.push_back(std::make_pair(0, 0xffffffffffffffffULL));
	}

	if (m_restoreFile != "")  {
		m_connection = s2e()->getCorePlugin()->onTranslateBlockStart.connect(
				sigc::mem_fun(*this, &Snapshot::slotTranslateBlockStart));
	}

	if (m_verbose) {
		s2e()->getDebugStream() << "[Snapshot] initialized, saving snapshot in "
				<< m_snapshotFolder << " "
				<< (existed ? "(existed)" : "(created)") << '\n';
	}
}

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
	restoreSnapshot(m_restoreFile, state);
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

extern "C" int ram_save_live(QEMUFile*, int, void*);
extern "C" MemoryRegion *get_system_memory(void);

static bool inRanges(uint64_t val, const Snapshot::MemoryRangeList& ranges)
{
	for (Snapshot::MemoryRangeList::const_iterator itr = ranges.begin();
		 itr != ranges.end();
		 itr++)
	{
		if (val >= itr->first && val < itr->second)  {
			return true;
		}
	}

	return false;
}

void Snapshot::saveRam(QEMUFile* fh, S2EExecutionState* state, const MemoryRangeList& ranges)
{
	RAMBlock *block;
	uint32_t section_start = qemu_ftell(fh);
	qemu_put_byte(fh, S2E_SS_SECTION_START);
	qemu_put_be32(fh, 0); //dummy length field
	qemu_put_be32(fh, S2E_SS_SECTION_TYPE_RAM);
	//Section ID string
	qemu_put_string(fh, S2E_SS_SECTION_NAME_RAM);
	qemu_put_be32(fh, 4); //Version (coherent with version specified in vl.c)
	uint8_t* buf = new uint8_t[TARGET_PAGE_SIZE];
	assert(buf);

	QLIST_FOREACH(block, &ram_list.blocks, next)
	{
		uint64_t mem_base = block->offset;
		uint64_t mem_size = memory_region_size(block->mr);
		const char * mem_name = memory_region_name(block->mr);
		uint64_t mem_end = mem_base + mem_size;
		uint32_t mem_attrs = 0;

		assert(mem_base % TARGET_PAGE_SIZE == 0);
		assert(mem_end % TARGET_PAGE_SIZE == 0);
		for (uint64_t mem_idx = mem_base; mem_idx < mem_end;)
		{
			for (; mem_idx < mem_end && !inRanges(mem_idx, ranges); mem_idx += TARGET_PAGE_SIZE)  {
			}

			if (mem_idx >= mem_end)  {
				break;
			}

			uint64_t cur_size = 0;
			for (cur_size = 0;
				 mem_idx + cur_size < mem_end && inRanges(mem_idx + cur_size, ranges);
				 cur_size += TARGET_PAGE_SIZE)  {

			}

			qemu_put_be64(fh, mem_idx);
			qemu_put_be64(fh, cur_size);
			qemu_put_be32(fh, mem_attrs);
			qemu_put_string(fh, mem_name);

			s2e()->getWarningsStream() << "[Snapshot] Dumping memory region "
					<< hexval(mem_idx) << "-"
					<< hexval(mem_idx + cur_size) << " (" << mem_name << ")" << '\n';

			for (uint64_t i = mem_idx; i < mem_idx + cur_size; i += TARGET_PAGE_SIZE)
			{
				state->readMemoryConcrete(i, buf, TARGET_PAGE_SIZE, S2EExecutionState::PhysicalAddress);
				qemu_put_buffer(fh, buf, TARGET_PAGE_SIZE);
			}

			mem_idx += cur_size;
		}
	}
	delete[] buf;

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
	return S2E_SS_ARCH_I386;
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

	s2e()->getDebugStream() << "[Snapshot] restore machine " << name
			<< (endianness == S2E_SS_ENDIAN_LITTLE ? "(little endian)" : "(big endian)") << '\n';

	if (size != 0)  {
		s2e()->getWarningsStream() << "[Snapshot] ERROR: Machine section remaining size: " << size << '\n';
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
		s2e()->getWarningsStream() << "[Snapshot] ERROR: Wrong CPU section version, cannot read" << '\n';
		throw std::runtime_error("Version or architecture of snapshot file wrong or not implemented");
	}

	uint32_t pos_before = qemu_ftell(fh);
	cpu_load(fh, env, version);
	size -= (qemu_ftell(fh) - pos_before);

	const char * arch_name;
	switch (architecture) {
	case S2E_SS_ARCH_ARM: arch_name = "ARM"; break;
	case S2E_SS_ARCH_I386: arch_name = "i386"; break;
	case S2E_SS_ARCH_X86_64: arch_name = "x86_64"; break;
	default: arch_name = "unknown"; break;
	}

	s2e()->getDebugStream() << "[Snapshot] Restore CPU "
			<< arch_name << " " << model << '\n';

	if (size != 0)  {
		s2e()->getWarningsStream() << "[Snapshot] ERROR: Cpu section remaining size: " << size << '\n';
		throw std::runtime_error("Cpu section has wrong size");
	}
}

void Snapshot::restoreRam(QEMUFile* fh, uint32_t size, S2EExecutionState* state)
{
	uint32_t version = qemu_get_be32(fh); size -= 4;

	while (size > 0)
	{
		uint64_t mem_base = qemu_get_be64(fh); size -= 8;
		uint64_t mem_size = qemu_get_be64(fh); size -= 8;
		uint32_t mem_attrs = qemu_get_be32(fh); size -= 4;
		uint64_t name_len = qemu_get_be16(fh); size -= 2;
		char mem_name[name_len + 1];
		qemu_get_buffer(fh, (unsigned char *) mem_name, name_len); size -= name_len;
		mem_name[name_len] = 0;

		s2e()->getDebugStream() << "[Snapshot] Restoring memory region " << hexval(mem_base) << "-" << hexval(mem_base + mem_size) << " (" << mem_name << ")" << '\n';

		uint8_t* buf = new uint8_t[TARGET_PAGE_SIZE];
		for (uint64_t idx = mem_base; idx < mem_base + mem_size; idx += TARGET_PAGE_SIZE)
		{
			qemu_get_buffer(fh, buf, TARGET_PAGE_SIZE); size -= TARGET_PAGE_SIZE;

			if (inRanges(idx, m_restoreMemoryRanges))
			{
				s2e()->getDebugStream() << "[Snapshot] Restoring memory " << hexval(idx) << "-" << hexval(idx + TARGET_PAGE_SIZE) << "\n";
				state->writeMemoryConcrete(idx, buf, TARGET_PAGE_SIZE, S2EExecutionState::PhysicalAddress);
			}
		}
	}

	if (size != 0)  {
		s2e()->getWarningsStream() << "[Snapshot] ERROR: Memory section remaining size: " << size << '\n';
		throw std::runtime_error("Memory section has wrong size");
	}
}

void Snapshot::restoreSnapshot(std::string filename, S2EExecutionState* state)
{
	QEMUFile* fh = qemu_fopen(filename.c_str(), "rb");

	assert(state);

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
		else if (section_id == S2E_SS_SECTION_TYPE_RAM && strcmp(section_name, S2E_SS_SECTION_NAME_RAM) == 0)  {
			restoreRam(fh, remaining_size, state);
		}
		else  {
			s2e()->getWarningsStream() << "[Snapshot] Unkown section \"" << section_name << "\" [" << section_id << "]" << '\n';
			throw std::runtime_error("Unknown section in snapshot file");
		}
	}

	s2e()->getWarningsStream() << "Done" << '\n';
	qemu_fclose(fh);
}

void Snapshot::takeSnapshot(S2EExecutionState* state, std::string name, unsigned flags, const MemoryRangeList& ranges)
{
	QEMUFile* fh;
	std::string filename;
	unsigned i;

	if (name == "")
	{
		time_t now = time(0);
		struct tm tstruct;
		char buf[80];
		tstruct = *localtime(&now);

		strftime(buf, sizeof(buf), "%Y-%m-%d_%H:%M:%S", &tstruct);

		std::stringstream ss;
		ss << "s2e-" << buf;
		name = ss.str();
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

	std::string snapshotFileName = snapshotFile.str();
	fh = qemu_fopen(snapshotFileName.c_str(), "wb");
	if (!fh) {
		throw std::runtime_error("File could not be opened");
	}

//	int saved_vm_running = runstate_is_running();
//	vm_stop(RUN_STATE_SAVE_VM); //maybe use vm_stop_force_state(RUN_STATE_FINISH_MIGRATE); instead

	try
	{
		saveStart(fh);
		if (flags & SNAPSHOT_MACHINE)  {
			saveMachine(fh);
		}
		if (flags & SNAPSHOT_CPU)  {
			saveCpu(fh);
		}
		if (flags & SNAPSHOT_MEMORY)  {
			saveRam(fh, state, ranges);
		}
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
