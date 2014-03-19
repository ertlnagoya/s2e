#include "ReplayMemoryAccesses.h"

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

#include "../ExecutionTracers/TraceEntries.h"
#include "../MemoryInterceptor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ReplayMemoryAccesses,
		"ReplayMemoryAccesses -- Replay previous recorded memory trace",
		"ReplayMemoryAccesses", "MemoryInterceptor");

void ReplayMemoryAccesses::initialize()
{
	ConfigFile *cfg = s2e()->getConfig();

	m_verbose = cfg->getBool(getConfigKey()+".verbose");
	m_skipCode = cfg->getBool(getConfigKey()+".skipCode", true);
	m_inputFileName = cfg->getString(getConfigKey()+".replayTraceFileName");
	m_memoryInterceptor =
		static_cast<MemoryInterceptor *>(s2e()->getPlugin(
					"MemoryInterceptor"));
	assert(m_memoryInterceptor);

	/* prepare input file */
	m_inputFile.open(m_inputFileName.c_str(), std::ifstream::in | std::ifstream::binary);
	if (!m_inputFile.good()) {
		std::cerr << m_inputFileName << ' ' << "err: " << std::strerror(errno) << '\n';
	}
	assert(m_inputFile.good());

	/* allocate initial state */
	m_nextToMatch = new ExecutionTraceMemory;
	m_stateId = 0;

	/* parse memory ranges */
	if (!setupRangeListeners()) {
		assert(0 && "Failed to setup range listeners");
	}

	s2e()->getDebugStream() << "[ReplayMemoryAccesses]: initialized" << '\n';
}

bool ReplayMemoryAccesses::setupRangeListeners()
{
	ConfigFile *cfg = s2e()->getConfig();
	bool ok;

	std::vector<std::string> plugins_keys = cfg->getListKeys(
			getConfigKey() + ".ranges", &ok);
	if (!ok) {
		s2e()->getWarningsStream()
			<< "[MemoryInterceptorReplay] Error reading subkey .intereceptors"
			<< '\n';
		return false;
	}

	for (std::vector<std::string>::iterator plugins_itr =
			plugins_keys.begin(); plugins_itr != plugins_keys.end();
			plugins_itr++)
	{
		std::vector<std::string> ranges_keys = cfg->getListKeys(
				getConfigKey() + ".ranges." + *plugins_itr, &ok);
		if (!ok) {
			s2e()->getWarningsStream()
				<< "[MemoryInterceptorReplay] Error reading subkey .ranges."
				<< *plugins_itr << '\n';
			return false;
		}

		std::string interceptor_key = getConfigKey() + ".ranges." + *plugins_itr;

		if (!cfg->hasKey(interceptor_key + ".address")
				|| !cfg->hasKey(interceptor_key + ".size")
				|| !cfg->hasKey(interceptor_key + ".access_type"))
		{
			s2e()->getWarningsStream()
				<< "[MemoryInterceptorReplay] Error: subkey .address, .size "
				<< "or .access_type for key " << interceptor_key
				<< " missing!" << '\n';
			return false;
		}

		uint64_t address = cfg->getInt(
				interceptor_key + ".address");
		uint64_t size = cfg->getInt(interceptor_key + ".size");
		ConfigFile::string_list access_types =
			cfg->getStringList(interceptor_key + ".access_type",
					ConfigFile::string_list(), &ok);
		if (!ok) {
			s2e()->getWarningsStream()
				<< "[MemoryInterceptorReplay] Error reading subkey "
				<< interceptor_key
				<< ".access_type"
				<< '\n';
			return false;
		}

		int access_type = 0;
		for (ConfigFile::string_list::const_iterator access_type_itr =
				access_types.begin();
				access_type_itr != access_types.end();
				access_type_itr++)
		{
			if (*access_type_itr == "read")
				access_type |= ACCESS_TYPE_READ;
			else if (*access_type_itr == "write")
				access_type |= ACCESS_TYPE_WRITE;
			else if (*access_type_itr == "execute")
				access_type |= ACCESS_TYPE_EXECUTE;
			else if (*access_type_itr == "io")
				access_type |= ACCESS_TYPE_IO;
			else if (*access_type_itr == "memory")
				access_type |= ACCESS_TYPE_NON_IO;
			else if (*access_type_itr == "concrete_value")
				access_type |= ACCESS_TYPE_CONCRETE_VALUE;
			//TODO: Symbolic values not yet supported
			//                else if (*access_type_itr == "symbolic_value")
			//                    access_type |= ACCESS_TYPE_SYMBOLIC_VALUE;
			else if (*access_type_itr == "concrete_address")
				access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;
			//TODO: Symbolic values not yet supported
			//                else if (*access_type_itr == "symbolic_address")
			//                    access_type |= ACCESS_TYPE_SYMBOLIC_ADDRESS;
		}

		//Add some sane defaults while symbolic values are disabled
		//User can select concrete, concrete+symbolic, symbolic for address and value, default is concrete
		if (!(access_type & ACCESS_TYPE_SYMBOLIC_VALUE))
			access_type |= ACCESS_TYPE_CONCRETE_VALUE;
		if (!(access_type & ACCESS_TYPE_SYMBOLIC_ADDRESS))
			access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;

		//If none of read, write, execute is specified, all are assumed
		if (!(access_type
					& (ACCESS_TYPE_READ | ACCESS_TYPE_WRITE
						| ACCESS_TYPE_EXECUTE))) {
			access_type |= ACCESS_TYPE_READ | ACCESS_TYPE_WRITE
				| ACCESS_TYPE_EXECUTE;
		}

		if (!(access_type & ACCESS_TYPE_SIZE_ANY)) {
			access_type |= ACCESS_TYPE_SIZE_ANY;
		}

		//If no IO or non-IO is specified, both are assumed
		if (!(access_type & (ACCESS_TYPE_IO | ACCESS_TYPE_NON_IO))) {
			access_type |= ACCESS_TYPE_IO | ACCESS_TYPE_NON_IO;
		}

		std::string read_handler;
		std::string write_handler;

		s2e()->getDebugStream()
			<< "[MemoryInterceptorReplay] Adding annotation "
			<< "for memory range " << hexval(address) << "-"
			<< hexval(address + size) << " with access type "
			<< hexval(access_type) << "\n";

		m_memoryInterceptor->addInterceptor(
				new MemoryInterceptorReplayHandler(m_s2e, address, size, access_type));
	}

	return true;
}

MemoryInterceptorReplayHandler::MemoryInterceptorReplayHandler(
	S2E* s2e, uint64_t address, uint64_t size, int mask)
		: MemoryAccessHandler(s2e, address, size, mask)
{
	m_replayMemoryAccesses = static_cast<ReplayMemoryAccesses *>(s2e->getPlugin(
				"ReplayMemoryAccesses"));
	assert(m_replayMemoryAccesses);
	m_s2e = m_replayMemoryAccesses->m_s2e;
	assert(m_s2e);
}

klee::ref<klee::Expr> MemoryInterceptorReplayHandler::read(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        unsigned size,
        bool is_io, bool is_code)
{
	int access_type = 0;
	uint64_t address = 0;
	klee::Expr::Width width;
	uint64_t value = 0;

	if (m_replayMemoryAccesses->m_skipCode && is_code)
		return klee::ref<klee::Expr>();

	if (is_code)
		access_type |= ACCESS_TYPE_EXECUTE;
	else
		access_type |= ACCESS_TYPE_READ;

	if (is_io)
		access_type |= ACCESS_TYPE_IO;
	else
		access_type |= ACCESS_TYPE_NON_IO;

	if (isa<klee::ConstantExpr>(virtaddr))
	{
		address = cast<klee::ConstantExpr>(virtaddr)->getZExtValue();
		access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;
	}
	else
		access_type |= ACCESS_TYPE_SYMBOLIC_ADDRESS;

	switch (size)
	{
		case 8:
			width = klee::Expr::Int8; access_type |= ACCESS_TYPE_SIZE_1; break;
		case 16:
			width = klee::Expr::Int16; access_type |= ACCESS_TYPE_SIZE_2; break;
		case 32:
			width = klee::Expr::Int32; access_type |= ACCESS_TYPE_SIZE_4; break;
		case 64:
			width = klee::Expr::Int64; access_type |= ACCESS_TYPE_SIZE_8; break;
		case 128:
			assert(0 && "Klee doesn't know about 128-bit vars wide");
			access_type |= ACCESS_TYPE_SIZE_16; break;
		default:
			assert(false && "Unknown memory access size");
	}

	if (m_replayMemoryAccesses->m_verbose) {
		m_s2e->getDebugStream()
			<< "[ReplayMemoryAccesses] slotMemoryRead called with address = " << hexval(address)
			<< ((access_type & ACCESS_TYPE_CONCRETE_ADDRESS) ? " [concrete]" : " [symbolic]")
			<< ", access_type = " << hexval(access_type)
			<< ", size = " << size
			<< ", is_io = " << is_io
			<< ", is_code = " << is_code
			<< '\n';
	}

	if (!m_replayMemoryAccesses->setValueFromNext(address, false, size, &value)) {
		value = 0xDEAD;
		m_s2e->getDebugStream()
			<< "[ReplayMemoryAccesses] failed to set value for address = " <<
			hexval(address) << '\n';
	} else {
		m_s2e->getDebugStream()
			<< "[ReplayMemoryAccesses] set value for address = " <<
			hexval(address) << " to " << hexval(value) << '\n';
	}

	klee::ref<klee::ConstantExpr> klee_value = klee::ConstantExpr::create(value, width);
	return static_cast<klee::ref<klee::Expr> >(klee_value);
}

bool ReplayMemoryAccesses::setValueFromNext(uint64_t address, bool isWrite,
					unsigned size, /* size in bits */
					uint64_t *valueRet)
{
	/*
	if (!updateNextMemoryAccess()) {
		s2e()->getDebugStream() << "[ReplayMemoryAccesses]: failed to get first entry" << '\n';
		return false;
	}
	*/
	int skipped = 0;

	while (updateNextMemoryAccess()) {
		if (m_nextToMatch->address != address)
			continue;
		if (m_nextToMatch->size*8 != size) {
			s2e()->getDebugStream() << "[ReplayMemoryAccesses]: size not matched" << ' ' << (int) m_nextToMatch->size << " vs " << size << " addr : 0x" << hexval(address) << '\n';
			continue;
		}
		/* keep searching until we'll find the correct operation */
		if (isWrite) {
			if (m_nextToMatch->flags & EXECTRACE_MEM_WRITE) {
				/* a write was requested */
				*valueRet = m_nextToMatch->value;
				s2e()->getDebugStream() << "[ReplayMemoryAccesses]: skip [W] " << skipped << '\n';
				return true;
			}
		} else {
			if (!(m_nextToMatch->flags & EXECTRACE_MEM_WRITE)) {
				/* a read was requested */
				*valueRet = m_nextToMatch->value;
				s2e()->getDebugStream() << "[ReplayMemoryAccesses]: skip [R] " << skipped << '\n';
				return true;
			}
		}
		++skipped;
	}

	return false;
}

bool MemoryInterceptorReplayHandler::write(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value,
        bool is_io)
{
	int access_type = ACCESS_TYPE_WRITE;
	uint64_t address = 0;

	if (is_io)
		access_type |= ACCESS_TYPE_IO;
	else
		access_type |= ACCESS_TYPE_NON_IO;

	if (isa<klee::ConstantExpr>(virtaddr))
	{
		address = cast<klee::ConstantExpr>(virtaddr)->getZExtValue();
		access_type |= ACCESS_TYPE_CONCRETE_ADDRESS;
	}
	else
		access_type |= ACCESS_TYPE_SYMBOLIC_ADDRESS;

	if (isa<klee::ConstantExpr>(value))
	{
		access_type |= ACCESS_TYPE_CONCRETE_VALUE;
	}
	else
		access_type |= ACCESS_TYPE_SYMBOLIC_VALUE;

	switch (value->getWidth())
	{
		case 8:
			access_type |= ACCESS_TYPE_SIZE_1; break;
		case 16:
			access_type |= ACCESS_TYPE_SIZE_2; break;
		case 32:
			access_type |= ACCESS_TYPE_SIZE_4; break;
		case 64:
			access_type |= ACCESS_TYPE_SIZE_8; break;
		case 128:
			access_type |= ACCESS_TYPE_SIZE_16; break;
		default:
			assert(false && "Unknown memory access size");
	}

	if (m_replayMemoryAccesses->m_verbose)
	{
		m_s2e->getDebugStream()
			<< "[ReplayMemoryAccesses] slotMemoryWrite called with address = " << hexval(address)
			<< ((access_type & ACCESS_TYPE_CONCRETE_ADDRESS) ? " [concrete]" : " [symbolic]")
			<< ", access_type = " << hexval(access_type)
			<< ", is_io = " << is_io
			<< '\n';
	}

	/* do nothing */
	return false;
}


bool ReplayMemoryAccesses::updateNextMemoryAccess()
{
	/* return true if next was found */
	assert(m_nextToMatch);

	while (!m_inputFile.eof()) {
		m_inputFile.read((char *)&mLastHdr, sizeof mLastHdr);
		if (m_inputFile.gcount() != sizeof mLastHdr) {
			return false;
		}

		if (mLastHdr.type >= TRACE_MAX) {
			return false;
		}

		if (mLastHdr.stateId == m_stateId &&
				mLastHdr.type == TRACE_MEMORY) {
			m_inputFile.read((char *) m_nextToMatch, sizeof *m_nextToMatch);
			if (m_inputFile.gcount() != sizeof *m_nextToMatch)
				return false;
			return true;
		}
	}

	return true;
}

}
}
