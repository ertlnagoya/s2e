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
		"ReplayMemoryAccesses");

void ReplayMemoryAccesses::initialize()
{
	m_verbose = s2e()->getConfig()->getBool(getConfigKey()+".verbose");
	m_skipCode = s2e()->getConfig()->getBool(getConfigKey()+".skipCode", true);
	m_inputFileName = s2e()->getConfig()->getString(getConfigKey()+".replayTraceFileName");

	m_inputFile.open(m_inputFileName.c_str(), std::ifstream::in | std::ifstream::binary);
	std::cerr << m_inputFileName << '\n';
	std::cerr << "err: " << std::strerror(errno) << '\n';
	assert(m_inputFile.good());
	m_nextToMatch = new ExecutionTraceMemory;
	m_stateId = 0;

	s2e()->getCorePlugin()->onHijackMemoryRead.connect(sigc::mem_fun(*this, &ReplayMemoryAccesses::slotMemoryRead));
	s2e()->getCorePlugin()->onHijackMemoryWrite.connect(sigc::mem_fun(*this, &ReplayMemoryAccesses::slotMemoryWrite));

	s2e()->getDebugStream() << "[ReplayMemoryAccesses]: initialized" << '\n';
}

klee::ref<klee::Expr> ReplayMemoryAccesses::slotMemoryRead(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        unsigned size,
        bool is_io, bool is_code)
{
	int access_type = 0;
	uint64_t address = 0;
	klee::Expr::Width width;
	uint64_t value = 0;

	if (m_skipCode && is_code)
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

	if (this->m_verbose)
	{
		s2e()->getDebugStream()
			<< "[ReplayMemoryAccesses] slotMemoryRead called with address = " << hexval(address)
			<< ((access_type & ACCESS_TYPE_CONCRETE_ADDRESS) ? " [concrete]" : " [symbolic]")
			<< ", access_type = " << hexval(access_type)
			<< ", size = " << size
			<< ", is_io = " << is_io
			<< ", is_code = " << is_code
			<< '\n';
	}

	if (!setValueFromNext(address, false, size, &value)) {
		value = 0xDEAD;
		s2e()->getDebugStream()
			<< "[ReplayMemoryAccesses] failed to set value for address = " <<
			hexval(address) << '\n';
	} else {
		s2e()->getDebugStream()
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

bool ReplayMemoryAccesses::slotMemoryWrite(S2EExecutionState *state,
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

	if (this->m_verbose)
	{
		s2e()->getDebugStream()
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
