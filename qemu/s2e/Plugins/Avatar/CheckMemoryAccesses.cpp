#include "CheckMemoryAccesses.h"

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/cajun/json/reader.h>
#include <s2e/cajun/json/writer.h>

#include <klee/Context.h>
#include <klee/Memory.h>
#include <klee/Solver.h>

#include <iomanip>
#include <cctype>

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>

#include <iostream>

namespace s2e {

void s2e_symbolic_write_to_concrete_memory(
		const klee::MemoryObject* mo,
		klee::ref< klee::Expr > offset,
		klee::ref< klee::Expr > value)
{
		if (mo->name == "CpuSystemState" &&
				isa<klee::ConstantExpr>(offset) &&
				cast<klee::ConstantExpr>(offset)->getZExtValue() == 0) {
			S2EExecutionState *state = g_s2e_state;
			std::pair< klee::ref<klee::Expr>, klee::ref<klee::Expr> > res =
				g_s2e->getExecutor()->getSolver()->
				getRange(klee::Query(state->constraints, value));
			uint32_t start = cast<klee::ConstantExpr>(res.first)->getZExtValue();
			uint32_t end = cast<klee::ConstantExpr>(res.second)->getZExtValue();
			g_s2e->getWarningsStream() << "writing symbolic value to pc "
				<< hexval(start) << " " << hexval(end) << "\n";
		}
}

namespace plugins {

S2E_DEFINE_PLUGIN(CheckMemoryAccesses,
		"CheckMemoryAccesses -- Check that a value (may be symbolic) is \\"
		" valid according to a memory map",
		"CheckMemoryAccesses");

void CheckMemoryAccesses::initialize()
{
	ConfigFile *cfg = s2e()->getConfig();
	m_verbose = cfg->getBool(getConfigKey()+".verbose");
	std::string inputFileName = cfg->getString(getConfigKey()+".memoryMapFile");
	std::istream *inputFile =
		new std::ifstream(inputFileName.c_str(),
			std::ios::in | std::ios::binary);

	assert(inputFile);
	loadMemoryMap(inputFile);

	s2e()->getCorePlugin()->onDataMemoryAccess.connect(
			sigc::mem_fun(*this, &CheckMemoryAccesses::onDataMemoryAccess));

	delete inputFile;
}

void CheckMemoryAccesses::onDataMemoryAccess(S2EExecutionState *state,
	klee::ref<klee::Expr> virtualAddress,
	klee::ref<klee::Expr> hostAddress,
	klee::ref<klee::Expr> value,
	bool isWrite, bool isIO, bool isCode)
{
	checkAddress(state, virtualAddress);
	//if (isa<klee::ConstantExpr>(virtualAddress)) {
	//	s2e()->getWarningsStream(state) << "concrete\n";
	//	return;
	//}

	//assert(!isa<klee::ConstantExpr>(virtualAddress));
}

/* return true if operation failed */
bool CheckMemoryAccesses::loadMemoryMap(std::istream *fin)
{
	json::Array doc;
	std::stringstream sin;
	sin << fin->rdbuf();

	json::Reader::Read(doc, sin);

	json::Array::const_iterator entry(doc.Begin()),
		entriesEnd(doc.End());
	for (; entry != entriesEnd; ++entry) {
		const json::Object& object= *entry;
		const json::String &type = object["type"];
		const json::Number &start = object["start"];
		const json::Number &size = object["size"];

		uint32_t range_start = (uint32_t)static_cast<double>(start);
		uint32_t range_size = (uint32_t)static_cast<double>(size);
		struct range new_range = {
			.start = range_start,
			.size = range_size,
		};

		m_validRanges.push_back(new_range);

		if (m_verbose)
			s2e()->getDebugStream() <<
					(static_cast<std::string>(type)).c_str() << ": " <<
					hexval(range_start) << "-" <<
					hexval(range_start+range_size) << '\n';
	}

	return true;
}


void CheckMemoryAccesses::printSolutions(S2EExecutionState *state)
{
	s2e()->getWarningsStream()
		<< "[CheckMemoryAccesses]: processTestCase of state " << state->getID()
		<< " at address " << hexval(state->getPc())
		<< '\n';

	ConcreteInputs out;

	bool success = s2e()->getExecutor()->getSymbolicSolution(*state, out);

	if (!success) {
		s2e()->getWarningsStream() << "Could not get symbolic solutions" << '\n';
		return;
	}

	std::stringstream ss;
	ConcreteInputs::iterator it;
	for (it = out.begin(); it != out.end(); ++it) {
		const VarValuePair &vp = *it;
		ss << std::setw(20) << vp.first << ": ";

		for (unsigned i = 0; i < vp.second.size(); ++i) {
			if (i != 0)
				ss << ' ';
			/* wrong endianness? */
			ss << std::setw(2) << std::setfill('0') << std::hex << (unsigned) vp.second[i] << std::dec;
		}
		ss << std::setfill(' ') << ", ";

		ss << "(string) \"";
		for (unsigned i=0; i < vp.second.size(); ++i) {
			ss << (char)(std::isprint(vp.second[i]) ? vp.second[i] : '.');
		}
		ss << "\"\n";
	}

	s2e()->getWarningsStream() << ss.str();
}

bool CheckMemoryAccesses::isOneMemoryAccessValid(uint64_t addr)
{
	std::vector<struct range>::iterator it;
	for (it = m_validRanges.begin(); it != m_validRanges.end(); ++it) {
		uint64_t start, size;
		start = (uint64_t) it->start;
		size = (uint64_t) it->size;

		if (start <= addr && addr <= start+size)
			return true;
	}
	return false;
}

bool CheckMemoryAccesses::checkAddress(S2EExecutionState *state, klee::ref<klee::Expr> addr)
{
	map_constraints = new klee::ConstraintManager();

	if (isa<klee::ConstantExpr>(addr)) {
		uint64_t addr_concrete = cast<klee::ConstantExpr>(addr)->getZExtValue();

		if (!isOneMemoryAccessValid(addr_concrete)) {
			s2e()->getWarningsStream() << "[CheckMemoryAccesses]: " <<
				"@" << hexval(state->getPc()) <<
				": Invalid (concrete) memaccess " << hexval(addr_concrete) << "\n";
		}
	} else {
		std::pair< klee::ref<klee::Expr>, klee::ref<klee::Expr> > res =
			s2e()->getExecutor()->getSolver()->
				getRange(klee::Query(state->constraints, addr));
		uint32_t start = cast<klee::ConstantExpr>(res.first)->getZExtValue();
		uint32_t end = cast<klee::ConstantExpr>(res.second)->getZExtValue();

		if (!isOneMemoryAccessValid(start) || !isOneMemoryAccessValid(end)) {
			s2e()->getWarningsStream()
				<< "[CheckMemoryAccesses]: " << "State id " << state->getID() <<
				" @" << hexval(state->getPc()) <<
				" Invalid (symbolic) memaccess" <<
				hexval(start) << " - " << hexval(end) << '\n';
			printSolutions(state);
		}
	}

	return true;
}

}
}
