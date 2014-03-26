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

#ifndef S2E_PLUGINS_SNAPSHOT_H
#define S2E_PLUGINS_SNAPSHOT_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/ConfigFile.h>
#include <string>
#include <list>

namespace s2e {
namespace plugins {

class Snapshot : public Plugin
{
    S2E_PLUGIN

public:
    typedef std::pair< uint64_t, uint64_t > MemoryRange;
    typedef std::list< MemoryRange > MemoryRangeList;
    enum SnapshotFlags
    {
    	SNAPSHOT_MACHINE = 0x1,
    	SNAPSHOT_CPU = 0x2,
    	SNAPSHOT_MEMORY = 0x4,
    	SNAPSHOT_SYMBOLIC_CONSTRAINTS = 0x8,
    	SNAPSHOT_ALL_SYMBOLIC_STATES = 0x10,
    	SNAPSHOT_EMULATED_DEVICES = 0x20,
    	SNAPSHOT_S2E_PLUGIN_STATE = 0x40
    };
    Snapshot(S2E* s2e);

    void initialize();
    void takeSnapshot(
    		S2EExecutionState* state,
    		std::string name = "",
    		unsigned flags = SNAPSHOT_CPU | SNAPSHOT_MACHINE | SNAPSHOT_MEMORY,
    		const MemoryRangeList& ranges  = MemoryRangeList() );

private:
    uint8_t getSystemEndianness();
    uint8_t getSystemArchitecture();
    void saveStart(QEMUFile* fh);
    void saveMachine(QEMUFile* fh);
    void saveCpu(QEMUFile* fh);
    void saveRam(QEMUFile* fh, S2EExecutionState* state, const MemoryRangeList& ranges);
    void restoreMachine(QEMUFile* fh, uint32_t size);
    void restoreCpu(QEMUFile* fh, uint32_t size);
    void restoreRam(QEMUFile* fh, uint32_t size, S2EExecutionState* state);
    void restoreSnapshot(std::string filename, S2EExecutionState* state);

    void slotTranslateBlockStart(
                ExecutionSignal *signal,
                S2EExecutionState* state,
                TranslationBlock *tb,
                uint64_t pc);
    void slotExecuteBlockStart(S2EExecutionState* state, uint64_t pc);

    void s2eInitialized(S2EExecutionState* state);
    static int luaTakeSnapshot(lua_State* L);

    std::string m_snapshotFolder;
    bool m_verbose;
    static Snapshot* s_self;
    std::string m_restoreFile;
    sigc::connection m_connection;
    static MemoryRangeList s_defaultSnapshotMemoryRanges;
    MemoryRangeList m_restoreMemoryRanges;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SNAPSHOT_H
