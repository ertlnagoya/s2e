/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2013, Institut Eurecom
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
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

/**
 * This plugin provides a searcher that tries to maximize code coverage.
 *
 * The configuration file parameters are:
 *  - batch_time_budget (float), how much time each state is given before it is evicted
 *      according to the code coverage optimization policy. A value of 0.0 disables
 *      the batching.
 *  - per_state_coverage (bool), If the code coverage is measured per state (true) or
 *      globally across all states (false)
 */

#ifndef S2E_PLUGINS_MAXCODECOVERAGESEARCHER_H
#define S2E_PLUGINS_MAXCODECOVERAGESEARCHER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

#include <klee/Searcher.h>

#include <vector>
#include <list>

namespace s2e {
namespace plugins {

class  MaxCodeCoverageSearcher;

class MaxCodeCoverageSearcherState : public PluginState
{
private:
    uint64_t m_metric;
    MaxCodeCoverageSearcher *m_plugin;
    S2EExecutionState *m_state;
    std::map<uint64_t, uint64_t> m_executedBasicBlocks; //Maps basic block to the number of times it was executed
public:

    MaxCodeCoverageSearcherState();
    MaxCodeCoverageSearcherState(S2EExecutionState *s, Plugin *p);
    virtual ~MaxCodeCoverageSearcherState();
    virtual PluginState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend struct CodeCoverageComparator;
    friend class MaxCodeCoverageSearcher;

};

class  MaxCodeCoverageSearcher : public Plugin, public klee::Searcher
{
    S2E_PLUGIN
public:
    MaxCodeCoverageSearcher(S2E* s2e): Plugin(s2e) {}
    void initialize();

    virtual klee::ExecutionState& selectState();
    virtual void update(klee::ExecutionState *current,
                        const std::set<klee::ExecutionState*> &addedStates,
                        const std::set<klee::ExecutionState*> &removedStates);

    virtual bool empty();
    virtual ~MaxCodeCoverageSearcher();

private:
    S2EExecutionState *m_currentState;
    klee::Searcher *m_batchingSearcher;
    double m_timeBudget;
    bool m_perStateCodeCoverage;
    bool m_verbose;
    std::map<uint64_t, uint64_t> m_executedBasicBlocks;

//    klee::Searcher *m_parentSearcher;

    std::list<S2EExecutionState *> m_states;

    uint64_t penaltyFunction(uint64_t state_metric, uint64_t block_execution_times);

    void slotTranslateBlockStart(
            ExecutionSignal *signal,
            S2EExecutionState *state,
            TranslationBlock *tb,
            uint64_t block_pc);

    void slotExecuteBlockStart(
            S2EExecutionState *state,
            uint64_t block_pc);

    void slotInitialize(S2EExecutionState *state);

    friend class MaxCodeCoverageSearcherState;
};



} // namespace plugins
} // namespace s2e

#endif
