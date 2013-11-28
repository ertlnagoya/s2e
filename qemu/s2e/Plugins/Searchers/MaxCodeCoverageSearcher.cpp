/*
 * S2E Selective Symbolic Execution Framework
 *
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
 *    Vitaly Chipounov <vitaly.chipounov@epfl.ch>
 *    Volodymyr Kuznetsov <vova.kuznetsov@epfl.ch>
 *
 * All contributors are listed in the S2E-AUTHORS file.
 */

extern "C" {
#include "config.h"
#include "qemu-common.h"
}

#include "MaxCodeCoverageSearcher.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/Initializer.h>

#include <iostream>

namespace s2e {
namespace plugins {

using namespace llvm;

S2E_DEFINE_PLUGIN(MaxCodeCoverageSearcher, "Prioritizes states that are about to execute unexplored translation blocks",
                  "MaxCodeCoverageSearcher", "Initializer");

void MaxCodeCoverageSearcher::initialize()
{
//    m_parentSearcher = NULL;
    m_currentState = 0;

    m_verbose = s2e()->getConfig()->getBool(getConfigKey() + ".verbose", false);
    m_timeBudget = s2e()->getConfig()->getDouble(getConfigKey() + ".batch_time_budget", 1.0);
    m_perStateCodeCoverage = s2e()->getConfig()->getBool(getConfigKey() + ".per_state_coverage", true);

    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &MaxCodeCoverageSearcher::slotTranslateBlockStart));

    assert(s2e()->getPlugin("Initializer") && "MaxCodeCoverageSearcher requires Initializer plugin");
    static_cast<Initializer *>(s2e()->getPlugin("Initializer"))->onInitialize.connect(sigc::mem_fun(*this, &MaxCodeCoverageSearcher::slotInitialize));

}

void MaxCodeCoverageSearcher::slotInitialize(S2EExecutionState *state)
{
    s2e()->getDebugStream() << "MaxCodeCoverageSearcher::initializeSearcher called" << '\n';

//    m_parentSearcher = s2e()->getExecutor()->getSearcher();
//    assert(m_parentSearcher);
    if (m_timeBudget == 0.0)
    {
        s2e()->getExecutor()->setSearcher(this);
    }
    else
    {
        m_batchingSearcher = new klee::BatchingSearcher(this, m_timeBudget, 1000);
        s2e()->getExecutor()->setSearcher(m_batchingSearcher);
    }
}

struct CodeCoverageComparator
{
    Plugin *p;

    CodeCoverageComparator(Plugin *p)
        : p(p)
    {
    }

    bool operator()(const S2EExecutionState *s1, const S2EExecutionState *s2) const
    {
        const MaxCodeCoverageSearcherState *p1 =
               static_cast<MaxCodeCoverageSearcherState*>(
                       p->getPluginState(
                               const_cast<S2EExecutionState*>(s1),
                               &MaxCodeCoverageSearcherState::factory));
       const MaxCodeCoverageSearcherState *p2 =
               static_cast<MaxCodeCoverageSearcherState*>(
                       p->getPluginState(
                               const_cast<S2EExecutionState*>(s2),
                               &MaxCodeCoverageSearcherState::factory));

       if (p1->m_metric == p2->m_metric)
           return s1->getID() < s2->getID();

       return p1->m_metric < p2->m_metric;
    }
};

klee::ExecutionState& MaxCodeCoverageSearcher::selectState()
{
    CodeCoverageComparator cmp(this);
    if (!m_states.empty())
    {
        //TODO: Searching the whole list is time-intensive ...
        S2EExecutionState *next_state = *std::min_element(m_states.begin(), m_states.end(), cmp);
        if (m_verbose)
          s2e()->getDebugStream() << "MaxCodeCoverageSearcher::selectState called, selecting next state " << hexval(next_state) << '\n';
        return *next_state;
    }
    else
    {
        s2e()->getWarningsStream() << "MaxCodeCoverageSearcher::selectState called, did not find any state!" << '\n';
        assert(false);
    }
}

void MaxCodeCoverageSearcher::update(klee::ExecutionState *current,
                    const std::set<klee::ExecutionState*> &addedStates,
                    const std::set<klee::ExecutionState*> &removedStates)
{
      if (m_verbose)
        s2e()->getDebugStream() << "MaxCodeCoverageSearcher::update called" << '\n';
//    m_parentSearcher->update(current, addedStates, removedStates);

    if (current && m_states.empty())
        m_states.push_back(static_cast<S2EExecutionState *>(current));


    foreach2(it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState*>(*it);
        if (m_verbose)
          s2e()->getDebugStream() << "removing state " << hexval(es) << " from searcher" << '\n';
        m_states.remove(es);
    }

    foreach2(it, addedStates.begin(), addedStates.end()) {
        S2EExecutionState *es = dynamic_cast<S2EExecutionState*>(*it);
        if (m_verbose)
          s2e()->getDebugStream() << "adding state " << hexval(es) << " to searcher" << '\n';
        m_states.push_back(es);
//        updatePc(es);
    }
}


bool MaxCodeCoverageSearcher::empty()
{
    return m_states.empty();
}

MaxCodeCoverageSearcher::~MaxCodeCoverageSearcher()
{
	delete m_batchingSearcher;
}

MaxCodeCoverageSearcherState::MaxCodeCoverageSearcherState()
    : m_metric(0),
      m_plugin(0),
      m_state(0)
{
}

MaxCodeCoverageSearcherState::MaxCodeCoverageSearcherState(S2EExecutionState *s, Plugin *p)
    : m_metric(0),
      m_plugin(static_cast<MaxCodeCoverageSearcher*>(p)),
      m_state(s)
{
}

MaxCodeCoverageSearcherState::~MaxCodeCoverageSearcherState()
{
}

PluginState *MaxCodeCoverageSearcherState::clone() const
{
    return new MaxCodeCoverageSearcherState(*this);
}

PluginState *MaxCodeCoverageSearcherState::factory(Plugin *p, S2EExecutionState *s)
{
    MaxCodeCoverageSearcherState *ret = new MaxCodeCoverageSearcherState(s, p);
    return ret;
}

void MaxCodeCoverageSearcher::slotTranslateBlockStart(
        ExecutionSignal *signal,
        S2EExecutionState *state,
        TranslationBlock *tb,
        uint64_t block_pc)
{
    signal->connect(sigc::mem_fun(*this, &MaxCodeCoverageSearcher::slotExecuteBlockStart));
}

uint64_t MaxCodeCoverageSearcher::penaltyFunction(uint64_t state_metric, uint64_t block_execution_times)
{
    return state_metric + block_execution_times;
}

void MaxCodeCoverageSearcher::slotExecuteBlockStart(
            S2EExecutionState *state,
            uint64_t block_pc)
{
    DECLARE_PLUGINSTATE(MaxCodeCoverageSearcherState, state);

    if (m_perStateCodeCoverage)
    {
        plgState->m_metric = penaltyFunction(plgState->m_metric, plgState->m_executedBasicBlocks[block_pc]);
    }
    else
    {
        plgState->m_metric = penaltyFunction(plgState->m_metric, m_executedBasicBlocks[block_pc]);
    }

    plgState->m_executedBasicBlocks[block_pc] += 1;
    m_executedBasicBlocks[block_pc] += 1;
}



} // namespace plugins
} // namespace s2e
