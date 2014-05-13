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

#include "MinStateSpawningSearcher.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Plugins/Initializer.h>

#include <iostream>

namespace s2e {
namespace plugins {

using namespace llvm;

S2E_DEFINE_PLUGIN(MinStateSpawningSearcher, "Prioritizes states that are about to execute unexplored translation blocks",
                  "MinStateSpawningSearcher", "Initializer");
				  
struct StateComparator
{
  Plugin *p;

  StateComparator(Plugin *p)
      : p(p)
  {
  }

  bool operator()(const S2EExecutionState *s1, const S2EExecutionState *s2) const
  {
      const MinStateSpawningSearcherState *p1 =
             static_cast<MinStateSpawningSearcherState*>(
                     p->getPluginState(
                             const_cast<S2EExecutionState*>(s1),
                             &MinStateSpawningSearcherState::factory));
     const MinStateSpawningSearcherState *p2 =
             static_cast<MinStateSpawningSearcherState*>(
                     p->getPluginState(
                             const_cast<S2EExecutionState*>(s2),
                             &MinStateSpawningSearcherState::factory));

     if (p1->m_penalty == p2->m_penalty)
         return s1->getID() < s2->getID();

     return p1->m_penalty < p2->m_penalty;
  }
};

void MinStateSpawningSearcher::initialize()
{
//    m_parentSearcher = NULL;
    m_currentState = 0;

    m_verbose = s2e()->getConfig()->getBool(getConfigKey() + ".verbose", false);
    m_timeBudget = s2e()->getConfig()->getDouble(getConfigKey() + ".batch_time_budget", 1.0);
	m_penaltyFactor = s2e()->getConfig()->getInt(getConfigKey() + ".penalty_factor", 1);
	m_stateComparator = new StateComparator(this);
	
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &MinStateSpawningSearcher::slotStateFork));

    assert(s2e()->getPlugin("Initializer") && "MinStateSpawningSearcher requires Initializer plugin");
    static_cast<Initializer *>(s2e()->getPlugin("Initializer"))->onInitialize.connect(sigc::mem_fun(*this, &MinStateSpawningSearcher::slotInitialize));
}

void MinStateSpawningSearcher::slotInitialize(S2EExecutionState *state)
{
    klee::Searcher *previousSearcher = 0;
    klee::Searcher *newSearcher = 0;

    s2e()->getDebugStream() << "[MinStateSpawningSearcher] initializeSearcher called" << '\n';

    previousSearcher = s2e()->getExecutor()->getSearcher();

    assert(previousSearcher && "No searcher set in klee");

    if (m_timeBudget == 0.0)
    {
        newSearcher = this;
    }
    else
    {
        m_batchingSearcher = new klee::BatchingSearcher(this, m_timeBudget, 1000);
        newSearcher = m_batchingSearcher;
        s2e()->getExecutor()->setSearcher(m_batchingSearcher);
    }

    newSearcher->addState(state, state);

    while (!previousSearcher->empty())
    {
        klee::ExecutionState& prevState = previousSearcher->selectState();

        if (static_cast<S2EExecutionState *>(&prevState)->getID() != state->getID())
            newSearcher->addState(&prevState, static_cast<klee::ExecutionState *>(state));

        previousSearcher->removeState(&prevState, static_cast<klee::ExecutionState *>(state));
    }

    delete previousSearcher;

    s2e()->getExecutor()->setSearcher(newSearcher);
}

klee::ExecutionState& MinStateSpawningSearcher::selectState()
{
    if (!m_states.empty())
    {
        //TODO: Searching the whole list is time-intensive ...
        S2EExecutionState *next_state = *std::min_element(m_states.begin(), m_states.end(), *m_stateComparator);
        if (m_verbose)  {
		  DECLARE_PLUGINSTATE(MinStateSpawningSearcherState, next_state);
          s2e()->getWarningsStream() << "[MinStateSpawningSearcher] selectState called, selecting next state " 
			  << next_state->getID()  << " with penalty "
			  << plgState->m_penalty << '\n';
	    }
        return *next_state;
    }
    else
    {
        s2e()->getWarningsStream() << "MinStateSpawningSearcher] selectState called, did not find any state!" << '\n';
        assert(false);
    }
}

void MinStateSpawningSearcher::update(klee::ExecutionState *current,
                    const std::set<klee::ExecutionState*> &addedStates,
                    const std::set<klee::ExecutionState*> &removedStates)
{
    foreach2(it, removedStates.begin(), removedStates.end()) {
        S2EExecutionState *es = static_cast<S2EExecutionState*>(*it);
        if (m_verbose)
          s2e()->getDebugStream() << "removing state " << hexval(es) << " from searcher" << '\n';
        m_states.remove(es);
    }

    foreach2(it, addedStates.begin(), addedStates.end()) {
        S2EExecutionState *es = static_cast<S2EExecutionState*>(*it);
        if (m_verbose)
          s2e()->getDebugStream() << "adding state " << hexval(es) << " to searcher" << '\n';
        m_states.push_back(es);
    }
}


bool MinStateSpawningSearcher::empty()
{
    return m_states.empty();
}

MinStateSpawningSearcher::~MinStateSpawningSearcher()
{
	if (m_batchingSearcher)  {
		delete m_batchingSearcher;
	}
	if (m_stateComparator)  {
		delete m_stateComparator;
	}
}

MinStateSpawningSearcherState::MinStateSpawningSearcherState()
    : m_penalty(0)
{
}

MinStateSpawningSearcherState::~MinStateSpawningSearcherState()
{
}

PluginState *MinStateSpawningSearcherState::clone() const
{
    return new MinStateSpawningSearcherState(*this);
}

PluginState *MinStateSpawningSearcherState::factory(Plugin *p, S2EExecutionState *s)
{
    return new MinStateSpawningSearcherState();
}

void MinStateSpawningSearcher::slotStateFork(S2EExecutionState* originalState,
                    const std::vector<S2EExecutionState*>& newStates,
                    const std::vector<klee::ref<klee::Expr> >& newConditions)
{
	uint64_t forkingPointPenalty = m_forkingPoints[originalState->getPc()];

	if (m_verbose)  {	
		s2e()->getWarningsStream() << "[MinStateSpawningSearcher] Forking at PC " << hexval(originalState->getPc())
			<< " in state " << originalState->getID() 
			<< " where forking point has penalty " << forkingPointPenalty << '\n';
	}
	
	//Penalize every state starting from the second forking at the same point
	foreach2(newState, newStates.begin(), newStates.end())
	{
		DECLARE_PLUGINSTATE(MinStateSpawningSearcherState, originalState);
		
		uint64_t oldStatePenalty = plgState->m_penalty;
		//Calculate new penalty
		plgState->m_penalty =  oldStatePenalty + forkingPointPenalty * m_penaltyFactor;
	
		if (m_verbose) {	
			s2e()->getWarningsStream() << "\tstate " << (*newState)->getID() 
				<< ", old penalty " << oldStatePenalty << ", new penalty " << plgState->m_penalty << '\n';
		}
	}
	
	//Increase penalty for forking point
	m_forkingPoints[originalState->getPc()] += 1;
}



} // namespace plugins
} // namespace s2e
