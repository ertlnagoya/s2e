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

#include "ControlFlowGraph.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include <iostream>
#include <s2e/S2EExecutor.h>

#include <llvm/Function.h>

#define nullptr NULL

namespace s2e {
namespace plugins {

//TODO: Plugin not suitable for self-modifying code
//TODO: What happens on state switching?

S2E_DEFINE_PLUGIN(ControlFlowGraph, "Generate control flow graph from execution trace", "",);

uint64_t ControlFlowGraphNode::s_nodeCount = 0;

bool ControlFlowGraphNode::operator==(ControlFlowGraphNode* other)
{
	if (m_startPc != other->m_startPc)
		return false;
	if (m_endPc != other->m_endPc)
		return false;
	if (m_nodeCount != other->m_nodeCount)
		return false;
	return true;
}

std::string ControlFlowGraphNode::getName()
{
	std::stringstream ss;

	ss << "tb_" << std::dec << m_nodeCount << "_0x" << std::hex << m_startPc;
	return ss.str();
}

PluginState* ControlFlowGraphState::factory(Plugin *p, S2EExecutionState *s)
{
	return new ControlFlowGraphState(0);
}

void ControlFlowGraph::initialize()
{
    s2e()->getCorePlugin()->onTranslateBlockEnd.connect(
			sigc::mem_fun(*this, &ControlFlowGraph::slotTranslateBlockEnd));
    s2e()->getCorePlugin()->onStateKill.connect(
    		sigc::mem_fun(*this, &ControlFlowGraph::slotStateKill));
}

void ControlFlowGraph::slotTranslateBlockEnd(ExecutionSignal *signal,
                                      S2EExecutionState *state,
                                      TranslationBlock *tb,
                                      uint64_t pc,
                                      bool isStaticTarget,
                                      uint64_t nextStaticPc)
{
	ControlFlowGraphNode* node = new ControlFlowGraphNode(tb, pc);

	signal->connect(
		sigc::bind(sigc::mem_fun(*this, &ControlFlowGraph::slotExecuteBlockEnd), node));
}

void ControlFlowGraph::slotExecuteBlockEnd(S2EExecutionState *state,
                                      uint64_t pc,
                                      ControlFlowGraphNode* node)
{
	DECLARE_PLUGINSTATE(ControlFlowGraphState, state);

	if (plgState->m_prevNode == 0)
	{
		plgState->m_prevNode = node;
		m_root = node;
		return;
	}

	std::map< uint64_t, std::list< std::pair< ControlFlowGraphNode*, ControlFlowGraphNode* > > >::iterator mapItr
		= m_edges.find(plgState->m_prevNode->m_startPc);

	if (mapItr != m_edges.end())
	{
		bool edgeFound = false;
		for (std::list< std::pair< ControlFlowGraphNode*, ControlFlowGraphNode* > >::iterator listItr = mapItr->second.begin();
		     listItr != mapItr->second.end();
		     listItr++)
		{
			if (listItr->first == plgState->m_prevNode && listItr->second == node)
			{
				edgeFound = true;
				break;
			}
		}

		if (!edgeFound)
		{
			mapItr->second.push_back(std::make_pair(plgState->m_prevNode, node));
		}
	}
	else
	{
		m_edges[plgState->m_prevNode->m_startPc].push_back(std::make_pair(plgState->m_prevNode, node));
	}

	plgState->m_prevNode = node;
}

void ControlFlowGraph::slotStateKill(S2EExecutionState* state)
{
	if (s2e()->getExecutor()->getStatesCount() <= 1)
	{
		std::string filename = s2e()->getOutputFilename("cfg.dot");
		std::ofstream fout(filename.c_str());
		fout << "digraph CFG {\n";
		fout << "    " << m_root->getName() << " [shape=oval,peripheries=2];\n";

		for (std::map< uint64_t, std::list< std::pair< ControlFlowGraphNode*, ControlFlowGraphNode*> > >::iterator mapItr = m_edges.begin();
			 mapItr != m_edges.end();
			 mapItr++)
		{
			for (std::list< std::pair< ControlFlowGraphNode*, ControlFlowGraphNode*> >::iterator listItr = mapItr->second.begin();
				 listItr != mapItr->second.end();
				 listItr++)
			{
				fout << "    " << listItr->first->getName() << " -> " << listItr->second->getName() << ";\n";
			}
		}

		fout << "}\n";
		fout.close();
	}
}

} // namespace plugins
} // namespace s2e
