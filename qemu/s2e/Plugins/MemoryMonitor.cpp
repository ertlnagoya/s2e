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
 * All contributors are listed in S2E-AUTHORS file.
 *
 */

#include "MemoryMonitor.h"
#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>

#define nullptr (0)

namespace s2e
{
  namespace plugins
  {

    S2E_DEFINE_PLUGIN(MemoryMonitor,
        "Plugin for monitoring memory regions with less performance impact", "",
        );

    void
    MemoryMonitor::initialize()
    {
      ConfigFile *cfg = s2e()->getConfig();
      bool ok;

      m_verbose =
          cfg->getBool(getConfigKey() + ".verbose", false, &ok);
          
      

      s2e()->getCorePlugin()->onDataMemoryAccess.connect(
          sigc::mem_fun(*this, &MemoryMonitor::slotMemoryAccess));

      if (m_verbose)
          s2e()->getDebugStream() << "[MemoryMonitor]: initialized" << '\n';
    }

    MemoryMonitor::MemoryMonitor(S2E* s2e) :
        Plugin(s2e)
    {
//      for (uint64_t i = 0; i < PAGE_DIRECTORY_SIZE; i++)
//      {
//        pageDirectory[i] = nullptr;
//      }

    }

    MemoryMonitor::~MemoryMonitor()
    {
//      for (uint64_t i = 0; i < PAGE_DIRECTORY_SIZE; i++)
//      {
//        if (pageDirectory[i])
//        {
//          delete pageDirectory[i];
//          pageDirectory[i] = nullptr;
//        }
//      }
    }

    void
    MemoryMonitor::slotMemoryAccess(S2EExecutionState *state,
        klee::ref<klee::Expr> virtaddr /* virtualAddress */,
        klee::ref<klee::Expr> hostaddr /* hostAddress */,
        klee::ref<klee::Expr> value /* value */, bool isWrite, bool isIO)
    {
    	int access_type = 0;
		uint64_t address = 0;
		bool isCode = false;

		//TODO: Currently there is no way to find out if this is a code access
		if (isWrite)
			access_type |= ACCESS_TYPE_WRITE;
		else if (isCode)
			access_type |= ACCESS_TYPE_EXECUTE;
		else
			access_type |= ACCESS_TYPE_READ;

		if (isIO)
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
					<< "[MemoryInterceptor] slotMemoryRead called with address = " << hexval(address)
					<< ((access_type & ACCESS_TYPE_CONCRETE_ADDRESS) ? " [concrete]" : " [symbolic]")
					<< ", access_type = " << hexval(access_type)
					<< ", size = " << (value->getWidth() / 8)
					<< ", is_io = " << isIO
					<< ", is_code = " << isCode
					<< '\n';
		}

		for (std::list< MemoryAccessListener* >::iterator listener_itr = this->m_listeners.begin();
			 listener_itr != this->m_listeners.end();
			 listener_itr++)
		{
			if (
					//If access type matches desired mask and either address is symbolic or matches the given range
					((*listener_itr)->getAccessMask() & access_type) == access_type &&
					(
						(access_type & ACCESS_TYPE_SYMBOLIC_ADDRESS) ||
						((*listener_itr)->getAddress() <= address &&
						 (*listener_itr)->getAddress() + (*listener_itr)->getSize() > address)
					)
				)
			{
				//TODO: Pass isCode flag
				(*listener_itr)->access(state, virtaddr, hostaddr, value, isWrite, isIO, false);
			}
		}
    }

    void
    MemoryMonitor::addListener(MemoryAccessListener* listener)
    {
      

      this->m_listeners.push_back(listener);
    }

    void
    MemoryMonitor::removeListener(MemoryAccessListener* listener)
    {
    	this->m_listeners.remove(listener);
    }

  } // namespace plugins
} // namespace s2e
