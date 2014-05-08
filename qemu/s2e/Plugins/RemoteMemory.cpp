/*
 * S2E Selective Symbolic Execution Framework
 *
 * Copyright (c) 2010, Eurecom
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
 * @author Jonas Zaddach <zaddach@eurecom.fr>
 *
 */

extern "C" {
#include <qemu-common.h>
#include <cpu-all.h>
#include <exec-all.h>
#include <qemu_socket.h>
#include <hw/irq.h>

#include <qint.h>
#include <qstring.h>
#include <qdict.h>
#include <qjson.h>
#include <qemu-thread.h>
}

#include "RemoteMemory.h"
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <s2e/cajun/json/reader.h>
#include <s2e/cajun/json/writer.h>

#include <iostream>
#include <sstream>
#include <iomanip>

namespace s2e {
namespace plugins {
    
S2E_DEFINE_PLUGIN(RemoteMemory, "Asks a remote program what the memory contents actually should be", "RemoteMemory", "MemoryInterceptor", "Initializer");

void RemoteMemory::initialize()
{
    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    
    m_verbose =
        cfg->getBool(getConfigKey() + ".verbose", false, &ok);
	bool writeBack =
		cfg->getBool(getConfigKey() + ".writeBack", false, &ok);
      
    std::string serverSocketAddress = cfg->getString(getConfigKey() + ".listen", ":5555", &ok);
    
    m_remoteInterface = std::tr1::shared_ptr<RemoteMemoryInterface>(new RemoteMemoryInterface(s2e(), serverSocketAddress, m_verbose)); 
	m_remoteInterface->m_writeBack = writeBack;
    MemoryInterceptor* memoryInterceptor = static_cast<MemoryInterceptor *>(s2e()->getPlugin("MemoryInterceptor"));
    assert(memoryInterceptor);
    
        
     std::vector<std::string> keys = cfg->getListKeys(getConfigKey() + ".ranges", &ok);
     if (ok)
     {
         for (std::vector<std::string>::iterator itr = keys.begin();
              itr != keys.end();
              itr++)
         {
             int mask = ACCESS_TYPE_CONCRETE_VALUE | ACCESS_TYPE_SYMBOLIC_VALUE
                     | ACCESS_TYPE_CONCRETE_ADDRESS | ACCESS_TYPE_IO | ACCESS_TYPE_NON_IO;

             if (!cfg->hasKey(getConfigKey() + ".ranges." + *itr + ".address") || 
                 !cfg->hasKey(getConfigKey() + ".ranges." + *itr + ".size")) 
             {
                 s2e()->getWarningsStream() << "[RemoteMemory] Invalid range configuration key: '" << *itr << "'. start or end subkey is missing." << '\n';
             }
             else
             {
                 if (cfg->hasKey(getConfigKey() + ".ranges." + *itr + ".access"))
                 {
                     ConfigFile::string_list access_words = cfg->getStringList(
                             getConfigKey() + ".ranges." + *itr + ".access",
                             ConfigFile::string_list(),
                             &ok);
                     if (ok)
                     {
                         for(ConfigFile::string_list::const_iterator access_word = access_words.begin();
                             access_word != access_words.end();
                             access_word++)
                         {
                             if (*access_word == "read")
                                 mask |= ACCESS_TYPE_READ;
                             else if (*access_word == "write")
                                 mask |= ACCESS_TYPE_WRITE;
                             else if (*access_word == "execute")
                                 mask |= ACCESS_TYPE_EXECUTE;
                         }
                     }
                 }
                 else
                 {
                     mask |= ACCESS_TYPE_READ | ACCESS_TYPE_WRITE | ACCESS_TYPE_EXECUTE;
                 }

                 uint64_t address = cfg->getInt(getConfigKey() + ".ranges." + *itr + ".address");
                 uint64_t size = cfg->getInt(getConfigKey() + ".ranges." + *itr + ".size");
				 int mask = ACCESS_TYPE_READ | ACCESS_TYPE_WRITE |
					 ACCESS_TYPE_EXECUTE | ACCESS_TYPE_CONCRETE_VALUE |
					 ACCESS_TYPE_SYMBOLIC_VALUE |
					 ACCESS_TYPE_CONCRETE_ADDRESS | ACCESS_TYPE_IO |
					 ACCESS_TYPE_NON_IO | ACCESS_TYPE_SIZE_ANY;
                 s2e()->getDebugStream() << "[RemoteMemory] Monitoring memory range " << *itr << ": " << hexval(address) << "-" << hexval(address + size) << '\n';
                 memoryInterceptor->addInterceptor(new RemoteMemoryListener(
                        s2e(), 
                        m_remoteInterface.get(), 
                        address, 
                        size, 
                        mask));
             }
         }
     }
     else
     {
                 int mask = ACCESS_TYPE_READ | ACCESS_TYPE_WRITE | ACCESS_TYPE_EXECUTE | ACCESS_TYPE_CONCRETE_VALUE | ACCESS_TYPE_SYMBOLIC_VALUE 
                    | ACCESS_TYPE_CONCRETE_ADDRESS | ACCESS_TYPE_IO | ACCESS_TYPE_NON_IO;
         s2e()->getMessagesStream() << "[RemoteMemory] No memory ranges specified, forwarding requests for all memory" << '\n';
                 memoryInterceptor->addInterceptor(new RemoteMemoryListener(
                        s2e(), 
                        m_remoteInterface.get(), 
                        0, 
                        0xffffffffffffffffULL, 
                        mask));
     }
    
      
    if (m_verbose)
        s2e()->getDebugStream() << "[RemoteMemory]: initialized" << '\n';
}

RemoteMemory::~RemoteMemory()
{
}

std::string intToHex(uint64_t val)
{
    std::stringstream ss;
    
    ss << "0x" << std::hex << val;
    return ss.str();
}

static uint64_t hexBufToInt(std::string str)
{
    uint64_t val = 0;
    std::stringstream ss;
    
    ss << str;
    ss >> std::hex >> val;

    return val;
}

RemoteMemoryInterface::RemoteMemoryInterface(S2E* s2e, std::string remoteSockAddress, bool verbose) 
    : m_s2e(s2e), 
      m_cancelThread(false), 
      m_socket(std::tr1::shared_ptr<QemuTcpSocket>(new QemuTcpSocket())),
      m_state(NULL),
      m_verbose(verbose)
{   
    qemu_mutex_init(&m_mutex);
    qemu_cond_init(&m_responseCond);
    
    QemuTcpServerSocket serverSock(remoteSockAddress.c_str());
    m_s2e->getMessagesStream() << "[RemoteMemory]: Waiting for connection on " << remoteSockAddress << '\n';
    serverSock.accept(*m_socket);
    
    qemu_thread_create(&m_thread, &RemoteMemoryInterface::receiveThread, this, 0);
}

void * RemoteMemoryInterface::receiveThread(void * opaque)
{
    RemoteMemoryInterface * rmi = static_cast<RemoteMemoryInterface *>(opaque);
    while (!rmi->m_cancelThread)
    {
        std::string token;
            
        getline(*rmi->m_socket, token, '\n');

        if (token.size() == 0 && !rmi->m_socket->isConnected())
        {
            //TODO: do something to gracefully shutdown qemu (i,.e. unblock main thread, return dummy value, shutdown vm)
            rmi->m_s2e->getWarningsStream() << "[RemoteMemory] Remote end disconnected, machine is dead" << '\n';
            ::exit(1);
            break;
        }
        
        
        rmi->parse(token);
    }
    
    return NULL;
}

void RemoteMemoryInterface::parse(std::string& token)
{
    std::tr1::shared_ptr<json::Object> jsonObject = std::tr1::shared_ptr<json::Object>(new json::Object());

    std::istringstream tokenAsStream(token);
    
    try
    {
        json::Reader::Read(*jsonObject, tokenAsStream);
        
        if(jsonObject->Find("reply") != jsonObject->End())
        {
            //TODO: notify and pass object
            qemu_mutex_lock(&m_mutex);
            m_responseQueue.push(jsonObject);
            qemu_cond_signal(&m_responseCond);
            qemu_mutex_unlock(&m_mutex);
        }
        else
        {
            try
            {
                json::Object::iterator itrCmd = jsonObject->Find("cmd");
                if (itrCmd == jsonObject->End())
                {
                    m_s2e->getWarningsStream() << "[RemoteMemory] Received json object that was neither a cmd nor a reply: " << token << '\n';
                    return;
                }
                
                json::String& cmd = itrCmd->element;
                
                handleClientCommand(cmd, jsonObject);
            }
            catch (json::Exception& ex)
            {
                m_s2e->getWarningsStream() << "[RemoteMemory] JSON exception while handling a command from the client" << '\n';
            }
        }
    }
    catch (json::Exception& ex)
    {
        m_s2e->getWarningsStream() <<  "[RemoteMemory] Exception in JSON data: '" << token << "'" << '\n';
    }
}

void RemoteMemoryInterface::handleClientCommand(std::string cmd, std::tr1::shared_ptr<json::Object> params)
{
    qemu_mutex_lock(&m_mutex);
    m_interruptQueue.push(params);
    qemu_mutex_unlock(&m_mutex);
}

  
/**
 * Calls the remote helper to read a value from memory.
 */
uint64_t RemoteMemoryInterface::readMemory(S2EExecutionState * state, uint32_t address, int size)
{
     json::Object request;
     json::Object params;
     json::Object cpu_state;
     
	 setHit();
     if (m_verbose)
        m_s2e->getDebugStream() << "[RemoteMemory] reading memory from address " << hexval(address) << "[" << size << "]" << '\n';
     request.Insert(json::Object::Member("cmd", json::String("read")));
     
     //HACK: Instead of using the physical address switch here, this should be specified somehow ...
     klee::ref<klee::Expr> exprValue = state->readMemory(address, size << 3, S2EExecutionState::PhysicalAddress);
     
     if (exprValue.isNull())
     {
         if (m_verbose)
            m_s2e->getDebugStream() << "[RemoteMemory] Failed to read old memory value at address " << hexval(address) << '\n';
     }
     else if (isa<klee::ConstantExpr>(exprValue))
     {
         params.Insert(json::Object::Member("old_value", json::String(intToHex(cast<klee::ConstantExpr>(exprValue)->getZExtValue()))));
     }
     else
     {
         m_s2e->getWarningsStream() << "[RemoteMemory] Old value of memory at 0x" << hexval(address) << " is symbolic (currently not supported)" << '\n';
     }
         
     
     params.Insert(json::Object::Member("address", json::String(intToHex(address))));
     params.Insert(json::Object::Member("size", json::String(intToHex(size))));
     
	 buildCPUState(state, cpu_state, "read");
     request.Insert(json::Object::Member("params", params));
     request.Insert(json::Object::Member("cpu_state", cpu_state));

	 std::tr1::shared_ptr<json::Object> response;
	 submitAndWait(state, request, response);

	//TODO: There could be multiple responses, but we assume the first is the right
     json::String& strValue = (*response)["value"];
     uint64_t ret_val = hexBufToInt(strValue);

	if (m_writeBack) {
#ifdef TARGET_WORDS_BIGENDIAN
		assert(0 && "Cannot write back memory. Target is big endian.");
#endif
		if (m_verbose)
			m_s2e->getDebugStream() << "[RemoteMemory] write back value 0x" <<
				hexval(ret_val) << " to address 0x" << hexval(address) << '\n';
		assert(state);
		/* XXX: see above! */
		state->writeMemoryConcrete(address, &ret_val, size, S2EExecutionState::PhysicalAddress);
	}
	return ret_val;
}

bool RemoteMemoryInterface::waitForAnswer(S2EExecutionState *state,
		std::tr1::shared_ptr<json::Object> &response)
{
	qemu_mutex_lock(&m_mutex);
	m_state = state;

	while (m_responseQueue.empty())  {
		qemu_cond_wait(&m_responseCond, &m_mutex);
	}

	response = m_responseQueue.front();
	m_responseQueue.pop();
	m_state = NULL;
	qemu_mutex_unlock(&m_mutex);
	return true;
}
  
/**
 * Calls the remote helper to write a value to memory.
 * This method returns immediatly, as there is not return value to wait for.
 */
void RemoteMemoryInterface::writeMemory(S2EExecutionState * state, uint32_t address, int size, uint64_t value)
{
     json::Object request;
     json::Object params;
     json::Object cpu_state;
     
	 setHit();
     if (m_verbose)
        m_s2e->getDebugStream() << "[RemoteMemory] writing memory at address " << hexval(address) << "[" << size << "] = " << hexval(value) << '\n';
     request.Insert(json::Object::Member("cmd", json::String("write")));
     
     params.Insert(json::Object::Member("value", json::String(intToHex(value))));
         
     
     params.Insert(json::Object::Member("address", json::String(intToHex(address))));
     params.Insert(json::Object::Member("size", json::String(intToHex(size))));
     
     
	 buildCPUState(state, cpu_state, "write");
     request.Insert(json::Object::Member("params", params));
     request.Insert(json::Object::Member("cpu_state", cpu_state));

	 submitRequest(state, request);
}

bool RemoteMemoryInterface::buildCPUState(S2EExecutionState *state,
		json::Object &cpu_state,
		std::string op = "access")
{
	bool ret = true;

#ifdef TARGET_ARM
#define CPU_NB_REGS 16
#endif
	for (int i = 0; i < CPU_NB_REGS - 1; i++)
	{
		std::stringstream ss;

		ss << "r";
		ss << i;

		klee::ref<klee::Expr> exprReg =
			state->readCpuRegister(CPU_REG_OFFSET(i),
					CPU_REG_SIZE << 3);
		if (isa<klee::ConstantExpr>(exprReg))
		{
			cpu_state.Insert(json::Object::Member(ss.str(),
						json::String(intToHex(cast<klee::ConstantExpr>(exprReg)->getZExtValue()))));
		}
		else
		{
			std::string example =
				intToHex(m_s2e->getExecutor()->toConstantSilent(*state,
							exprReg)->getZExtValue());
			m_s2e->getWarningsStream() << "[RemoteMemory] Register "
				<< i << " was symbolic during a " << op << " at "
				<< hexval(state->getPc()) << ", taking " <<
				example << " as an example" << '\n';
			cpu_state.Insert(json::Object::Member(ss.str(),
						json::String(example)));
			ret = false;
		}
	}
	cpu_state.Insert(json::Object::Member("pc",
				json::String(intToHex(state->getPc()))));

#ifdef TARGET_ARM
	//TODO: Fill CPSR register
	//     cpsr.Insert(json::Object::Member("cf", json::Bool(
	cpu_state.Insert(json::Object::Member("cpsr",
				json::String(intToHex(state->getFlags()))));
#endif
	return ret;
}

void RemoteMemoryInterface::submitRequest(S2EExecutionState *state,
		json::Object &request)
{
	qemu_mutex_lock(&m_mutex);
	m_state = state;
	json::Writer::Write(request, *m_socket);
	m_socket->flush();
	qemu_mutex_unlock(&m_mutex);
}
bool RemoteMemoryInterface::submitAndWait(S2EExecutionState *state,
		json::Object &request,
		std::tr1::shared_ptr<json::Object> &response)
{
	qemu_mutex_lock(&m_mutex);
	m_state = state;
	json::Writer::Write(request, *m_socket);
	m_socket->flush();


	/* TODO: test if this is our request reply.
	 * Right now, the hidden assumption is that each submited request
	 * that requires an aswer is submited via this function i.e. we're
	 * *always* popping the reply
	 */
	while (m_responseQueue.empty())  {
		qemu_cond_wait(&m_responseCond, &m_mutex);
	}
	response = m_responseQueue.front();
	m_responseQueue.pop();
	m_state = NULL;
	qemu_mutex_unlock(&m_mutex);

	return true;
}

RemoteMemoryInterface::~RemoteMemoryInterface()
{
    qemu_cond_destroy(&m_responseCond);
    qemu_mutex_destroy(&m_mutex);
}


RemoteMemoryListener::RemoteMemoryListener(
        S2E* s2e,
        RemoteMemoryInterface* remoteMemoryIf,
        uint64_t address,
        uint64_t size,
        uint64_t mask)
        : MemoryAccessHandler(s2e, address, size, mask),
          m_remoteMemoryIf(remoteMemoryIf)
{
}

klee::ref<klee::Expr> RemoteMemoryListener::read(S2EExecutionState *state,
            klee::ref<klee::Expr> virtaddr,
            klee::ref<klee::Expr> hostaddr,
            unsigned size,
            bool isIO, bool isCode)
{
    if (!isa<klee::ConstantExpr>(virtaddr))
    {
        m_s2e->getWarningsStream() << "[RemoteMemory] A symbolic virtual address has been passed to RemoteMemory. Cannot handle this case." << '\n';
        return klee::ref<klee::Expr>();
    }

    uint64_t value = m_remoteMemoryIf->readMemory(state, cast<klee::ConstantExpr>(virtaddr)->getZExtValue(), size / 8);
    return klee::ConstantExpr::create(value, size);
}

bool RemoteMemoryListener::write(S2EExecutionState *state,
                klee::ref<klee::Expr> virtaddr,
                klee::ref<klee::Expr> hostaddr,
                klee::ref<klee::Expr> value,
                bool isIO)
{
    if (!isa<klee::ConstantExpr>(virtaddr))
    {
        m_s2e->getWarningsStream() << "[RemoteMemory] A symbolic virtual address has been passed to RemoteMemory. Cannot handle this case." << '\n';
        return false;
    }

    if (!isa<klee::ConstantExpr>(value))
    {
        m_s2e->getWarningsStream() << "[RemoteMemory] A symbolic value address has been passed to RemoteMemory. Cannot handle this case." << '\n';
        return false;
    }

    m_remoteMemoryIf->writeMemory(state, 
                                  cast<klee::ConstantExpr>(virtaddr)->getZExtValue(),
                                  value->getWidth() / 8,
                                  cast<klee::ConstantExpr>(value)->getZExtValue());

    return true;
}

RemoteMemoryListener::~RemoteMemoryListener() 
{
}

} /* namespace plugins */
} /* namespace s2e */
