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

#ifndef S2E_PLUGINS_DEBUG_H
#define S2E_PLUGINS_DEBUG_H

#include <tr1/memory> //shared_ptr
#include <queue>

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/MemoryInterceptor.h>


extern "C" {
#include <qemu-thread.h>
}

#include <s2e/cajun/json/reader.h>
#include <s2e/QemuSocket.h>

std::string intToHex(uint64_t val);
static uint64_t hexBufToInt(std::string str);
std::vector<std::string> split(std::string input);
std::vector<int> split_to_int(std::string input);

class TCPClient {
public:
    TCPClient(std::string host, int port);
    ~TCPClient();
    void sendline(std::string msg);
    std::string recvline();
    std::string recvuntil(std::string terminator);
private:
    int m_sock;
    struct sockaddr_in m_addr;
    std::string m_buf;
};

class OpenOCD {
public:
    OpenOCD();
    ~OpenOCD();
    std::string command(std::string cmd, bool expect_response = true);
    std::vector<int> mdw(int addr, int count);
    void mww(int addr, int content);
private:
    TCPClient m_openocd;
};

namespace s2e {
namespace plugins {
    
class RemoteMemoryInterface
{
public:
    RemoteMemoryInterface(S2E* s2e, std::string sockAddress, bool verbose = false);
    virtual ~RemoteMemoryInterface();
    void writeMemory(S2EExecutionState*, uint32_t address, int size, uint64_t value);
    uint64_t readMemory(S2EExecutionState*, uint32_t address, int size);

	/* low level operations */
	void submitRequest(S2EExecutionState *, json::Object &request);
	bool waitForAnswer(S2EExecutionState *, std::tr1::shared_ptr<json::Object> &response);
	bool submitAndWait(S2EExecutionState *,
			json::Object &request,
			std::tr1::shared_ptr<json::Object> &response);
	bool buildCPUState(S2EExecutionState *, json::Object &cpu_state, std::string op);
    
    void parse(std::string& token);
	bool wasHit() {return m_hit;}
	void resetHit() {m_hit = false;}
	bool m_writeBack;
    
private:
    static void * receiveThread(void *);
    void handleClientCommand(std::string cmd, std::tr1::shared_ptr<json::Object> params);
    
    S2E* m_s2e;
    QemuMutex m_mutex;
    QemuCond m_responseCond;
    QemuThread m_thread;
    std::queue<std::tr1::shared_ptr<json::Object> > m_interruptQueue;
    std::queue<std::tr1::shared_ptr<json::Object> > m_responseQueue;
    bool m_cancelThread;
    std::tr1::shared_ptr<s2e::QemuTcpSocket> m_socket;
    S2EExecutionState * m_state;
    bool m_verbose;
	bool m_hit;
	void setHit() {m_hit = true;}

    OpenOCD m_openocd_client;
};
    
class RemoteMemoryListener : public MemoryAccessHandler
{
public:
    RemoteMemoryListener(S2E* s2e, RemoteMemoryInterface* remoteMemoryIf, uint64_t address, uint64_t size, uint64_t mask);

    virtual klee::ref<klee::Expr> read(S2EExecutionState *state,
            klee::ref<klee::Expr> virtaddr,
            klee::ref<klee::Expr> hostaddr,
            unsigned size,
            bool isIO, bool isCode);

    virtual bool write(S2EExecutionState *state,
                klee::ref<klee::Expr> virtaddr,
                klee::ref<klee::Expr> hostaddr,
                klee::ref<klee::Expr> value,
                bool isIO);

    virtual ~RemoteMemoryListener();
private:
    RemoteMemoryInterface* m_remoteMemoryIf;
};

/**
 *  This is a plugin for aiding in debugging guest code.
 *  XXX: To be replaced by gdb.
 */
class RemoteMemory : public Plugin
{
    S2E_PLUGIN
public:
    RemoteMemory(S2E* s2e)
        : Plugin(s2e),
          m_verbose(false)
    {
    }

    virtual ~RemoteMemory();

    void initialize();
	bool wasHit() {return m_remoteInterface->wasHit();}
	void resetHit() {m_remoteInterface->resetHit();}
	std::tr1::shared_ptr<RemoteMemoryInterface> getInterface() {return m_remoteInterface;}
    
private:
    enum MemoryAccessType {EMemoryAccessType_None, EMemoryAccessType_Read, EMemoryAccessType_Write, EMemoryAccessType_Execute};
    
    bool m_verbose;
    std::tr1::shared_ptr<RemoteMemoryInterface> m_remoteInterface;
    
};

std::string intToHex(uint64_t);

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
