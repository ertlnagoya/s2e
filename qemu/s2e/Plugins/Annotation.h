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

/**
 * TODO:
 * - Currently only one memory annotation can be made per address. If there are
 *   several ranges that include an address, only the first one will be notified.
 * - Currently returning a different value in symbolic mode has unknown effects.
 *   I haven't yet understood from where the onDataMemoryAccess signal is emitted
 *   (S2EExecutor::handlerTraceMemoryAccess is called directly from
 *
 * This is the configuration used for the memory annotation:
 *     Annotation = {
 *       uart_read = {
 *           module = "bootloader",
 *           active = true,
 *           address = 0xfffb8000,
 *           size = 0x100,
 *           memoryAnnotation = "ann_read_serial",
 *           beforeInstruction = true,
 *           switchInstructionToSymbolic = true,
 *
 *       }
 *     }
 *
 * And this is the annotation function:
 *
 * function ann_read_serial(state, s2e, address, width, value, is_write, is_io)
 *   -- we are not interested in writes
 *   if is_write then
 *       return false, value
 *    end
 *
 *    if address == 0xfffb8018 then
 *        return false, 0x80 --TXFE set, RXFE not set
 *    elseif address == 0xfffb8004 then
 *        return false, 0x0
 *    else
 *        local pc = s2e:readRegister("pc")
 *        if pc >= 0xe8b4 and pc < 0xe8ec then
 *           --In uart_reset we don't care about the return value
 *           return false, 0
 *        elseif pc >= 0xE8F0 and pc < 0xE91C then
 *           local str_mfgt1 = "MFGT1"
 *           state:setValue("mfg_state", state:getValue("mfg_state") + 1)
 *           if state:getValue("mfg_state") > 5 then
 *               state:setValue("mfg_state", 1)
 *           end
 *           return false, string.byte(str_mfgt1, state:getValue("mfg_state"))
 *        else
 *           io.write(string.format("serial: Unknown access at address 0x%x, pc 0x%x\n", address, s2e:readRegister("pc")))
 *        end
 *    end
 * end
 */

#ifndef S2E_PLUGINS_FUNCSKIPPER_H
#define S2E_PLUGINS_FUNCSKIPPER_H

#include <s2e/Plugin.h>
#include <s2e/Plugins/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/FunctionMonitor.h>
#include <s2e/Plugins/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitor.h>
#include <s2e/ConfigFile.h>

#include <list>

namespace s2e {
namespace plugins {

    struct AnnotationCfgEntry
    {
        std::string cfgname;
        std::string module;
        uint64_t address;
        bool isActive;
        unsigned paramCount;

        bool isCallAnnotation;
        std::string annotation;
        unsigned invocationCount, returnCount;

        bool beforeInstruction;
        bool switchInstructionToSymbolic;

        AnnotationCfgEntry() {
            isCallAnnotation = true;
            address = 0;
            paramCount = 0;
            isActive = false;
            beforeInstruction = false;
            switchInstructionToSymbolic = false;
        }

        bool operator()(const AnnotationCfgEntry *a1, const AnnotationCfgEntry *a2) const {
            if (a1->isCallAnnotation != a2->isCallAnnotation) {
                return a1->isCallAnnotation < a2->isCallAnnotation;
            }

            int res = a1->module.compare(a2->module);
            if (!res) {
                return a1->address < a2->address;
            }
            return res < 0;
        }
    };

    struct MemoryAnnotationCfgEntry
    {
        std::string annotation;
        uint64_t rangeStart;
        uint64_t rangeSize;

        bool operator()(const MemoryAnnotationCfgEntry *a1, const MemoryAnnotationCfgEntry* a2) const {
            return a1->rangeStart < a2->rangeStart;
        }
    };

class LUAAnnotation;

class Annotation : public Plugin
{
    S2E_PLUGIN
public:
    typedef std::set<AnnotationCfgEntry*, AnnotationCfgEntry> CfgEntries;

    Annotation(S2E* s2e): Plugin(s2e) {}
    virtual ~Annotation();
    void initialize();

private:
    FunctionMonitor *m_functionMonitor;
    ModuleExecutionDetector *m_moduleExecutionDetector;
    OSMonitor *m_osMonitor;
    CfgEntries m_entries;
    std::list<MemoryAnnotationCfgEntry> m_memoryAnnotations;

    //To instrument specific instructions in the code
    bool m_translationEventConnected;
    TranslationBlock *m_tb;
    sigc::connection m_tbConnectionStart;
    sigc::connection m_tbConnectionEnd;

    std::string m_onStateKill;
    std::string m_onTimer;

    bool initSection(const std::string &entry, const std::string &cfgname);

    std::string checkCoreSignal(const std::string &cfgname,
                                const std::string &name);
    void registerCoreSignals(const std::string &cfgname);

    //CorePlugin signal hooks for annotations
    void onStateKill(S2EExecutionState* state);
    void onTimer();

    void onModuleLoad(
            S2EExecutionState* state,
            const ModuleDescriptor &module
            );

    void onFunctionRet(
            S2EExecutionState* state,
            AnnotationCfgEntry *entry
            );

    void onFunctionCall(
            S2EExecutionState* state,
            FunctionMonitorState *fns,
            AnnotationCfgEntry *entry
            );

    void onTranslateBlockStart(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            const ModuleDescriptor &module,
            TranslationBlock *tb,
            uint64_t pc);

    void onTranslateInstructionStart(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            TranslationBlock *tb,
            uint64_t pc);

    void onTranslateInstructionEnd(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            TranslationBlock *tb,
            uint64_t pc);

    void onTranslateInstruction(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            TranslationBlock *tb,
            uint64_t pc, bool isStart);

    void onModuleTranslateBlockEnd(
            ExecutionSignal *signal,
            S2EExecutionState* state,
            const ModuleDescriptor &module,
            TranslationBlock *tb,
            uint64_t endPc,
            bool staticTarget,
            uint64_t targetPc);

    void onInstruction(S2EExecutionState *state, uint64_t pc);

    void onDataMemoryAccess(S2EExecutionState*,
            klee::ref<klee::Expr> virtualAddress,
            klee::ref<klee::Expr> hostAddress,
            klee::ref<klee::Expr> value,
            bool isWrite, bool isIO);

    void invokeAnnotation(
            S2EExecutionState* state,
            FunctionMonitorState *fns,
            AnnotationCfgEntry *entry,
            bool isCall, bool isInstruction
        );

    friend class LUAAnnotation;
};

class AnnotationState: public PluginState
{
public:
    typedef std::map<std::string, uint64_t> Storage;

private:
    Storage m_storage;

public:
    AnnotationState();
    virtual ~AnnotationState();
    virtual AnnotationState* clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend class Annotation;

    uint64_t getValue(const std::string &key);
    void setValue(const std::string &key, uint64_t value);   
};

class LUAAnnotation
{
private:
    Annotation *m_plugin;
    bool m_doSkip;
    bool m_doKill;
    bool m_doGenerateTestcase;
    bool m_isReturn;
    bool m_isInstruction;
    S2EExecutionState *m_state;

public:
    static const char className[];
    static Lunar<LUAAnnotation>::RegType methods[];

    LUAAnnotation(Annotation *plg, S2EExecutionState *state);
    LUAAnnotation(lua_State *lua);
    ~LUAAnnotation();

    int setSkip(lua_State *L);
    int setKill(lua_State *L);
    int setGenerateTestcase(lua_State *L);
    int activateRule(lua_State *L);
    int isReturn(lua_State *L);
    int isCall(lua_State *L);

    int setValue(lua_State *L);
    int getValue(lua_State *L);

    int exit(lua_State *L);

    friend class Annotation;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FUNCSKIPPER_H
