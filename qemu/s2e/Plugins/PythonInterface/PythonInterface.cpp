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

//Has to be here, boost is picky about the header order
//#include <boost/python.hpp>

#include <s2e/Plugins/PythonInterface/PythonInterface.h>

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>

#include <iostream>
#include <list>

extern "C" {
	#include <Python.h>
}


//using boost::python::object;
//using boost::python::import;
//using boost::python::exec_file;
//using boost::python::exec;
//using boost::python::call;
//using boost::python::override;
//using boost::python::wrapper;
//using boost::noncopyable;
//using boost::python::class_;
//using boost::python::no_init;
//using boost::python::init;
//using boost::python::def;
//using boost::python::pure_virtual;


#define nullptr NULL



//Magic to make klee::ref smart pointers work
//namespace boost {
//    namespace python  {
//        template<typename T> struct pointee< klee::ref< T > > {
//        	typedef T type;
//        };
//    }
//}

namespace s2e {
namespace plugins {

//Method declaration for BOOST_PYTHON_MODULE(s2e)
//extern "C" PyObject* PyInit_s2e();

S2E_DEFINE_PLUGIN(PythonInterface, "Interface plugin for developing plugins in Python3", "",);

//class PluginWrapper : public Plugin, public wrapper<Plugin>
//{
//public:
//	PluginWrapper(S2E* s2e)
//        : Plugin(s2e)
//    {
//    }
//
//	virtual void initialize() {
//		if (override method = this->get_override("initialize"))
//		{
//			method();
//		}
//		else {
//			//TODO: catch not implemented
//			assert(false && "Method not overriden by python");
//		}
//	}
//
//	virtual PluginInfo* getPluginInfo() const {
//		if (override method = this->get_override("getPluginInfo"))
//		{
//			return method();
//		}
//		else {
//			//TODO: catch not implemented
//			assert(false && "Method not overriden by python");
//			return nullptr;
//		}
//	}
//};
//
//static std::list< PluginInfo > pythonPluginInfo;

//static void registerPlugin(PluginInfo info)
//{
//	pythonPluginInfo.push_back(info);
//	//TODO: Using the global pointer is a bit ugly, but I don't know how to get the pointer
//	//from the plugin class
//	g_s2e->registerPlugin(&pythonPluginInfo.back());
//}


static std::string getString(PyObject* str)
{
	PyObject* asciiString = PyUnicode_AsASCIIString(str);
	std::string result(PyBytes_AsString(asciiString));
	Py_DECREF(asciiString);
	return result;
}

class PythonPluginWrapper : public Plugin
{
private:
	PythonInterface* m_plugin;
	PyObject* m_pyPlugin;
public:
	PythonPluginWrapper(PythonInterface* plugin, PyObject* pyPlugin)
		: Plugin(plugin->s2e()),
		  m_plugin(plugin),
		  m_pyPlugin(pyPlugin)
	{
	}
	virtual const PluginInfo* getPluginInfo() const;

	virtual void initialize();
};

static Plugin* call_plugin_create(S2E* s2e, void* opaque)
{
	std::pair<PythonInterface*, PyObject*>* pointers = reinterpret_cast< std::pair< PythonInterface*, PyObject* >* >(opaque);
	//TODO: stub
	PyObject* callable = pointers->second;
	PythonInterface* plugin = pointers->first;
	assert(PyCallable_Check(callable));
	//TODO: Add parameter
	PyObject* args = PyList_New(1);
	PyList_SetItem(args, 0, plugin->m_s2e_instance);
	PyObject* result = PyObject_Call(callable, args, Py_None);

	Py_DECREF(args);
	return new PythonPluginWrapper(plugin, result);
}

static PluginInfo* parsePluginInfo(PythonInterface* plugin, PyObject* dict)
{
	//TODO: Memory leaks
	PyObject* pyDependencies = NULL;
	PyObject* pyInstanceCreator = NULL;
	PluginInfo plgInfo;

	assert(PyDict_Check(dict));

	if (!PyDict_GetItemString(dict, "name")) {
		PyErr_SetString(PyExc_TypeError, "PluginInfo dictionary must contain key 'name'");
		return NULL;
	}

	if (!PyUnicode_Check(PyDict_GetItemString(dict, "name"))) {
		PyErr_SetString(PyExc_TypeError, "PluginInfo dictionary must contain key 'name' with value of type unicode");
		return NULL;
	}

	if (!PyDict_GetItemString(dict, "instanceCreator")) {
		PyErr_SetString(PyExc_TypeError, "PluginInfo dictionary must contain key 'instanceCreator'");
		return NULL;
	}

	if (!PyCallable_Check(PyDict_GetItemString(dict, "instanceCreator"))) {
		PyErr_SetString(PyExc_TypeError, "PluginInfo dictionary must contain key 'instanceCreator' with value of type callable");
		return NULL;
	}

	if (PyDict_GetItemString(dict, "description") && !PyUnicode_Check(PyDict_GetItemString(dict, "description"))) {
		PyErr_SetString(PyExc_TypeError, "PluginInfo dictionary value of key 'description' must be unicode");
		return NULL;
	}

	if (PyDict_GetItemString(dict, "configKey") && !PyUnicode_Check(PyDict_GetItemString(dict, "configKey"))) {
		PyErr_SetString(PyExc_TypeError, "PluginInfo dictionary value of key 'configKey' must be unicode");
		return NULL;
	}

	if (PyDict_GetItemString(dict, "functionName") && !PyUnicode_Check(PyDict_GetItemString(dict, "functionName"))) {
		PyErr_SetString(PyExc_TypeError, "PluginInfo dictionary value of key 'functionName' must be unicode");
		return NULL;
	}

	plgInfo.name = getString(PyDict_GetItemString(dict, "name"));
	pyInstanceCreator = PyDict_GetItemString(dict, "instanceCreator");

	if (PyDict_GetItemString(dict, "functionName"))
		plgInfo.functionName = getString(PyDict_GetItemString(dict, "functionName"));
	else
		plgInfo.functionName = plgInfo.name;
	if (PyDict_GetItemString(dict, "configKey"))
		plgInfo.configKey = getString(PyDict_GetItemString(dict, "configKey"));
	else
		plgInfo.configKey = plgInfo.name;
	if (PyDict_GetItemString(dict, "description"))
			plgInfo.description = getString(PyDict_GetItemString(dict, "description"));

	if (PyDict_GetItemString(dict, "dependencies"))
	{
		pyDependencies = PyDict_GetItemString(dict, "dependencies");
		for (Py_ssize_t i = 0; i < PySequence_Size(pyDependencies); i++)
		{
			PyObject* item = PySequence_GetItem(pyDependencies, i);
			if (!PyUnicode_Check(item)) {
				PyErr_SetString(PyExc_TypeError, "register_plugin parameter dependencies needs to be a sequence or strings");
				return NULL;
			}

			plgInfo.dependencies.push_back(getString(item));
		}
	}

	if (std::find(plgInfo.dependencies.begin(), plgInfo.dependencies.end(), std::string("PythonInterface")) == plgInfo.dependencies.end())
		plgInfo.dependencies.push_back("PythonInterface");

	plgInfo.instanceCreator = &call_plugin_create;
	plgInfo.opaque = new std::pair<PythonInterface*, PyObject*>(std::make_pair(plugin, pyInstanceCreator));
	return new PluginInfo(plgInfo);
}

const PluginInfo* PythonPluginWrapper::getPluginInfo() const
{
	//TODO: leaks memory
	PyObject* infoDict = PyObject_GetAttrString(m_pyPlugin, "plugin_info");
	if (!infoDict || !PyDict_Check(infoDict))
	{
		m_plugin->s2e()->getWarningsStream() << "[PythonInterface] Error getting plugin info from wrapped python plugin class" << '\n';
		return NULL;
	}

	return parsePluginInfo(m_plugin, infoDict);
}

void PythonPluginWrapper::initialize() {
	PyObject_CallMethod(m_pyPlugin, "initialize", NULL);
}

static PyObject* register_plugin(PyObject* self, PyObject* args, PyObject* kw)
{
	PyObject* dict;
	PythonInterface* plugin = *reinterpret_cast<PythonInterface**>(PyModule_GetState(self));
	static const char* kwlist[] = {
		"info",
		NULL
	};

	if (!PyArg_ParseTupleAndKeywords(
			args,
			kw,
			"O!",
			const_cast<char **>(kwlist),
			&PyDict_Type,
			&dict))
	{
		return NULL;
	}

	plugin->s2e()->getWarningsStream() << "Hello world" << '\n';

	PluginInfo* info = parsePluginInfo(plugin, dict);

	if (!info)
		return NULL;

	plugin->m_pluginInfo.push_back(info);

	plugin->s2e()->registerPlugin(info);
	return Py_None;
}

static PyMethodDef s2e_methods[] = {
    {"register_plugin",  reinterpret_cast<PyCFunction>(register_plugin), METH_VARARGS | METH_KEYWORDS,
     "register an S2E plugin written in python"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef s2e_module = {
   PyModuleDef_HEAD_INIT,
   "s2e",   /* name of module */
   "S2E access module", /* module documentation, may be NULL */
   sizeof(void *),       /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   s2e_methods
};

 static PyObject* PyInit_s2e(void)
{
	return PyModule_Create(&s2e_module);
}

 PythonInterface::PythonInterface(S2E* s2e)
 	 : Plugin(s2e),
 	   m_s2e_instance(Py_None)
 {
	 static const wchar_t * program_name = L"qemu-system-arm";

	/* Add a built-in module, before Py_Initialize */
	if (PyImport_AppendInittab("s2e", PyInit_s2e)) {
		s2e->getWarningsStream() << "[PythonInterface] Error adding s2e python module to inittab" << '\n';
		return;
	}

	/* Pass argv[0] to the Python interpreter */
	Py_SetProgramName(const_cast<wchar_t*>(program_name));

	/* Initialize the Python interpreter.  Required. */
	Py_Initialize();
	m_s2e_module = PyImport_ImportModule("s2e");
	if (!m_s2e_module) {
		s2e->getWarningsStream() << "[PythonInterface] Error importing s2e module" << '\n';
		return;
	}

	*reinterpret_cast<PythonInterface**>(PyModule_GetState(m_s2e_module)) = this;

	//TODO: Generate s2e class instance
	m_s2e_instance = Py_None;

	//Get python file from configuration
	std::string config_file = s2e->getConfig()->getString(
						getConfigKey() + ".python_file");

	if (config_file.empty())
	{
		s2e->getWarningsStream() << "[PythonInterface] ERROR: PythonInterface plugin needs a Python "
			<< "script specified via the 'python_file' configuration option. "
			<< "Plugin is exiting now."
			<< '\n';

		return;
	}

	if (PyRun_SimpleFileEx(fopen(config_file.c_str(), "r"), config_file.c_str(), 1))  {
		s2e->getWarningsStream() << "[PythonInterface] Error running python script" << '\n';
		return;
	}
 }

void PythonInterface::initialize()
{
}

} // namespace plugins
} // namespace s2e
