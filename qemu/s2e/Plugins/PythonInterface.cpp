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

#include <s2e/Plugins/PythonInterface.h>

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

//BOOST_PYTHON_MODULE(s2e)
//{
//	class_<S2E, S2E*>("S2E", no_init)
//	;

//	class_<PluginWrapper>("Plugin", init<S2E*>())
//	class_<PluginWrapper>("Plugin", no_init)
//		.def("initialize", &Plugin::initialize)
//		.def("getPluginInfo", pure_virtual(&Plugin::getPluginInfo))
//		.def("getConfigKey", &Plugin::getConfigKey)
//		.def("getPluginState", &Plugin::getPluginState)
//	;

//	class_<PluginInfo>("PluginInfo", no_init)
//		.def_readwrite("name", &PluginInfo::name)
//		.def_readwrite("description", &PluginInfo::description)
//		.def_readwrite("functionName", &PluginInfo::functionName)
//		.def_readwrite("dependencies", &PluginInfo::dependencies)
//		.def_readwrite("configKey", &PluginInfo::configKey)
//		.def_readwrite("instanceCreator", &PluginInfo::instanceCreator)
//	;
//
//	def("PythonS2E_registerPlugin", &registerPlugin);
//}

static Plugin* call_plugin_create(S2E* s2e, void* opaque)
{
	//TODO: stub
	PyObject* callable = reinterpret_cast<PyObject *>(opaque);
	assert(PyCallable_Check(callable));
	//TODO: Add parameter
	PyObject_Call(callable, Py_None, Py_None);

	return NULL;
}

static PyObject* register_plugin(PyObject* self, PyObject* args, PyObject* kw)
{
	//TODO: Memory leaks on errors
	char* name = NULL;
	char* description = NULL;
	char* functionName = NULL;
	PyObject* pyDependencies = NULL;
	char* configKey = NULL;
	PyObject* pyInstanceCreator = NULL;
	S2E* s2e = (*reinterpret_cast<PythonInterface**>(PyModule_GetState(self)))->s2e();
	PythonInterface* plugin = *reinterpret_cast<PythonInterface**>(PyModule_GetState(self));
	PluginInfo plgInfo;

	static const char* kwlist[] = {
		"name",
		"instanceCreator",
		"description",
		"functionName",
		"dependencies",
		"configKey",
		NULL
	};
	if (!PyArg_ParseTupleAndKeywords(
			args,
			kw,
			"UO|UUO!U",
			const_cast<char **>(kwlist),
			&name,
			&pyInstanceCreator,
			&description,
			&functionName,
			&PyList_Type,
			&pyDependencies,
			&configKey))
	{
		return NULL;
	}

	if (!functionName)
		functionName = name;
	if (!configKey)
		configKey = name;

	if (!PySequence_Check(pyDependencies)) {
		s2e->getWarningsStream()
				<< "[PythonInterface] register_plugin called with parameter "
				<< "dependencies which is not a list" << '\n';
		PyErr_SetString(PyExc_TypeError, "register_plugin parameter dependencies needs to be a sequence");
		return NULL;
	}

	for (Py_ssize_t i = 0; i < PySequence_Size(pyDependencies); i++)
	{
		PyObject* item = PySequence_GetItem(pyDependencies, i);
		if (!PyUnicode_Check(item)) {
			s2e->getWarningsStream()
					<< "[PythonInterface] register_plugin called with parameter "
					<< "dependencies which is not a list of strings" << '\n';
			PyErr_SetString(PyExc_TypeError, "register_plugin parameter dependencies needs to be a sequence or strings");
			return NULL;
		}

		PyObject* asciiString = PyUnicode_AsASCIIString(item);
		plgInfo.dependencies.push_back(PyBytes_AsString(asciiString));
		Py_DECREF(asciiString);
		Py_DECREF(item);
	}

	if (std::find(plgInfo.dependencies.begin(), plgInfo.dependencies.end(), std::string("PythonInterface")) == plgInfo.dependencies.end())
		plgInfo.dependencies.push_back("PythonInterface");

	if (!PyCallable_Check(pyInstanceCreator))  {
		s2e->getWarningsStream()
				<< "[PythonInterface] register_plugin called with parameter "
				<< "instanceCreator which is not a callable" << '\n';
		PyErr_SetString(PyExc_TypeError, "register_plugin parameter instanceCreator needs to be a callables");
		return NULL;
	}

	plgInfo.name = name;
	plgInfo.description = description;
	plgInfo.functionName = functionName;
	plgInfo.configKey = configKey;
	plgInfo.instanceCreator = &call_plugin_create;
	plgInfo.opaque = pyInstanceCreator;
	plugin->m_pluginInfo.push_back(plgInfo);

	s2e->registerPlugin(&plugin->m_pluginInfo.back());
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


void PythonInterface::initialize()
{
	static const wchar_t * program_name = L"qemu-system-arm";

	/* Add a built-in module, before Py_Initialize */
	if (PyImport_AppendInittab("s2e", PyInit_s2e)) {
		s2e()->getWarningsStream() << "[PythonInterface] Error adding s2e python module to inittab" << '\n';
		return;
	}

	/* Pass argv[0] to the Python interpreter */
	Py_SetProgramName(const_cast<wchar_t*>(program_name));

	/* Initialize the Python interpreter.  Required. */
	Py_Initialize();
	PyObject* s2e_mod = PyImport_ImportModule("s2e");
	if (!s2e_mod) {
		s2e()->getWarningsStream() << "[PythonInterface] Error importing s2e module" << '\n';
		return;
	}

	*reinterpret_cast<PythonInterface**>(PyModule_GetState(s2e_mod)) = this;

	//Get python file from configuration
	std::string config_file = s2e()->getConfig()->getString(
						getConfigKey() + ".python_file");

	if (config_file.empty())
	{
		s2e()->getWarningsStream() << "[PythonInterface] ERROR: PythonInterface plugin needs a Python "
			<< "script specified via the 'python_file' configuration option. "
			<< "Plugin is exiting now."
			<< '\n';

		return;
	}

	if (PyRun_SimpleFileEx(fopen(config_file.c_str(), "r"), config_file.c_str(), 1))  {
		s2e()->getWarningsStream() << "[PythonInterface] Error running python script" << '\n';
		return;
	}
}

} // namespace plugins
} // namespace s2e
