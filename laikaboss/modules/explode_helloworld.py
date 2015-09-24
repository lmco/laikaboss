# Copyright 2015 Lockheed Martin Corporation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# 

# Import the python libraries needed for your module
import logging
import hashlib

# Import classes and helpers from the Laika framework
from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

class EXPLODE_HELLOWORLD(SI_MODULE):
    ''' 
    A Hello World Laika module to use as a template and guide for your development. 

    Classes of Laika modules follow these rules:
      * Name MUST be in all capitals.
      * Name SHOULD use one of the predefined prefixes followed by an expressive name of what the module is or interacts with/on.
          * Prefixes: SCAN, META, EXPLODE, LOG, DECODE.
      * Class MUST inherit from SI_MODULE.
      * Saved in a file with name that is lowercase of the class name.
      * Define the _run(...) method, as seen below.
      * Should define an __init__(...) method that defines the self.module_name instance variable set to the class name, as seen below.
    '''

    def __init__(self):
        '''
        Typical class constructor. Should define instance variable self.module_name set to the class name, to be used for adding metadata and logging. Any other non-runtime specific initialization can happen here, such as making connections to external systems or compiling regular expressions for improved runtime performance.

        Note: no additional parameters (besides self) can be defined here, as the framework does not support parameterized initialization at module loading. Instead, use lazy-loading techniques during the first time _run(...) is called, using that methods 'args' parameter or the laikaboss.config for customization.
        '''
        self.module_name = "EXPLODE_HELLOWORLD"

    def _run(self, scanObject, result, depth, args):
        '''
        Here is where the actual magic happens. This method is called on the object being scanned given that the dispatcher has a matching rule triggering this module.

        There are four types of actions that modules do on scan objects:
          * Add flags.
          * Add metadata.
          * Explode children.
          * Interact with external systems.

        Any module can perform as many of these actions as necessary, and many do more than one, such as adding flags and metadata.

        The parameters provided to this method by the framework are:
          * scanObject: This is the object currently being scanned (duh) of type ScanObject. It contains all of the flags, metadata and other assigned fields regarding this spefic instance of the object. This parameter is used by modules to access the buffer, add flags and add metadata.
          * result: This is the umbrella object that contains all of the ScanObjects created during the root object's scan. It is primarily used by modules to access the parent object of the scanObject when needed.
          * depth: This is a leftover parameter from the tracking of the depth of recursion of objects. It is recommended to get this value from the scanObject itself.
          * args: This is a dictionary of the runtime arguments provided to the module by the dispatcher. This parameter provides customization of module runs from the dispatcher, so that the module can operate differently based on the type/context of the scanObject.

        This method MUST return a list of ModuleObjects. ModuleObjects represent the children exploded (or the less violent extracted) from the scanObject by this module. If the module does not explode any children (as most do not), simply return an empty list. Not returning a list causes the framework to log an error for this module each time it is run, but will not prevent it from running next time, nor will it remove any flags/metadata added by the module run.
        '''
        # This variable is recommended to be used by all modules as the returned list of ModuleObjects, populated as the children objects are found.
        moduleResult = [] 

        # A typical first step is define the configuration options of the module.
        # A best practice for configuration options to a module is to honor them in this precedence:
        #   3. value set as default in this code
        #   2. value specified in config file
        #   1. value specified in arguments of the invocation of this module (via the dispatcher)
        # To help with this, the get_option(...) method provided in the laikaboss.util module provides a single method call to set the option according to this precedence.
        helloworld_param = int(get_option(args, 'param', 'helloworldparam', 10))

        # To add flags to the object, use the addFlag method of the scanObject.
        # Flags should have the following three parts, separated by ':'s:
        #   * Shortened name of the module.
        #   * 'nfo' if the flag is informational, 'err' if the flag is for a policy/logic error (versus a programatic error), or leave blank if a typical flag.
        #   * Expressive name representing the atomic concept of the flag.
        scanObject.addFlag('e_helloworld:nfo:justsayinghello')

        # To add metadata to the object, use the addMetadata method of the scanObject.
        scanObject.addMetadata(self.module_name, "minsize", helloworld_param)

        # If you want to call a separate function, pass the data and let the 
        # function set flags on the data. The function will also modify the moduleResult variable
        # to add subobjects 
        flags = self._helloworld(scanObject.buffer, moduleResult, helloworld_param)

        for flag in flags:
            scanObject.addFlag(flag)

        # Whenever you need to do a try-except, you must make sure to catch and raise the framework ScanError exceptions.
        try:
            nonexistant_var.bad_method_call()
        except NameError:
            pass
        except ScanError:
            raise

        # Always return a list of ModuleObjects (or empty list if no children)
        return moduleResult

    def _close(self):
        '''
        Laika module destructor. This method is available for any actions that need to be done prior to the closing of the module, such as shutting down cleanly any client connections or closing files. It does not need to be defined for every module, such as this one, since there is nothing to do here. It is here to remind you that it is available.
        '''
        pass

    @staticmethod
    def _helloworld(buffer, moduleResult, helloworld_param):
        ''' 
        An example of a worker function you may include in your module.
        Note the @staticmethod "decorator" on the top of the function.
        These private methods are set to static to ensure immutability since
        they may be called more than once in the lifetime of the class
        '''
        flags = []

        # Using the logging module is a great way to create debugging output during testing without generating anything during production.
        # The Laika framework does not use the logging module for its logging (it uses syslog underneath several helpers found it laikaboss.util),
        # so none of thses messages will clutter up Laika logs.
        logging.debug('Hello world!')
        logging.debug('HELLOWORLD invoked with helloworld_param value %i', helloworld_param)

        if helloworld_param < 10: 
            flags.append('e_helloworld:nfo:helloworldsmall')
        else:
            logging.debug('HELLOWORLD(%i >= 10) setting flag', helloworld_param)
            flags.append('e_helloworld:nfo:helloworld')


        if helloworld_param > 20:
            logging.debug('HELLOWORLD(%i > 20) adding new object', helloworld_param)
            flags.append('e_helloworld:nfo:helloworldx2')
        
            if len(buffer) > helloworld_param:

                # Take the module buffer and trim the first helloworld_param size bytes.
                buff = buffer[helloworld_param:]

                object_name = 'e_helloworld_%s_%s' % (len(buff), hashlib.md5(buff).hexdigest())

                logging.debug('HELLOWORLD - New object: %s', object_name)
                
                # And we can create new objects that go back to the dispatcher and subsequent laika modules
                # Any modifications we make to the "moduleResult" variable here will go back to the main function 
    
                # laikaboss/objectmodel.py defines the variables you can set for externalVars. Two most common to set are
                #   contentType
                #   filename
                moduleResult.append(ModuleObject(buffer=buff, externalVars=ExternalVars(filename=object_name)))

            else:
                logging.debug('HELLOWORLD - object is too small to carve (%i < %i)', len(buffer), helloworld_param)

        return set(flags)

