#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
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
import castleblack
import logging
import sys
import os
import logging

# Instantiate logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - [simple_dir_watch] PID: %(process)d - %(message)s')

# obj is the NightsWatch object. You can access class members that you set via **kwargs
def my_func(obj, file_path, file_buffer, extra_metadata):
  logging.debug('Custom action: File buffer size {}'.format(len(file_buffer)))
  logging.debug('Our object has member "foo" which has value {}'.format(obj.foo))
  logging.debug('Original time that this file was placed in queue: {}'.format(extra_metadata['orig_put_time']))
  
  # IMPORTANT! Remember to return True if the function
  # completed successfully so we know that we can do post_action
  return True

# We define something we want to do after successfully completing our normal action
# This allows you to define custom behavior other than remove_after_processing
# This action runs BEFORE remove_after_processing (so you still have access to the file at file_path)
# Keep this in mind if you do something to the file which may prevent it from being deleted
def post_action(obj, file_path):
  logging.debug('Post_action: File is at path {}'.format(file_path))

  # We don't need to return anything here

def main(directory):

  extra_values = {'foo': 1, 'bar': True, 'baz': 'Hello World'}

  # Initialize our worker
  # We can pass in extra_values which will be assigned to the object
  # and can be accessed from within the custom functions like obj.foo
  # in case we want to pass things into our threaded workers
  worker = castleblack.NightsWatch(my_func, post_action, **extra_values)

  # Use the following line instead if you want to remove files after processing
  # worker = castleblack.NightsWatch(my_func, remove_after_processing=True)

  # Start our worker
  worker.start()

  # Observe for file creations but not file moves
  # It's adequate to only have one observer but you may want more than one worker
  castleblack.observe(directory, process_existing_files=True, enable_created=True, enable_moved=False)

if __name__ == '__main__':
  if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
    print("Usage: python {} <directory>".format(sys.argv[0]))
    sys.exit(1)

  main(sys.argv[1])
