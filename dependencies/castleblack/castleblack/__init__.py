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

from future import standard_library
standard_library.install_aliases()
from builtins import next
from builtins import object
import os
import time
import logging
import shutil
import re
from multiprocessing import Process, Queue, JoinableQueue
import queue as RQueue
from collections import OrderedDict
import random

# Third-party library imports
from watchdog.observers import Observer 
from watchdog.events import PatternMatchingEventHandler, FileMovedEvent

_max_items_processed=100000

# Thread-safe queues with files that need to be processed
job_queues = OrderedDict()

# this queue must always exist
job_queues['default'] = JoinableQueue()

# Inherit log configuration
logging = logging.getLogger(__name__)

def resolve_queue_name_by_dir(event_path, queue='default', queues=None, **kwargs):
   parent = os.path.basename(os.path.abspath(os.path.join(event_path, os.pardir))).lower()
   if queues and parent and parent in queues:
      return parent
   return queue

def resolve_queue_name_default(event_path, queue='default', queues=None, **kwargs):
    return queue

class queue_selector_default(object):

    def __init__(self, queue_set, **kwargs):

        queue_set = list(set(queue_set))
        self.randomize = True
        self.queues = list(set(queue_set))
        if kwargs:
            weighted_queues = kwargs.get('weighted_queues', None)
            randomize = kwargs.get('randomize', True)
            if weighted_queues:
               weighted_queues.extend([f for f in queue_set if f not in weighted_queues])
               self.queues = weighted_queues

        # don't bother if the weights aren't really being used
        if len(queue_set) >= len(self.queues):
           self.randomize = False

    def cycle_length(self):
        return len(self.queues)

    def generator(self):
        while True:
           if self.randomize:
               random.shuffle(self.queues)
           for queue in self.queues:
               yield queue

def init(queues=None, **kwargs):
    if queues:
        for queue in queues:
           if not queue in job_queues:
              job_queues[queue] = JoinableQueue()

# Watchdog handler to observe for file changes in designated directory
class NewFileHandler(PatternMatchingEventHandler):

  def __init__(self, extension=None, enable_created=False, enable_moved=False, include_filter=None, exclude_filter=None, queue_selector=None, queue_selector_args=None, resolve_queue=None, resolve_queue_args=None):
    super(NewFileHandler, self).__init__()
    self.extension = extension

    self.enable_created = enable_created
    self.enable_moved = enable_moved
    self.include_filter = include_filter
    self.exclude_filter = exclude_filter
    self.queue_selector = queue_selector

    if queue_selector_args is None:
        queue_selector_args = {}

    self.queue_selector_args = queue_selector_args

    if resolve_queue_args is None:
        resolve_queue_args = {}

    self.resolve_queue = resolve_queue

    if resolve_queue_args is None:
        resolve_queue_args = {}

    self.resolve_queue_args = resolve_queue_args

  def process(self, event):

    if isinstance(event, FileMovedEvent):
      event_path = event.dest_path
    else:
      event_path = event.src_path

    logging.debug("Event Path ({}), Event Type ({})".format(event_path, event.event_type))

    # Only add to job queue if this is a file (not a directory)
    queue_name = 'default'
    if os.path.isfile(event_path):
      if filter_filename(event_path, include_filter=self.include_filter, exclude_filter=self.exclude_filter, extension=self.extension):
        queue_name = self.resolve_queue(event_path, queue=queue_name, queues=list(job_queues.keys()), **self.resolve_queue_args)
        logging.info("Event Path ({}), Event Type ({}) put in requesting queue ({}))".format(event_path, event.event_type, queue_name))
        queue = job_queues.get(queue_name)
        size = queue.qsize()
        queue.put((event_path, 0, int(round(time.time() * 1000))))
        logging.info("Event Path ({}), Event Type ({}) used queue ({}) size ({}))".format(event_path, event.event_type, queue_name, size))

  # Watch for when new files are created
  def on_created(self, event):
    if self.enable_created:
      self.process(event)

  def on_moved(self, event):
    if self.enable_moved:
      self.process(event)

      
def filter_filename(filename, include_filter=None, exclude_filter=None, extension=None):
  '''filter filenames using provided regexes. 
  If include_filter is set, returns filename only if filename matches
  If exclude_filter is set, only returns filesname if they don't match
  If neither is set, return all filenames
  '''
  ret_value = filename
  if include_filter:
    ret_value = None
    if re.search(include_filter, filename):
      ret_value = filename
  if exclude_filter:
    if re.search(exclude_filter, filename):
      ret_value = None

  if ret_value and extension and not filename.endswith(extension):
     ret_value = None

  return ret_value
      
# Observe files in the input directory
def observe(input_dir, process_existing_files=False, extension=None, enable_created=False, enable_moved=False, include_filter=None, exclude_filter=None, recursive=True, queue_selector=None, queue_selector_args=None,resolve_queue=resolve_queue_name_default, resolve_queue_args=None):
  observer = Observer()

  if resolve_queue_args is None:
     resolve_queue_args = {}

  if queue_selector_args is None:
     queue_selector_args = {}

  # Format input directory as absolute path for easier handling of files
  if not input_dir.startswith('/'):
    input_dir = os.path.abspath(input_dir)

  logging.info('Observing directory: {}'.format(input_dir))

  if process_existing_files:
    # Add files already in directory to queue
    existing_files = []
    for (dirpath, dirnames, filenames) in os.walk(input_dir):
      existing_files.extend([(x, os.path.getmtime(x)) for x in [os.path.abspath(os.path.join(dirpath, f)) for f in filenames]])

    existing_files = sorted(existing_files, key=lambda x: x[1])

    queue_name = 'default'

    for file in existing_files:
      if filter_filename(file[0], include_filter=include_filter, exclude_filter=exclude_filter, extension=extension):
        queue_name = resolve_queue(file[0], queue=queue_name, queues=list(job_queues.keys()), **resolve_queue_args)
        queue = job_queues.get(queue_name)
        try:
          queue.put((file[0], 0, int(round(time.time() * 1000))))
        except Exception as e:
          # File does not exist since doing an os.walk, pass
          pass

  # Tell observer which handler to file whenever file system changes are seen
  observer.schedule(NewFileHandler(extension, enable_created=enable_created, enable_moved=enable_moved, include_filter=include_filter, exclude_filter=exclude_filter, queue_selector=queue_selector, queue_selector_args=queue_selector_args,resolve_queue=resolve_queue, resolve_queue_args=resolve_queue_args), path=input_dir, recursive=recursive)

  # Start observer
  try:
    observer.start()
  except Exception as e:
    logging.exception('Unable to start observer on dir ({}) : ({})'.format(input_dir, e))

  # Continually watch file until a KeyboardInterrupt
  try:
    while True:
      time.sleep(1)
  except KeyboardInterrupt:
    logging.debug("Observer caught KeyboardInterrupt. Exiting.")
    observer.stop()

  observer.join()

# NightsWatch Class
# Main worker logic to perform actions on files added to queue by observer
class NightsWatch(Process):

  def __init__(self, custom_action, post_action, queue_ready=None, error_threshold=0, error_dir='/tmp', error_wait=0, min_size=1, queue_selector=None, queue_selector_args=None, **kwargs):
    super(NightsWatch, self).__init__()
    self.custom_action = custom_action
    self.post_action = post_action
    self.error_threshold = error_threshold
    self.error_dir = os.path.abspath(error_dir)
    self.error_wait = error_wait #time to wait in s following error (throttles error retries)
    self.min_size = min_size # minimum size of file to be considered complete
    self.items_processed = 0

    self.queue_ready = queue_ready

    if not queue_ready:
       self.queue_ready = lambda a, b: True

    if queue_selector_args is None:
       queue_selector_args = {}

    if not queue_selector:
       queue_selector = queue_selector_default

    self.queue_selector = queue_selector(list(job_queues.keys()), **queue_selector_args)
    self.get_next_queue = self.queue_selector.generator()

    if not os.path.isdir(self.error_dir):
      logging.error('Directory %s does not exist or is not a directory -- not setting error threshold for moving files' % (self.error_dir))
      error_threshold = 0

    for key in kwargs:
      setattr(self, key, kwargs[key])

    if getattr(self, 'remove_after_processing', None) is None:
      setattr(self, 'remove_after_processing', False)

  def remove_file(self, file_path):
    if os.path.exists(file_path):
      try:
        os.remove(file_path)
        logging.debug("Removed processed file ({})".format(file_path))
      except Exception as e:
        logging.exception(e)

  def get_file_buffer(self, file_path):
    file_buffer = ''
    try:
      with open(file_path, 'rb') as f:
        file_buffer = f.read()
    except Exception as e:
      logging.debug("Error opening and reading file ({})".format(file_path))

    return file_buffer

  def run(self):

    cycle_length = self.queue_selector.cycle_length()

    noOpCount = 0

    item_ready = False
    num_errors = -1

    while True:
      num_errors = -1
      queue = None
      res = False
      item_ready = False
      try:

        queue_name = next(self.get_next_queue)

        queue = job_queues.get(queue_name)

        size = queue.qsize()

        if size > 0:
            try:
               if self.queue_ready(self, queue_name):

                  logging.info("Worker: retrieved queue name to try ({}) worker processed ({}) items.".format(queue_name, self.items_processed))
                  
                  try:
                     logging.info("Worker: trying to get from queue ({}) size ({}).".format(queue_name, size))
                     file_path, num_errors, orig_put_time = queue.get(False)
                     logging.info("Worker: found an item on queue ({}) with filepath ({}).".format(queue_name, file_path))
                     noOpCount = 0
                     item_ready = True
                  except RQueue.Empty:
                     pass
            except Exception as e:
              logging.exception("error waiting on queue sleeping for {} seconds".format(self.error_wait))
              time.sleep(self.error_wait)

      except KeyboardInterrupt:
        logging.debug("Caught KeyboardInterrupt. Exiting.")
        break

       # don't overwelm the processor if there is no input to process
      if not item_ready:
         noOpCount+=1
         if cycle_length == noOpCount:
            noOpCount = 0
            #logging.info("Worker: sleeping because all queues were not ready or empty {}".format(queue_name))
            time.sleep(.1)
         continue

      logging.info("Worker: Processing file ({}) with time {} and queue:{} and error count:{}.".format(file_path, orig_put_time, queue_name, num_errors))

      extra_metadata = {'orig_put_time': orig_put_time}

      file_buffer = self.get_file_buffer(file_path)

      if len(file_buffer) >= self.min_size:
        try:
          res = self.custom_action(self, file_path, file_buffer, extra_metadata, queue_name=queue_name)
          self.items_processed+=1
          if self.items_processed >= _max_items_processed:
             logging.info("Worker: Processed max items {} restarting count".format(self.items_processed))
             self.items_processed = 0

        except Exception as e:
          logging.exception(e)
          time.sleep(self.error_wait)
          
      else:
        logging.debug("Picked up file below min size or invalid file ({}) queue:{}".format(file_path, queue_name))
        time.sleep(self.error_wait)

      # Successfully completed custom_action, perform post processing
      if res:
        if self.post_action:
          try:
            self.post_action(self, file_path)
          except Exception as e:
            logging.exception(e)
            time.sleep(self.error_wait)

        # Optionally delete file
        if self.remove_after_processing:
          self.remove_file(file_path)

        logging.debug("Removing ({}) from file queue memory queue:{}".format(file_path, queue_name))

        # Remove this item from our queue
        queue.task_done()

      # Requeue if custom_action returned False or failed
      else:
        # We have to call task_done() for every get() before we can requeue
        queue.task_done()

        # If we have a threshold of number of errors we allow before moving the file
        # into an error directory
        if self.error_threshold > 0 and (num_errors + 1) >= self.error_threshold:
          # File has reached or exceeded error threshold, move to error directory
          try:
            logging.info("File processing on %s has reached error threshold. Moving to %s queue:%s." % (file_path, self.error_dir, queue_name))
            shutil.move(file_path, self.error_dir)
          except Exception as e:
            logging.error("Error moving file %s to error directory %s from queue:%s" % (file_path, self.error_dir, queue_name))
            logging.exception(e)
            # TODO: Do we put the file back into the job_queue here or no?

        else:
          # Place file back into queue since errors has not reached threshold yet
          queue.put((file_path, num_errors + 1, orig_put_time))
