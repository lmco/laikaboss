# Castle Black

Castle Black is a custom file directory watcher which uses [watchdog](https://pypi.python.org/pypi/watchdog).

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.

### Prerequisites

This project uses [watchdog](https://pypi.python.org/pypi/watchdog) >= 0.8.3. Watchdog is installed along with this project.

### Installing

The easiest way to install Castle Black is via [pip](https://pip.pypa.io/en/stable/). Clone the repository and then install using pip:

```sh
$ pip install ./castleblack
```

If you already have Castle Black installed but you want to update it and the version number in `setup.py` has not changed but the code has changed:

```
$ pip install --upgrade ./castleblack
```

### Example Code

```python
import castleblack

def my_custom_function(obj, file_path, file_buffer, extra_metadata):
  print('{} has a file length of {} and was originally placed into the queue at millisecond time {}'.format(file_path, len(file_buffer), extra_metadata['orig_put_time']))

# Define a new worker. You can define as many workers as you'd like.
# First parameter is your custom worker function. 
# remove_after_processing is an optional parameter (default: False) to delete files afterwards.
worker = castleblack.NightsWatch(my_custom_function, remove_after_processing=True)

# Tell the worker to start working
worker.start()

# Tell castleblack which directory to observe
castleblack.observe('/my/custom/directory')
```

`obj` contains whatever parameters you passed in as `**kwargs` when instantiating the NightsWatch object.

`extra_metadata` contains any extra metadata that is also queued. From the time of this writing, this includes:

`orig_put_time` (int): Milliseconds since epoch of when this file was first put into the queue. Useful for if you need to perform certain actions based on time since the file was put into the queue.

Please also see the example scripts in the examples directory.


## Running the tests

Tests are still in development.

## Limitations

* Castle Black can currently only observe one directory at a time.
* You are able to have more than one worker (more threads) but if you assign different custom processing functions to each, please note that **worker order of executation is nondeterminate**.

## License

Apache 2 (as part of Laikaboss)
