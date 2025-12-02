import json

import ansible

from ansible.plugins.callback import CallbackBase
from ansible.utils.display import Display

display = Display()

DOCUMENTATION = """
    name: json_results
    type: stdout
    short_description: Collect results into a JSON structure
    version_added: historical
    description:
        - This is the callback plugin that collects results into a JSON structure
"""


class CallbackModule(CallbackBase):

    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'stdout'
    CALLBACK_NAME = 'json_results'
    # List of task fields to be retried from the result.
    TASK_FIELDS = (
        'action',
        'become',
        'become_method',
        'become_user',
        'connection',
        'ignore_errors',
        'ignore_unreachable',
        'register',
        'retries',
        'timeout',
    )

    def __init__(self):
        super(CallbackModule, self).__init__()
        self._results = {}

    def _get_module_name(self, result):
        if ansible.__version__ >= '2.19.0':
            return result.task
        else:
            return result.task_name

    def _get_task_fields(self, result):
        task_fields = {}
        for field in self.TASK_FIELDS:
            if field in result._task_fields:
                task_fields[field] = result._task_fields[field]
        return task_fields

    def _log_res(self, hostname, module_name, res):
        if display.verbosity == 0:
            return
        elif display.verbosity == 1:
            log_func = display.v
            brief_res_str = json.dumps({'module_name': module_name, 'reachable': res['reachable'], 'failed': res['failed']})
            msg = f'[{hostname}] => {brief_res_str}'
        elif display.verbosity == 2:
            log_func = display.vv
            msg = f'[{hostname}] => {json.dumps(res)}'
        elif display.verbosity == 3:
            log_func = display.vvv
            msg = f'[{hostname}] => {json.dumps(res, indent=4)}'
        else:
            log_func = display.vvvv
            msg = f'[{hostname}] => {json.dumps(res, indent=4)}'

        log_func(msg)

    def v2_runner_on_ok(self, result):
        hostname = result._host.get_name()
        module_name = self._get_module_name(result)

        if hostname not in self._results:
            self._results[hostname] = []

        res = dict(hostname=hostname, reachable=True, failed=False)
        res.update(result._result)

        if 'invocation' in res and isinstance(res['invocation'], dict):
            res['invocation']['module_name'] = module_name
        res['_task_fields'] = self._get_task_fields(result)

        self._log_res(hostname, module_name, res)

        self._results[hostname].append(res)



    def v2_runner_on_failed(self, result, *args, **kwargs):
        hostname = result._host.get_name()
        module_name = self._get_module_name(result)

        if hostname not in self._results:
            self._results[hostname] = []

        res = dict(hostname=hostname, reachable=True, failed=True)
        res.update(result._result)

        if 'invocation' in res and isinstance(res['invocation'], dict):
            res['invocation']['module_name'] = module_name
        res['_task_fields'] = self._get_task_fields(result)

        self._log_res(hostname, module_name, res)

        self._results[hostname].append(res)


    def v2_runner_on_unreachable(self, result):
        hostname = result._host.get_name()
        module_name = self._get_module_name(result)

        if hostname not in self._results:
            self._results[hostname] = []

        res = dict(hostname=hostname, reachable=False, failed=True)
        res.update(result._result)

        if 'invocation' in res and isinstance(res['invocation'], dict):
            res['invocation']['module_name'] = module_name
        res['_task_fields'] = self._get_task_fields(result)

        self._log_res(hostname, module_name, res)

        self._results[hostname].append(res)

    @property
    def results(self):
        return self._results
