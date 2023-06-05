import json
from sys import platform
from metric import Metric
from custom_exceptions import (
        ImplementationTargetError, RemediationTargetError,
        RemediationFixInvalid
)


class Model(object):
    '''Perform tests over a threat model'''

    def __init__(self, dir_path):
        # Detect platform
        if platform == "linux" or platform == "linux2":
            # linux
            self.source = "Linux"
        elif platform == "darwin":
            # OS X
            self.source = "macOS"
        elif platform == "win32":
            # Windows...
            self.source = "Windows"

        # Opening the json model of the platform
        with open(f'{dir_path}/threatmodel-{self.source}.json', 'r') as file:
            self.model = json.load(file)

        self.metrics: list[Metric] = []

        # Instanciating metrics
        for metric_info in self.model['metrics']:
            self.metrics.append(Metric(metric_info, self.source))

        # Errors count
        self.errors = 0
        self.invalid_remediations = 0

    def run_implementations(self):
        '''Run implementation for each metric'''
        for metric in self.metrics:
            try:
                metric.implementation()
            except ImplementationTargetError:
                self.errors += 1

    def run_remediations(self, force=False):
        '''
        Run remediation for each metric

        paraameter:
            force: Force the execution of remediations even if the
                   corresponding implementations did not failed
        '''
        for metric in self.metrics:
            try:
                metric.remediation(force=force)
            except RemediationTargetError:
                self.errors += 1
            except RemediationFixInvalid:
                self.invalid_remediations += 1

    def run_rollbacks(self):
        '''Run rollback for each metric'''
        for metric in self.metrics:
            metric.rollback()

    def get_results(self):
        '''Returns the results of the tests'''
        return {"errors": self.errors,
                "invalid_remediations": self.invalid_remediations}
