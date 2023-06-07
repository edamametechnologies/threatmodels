import json
from sys import platform
from metric import Metric


class Model(object):
    '''Perform tests over a threat model'''

    def __init__(self, logger, dir_path):
        # Detect platform
        if platform == "linux" or platform == "linux2":
            # linux
            self.source = "Linux"
        elif platform == "darwin":
            # OS X
            self.source = "MacOS"
        elif platform == "win32":
            # Windows...
            self.source = "Windows"

        # Opening the json model of the platform
        with open(f'{dir_path}/threatmodel-{self.source}.json', 'r') as file:
            self.model = json.load(file)

        self.metrics: list[Metric] = []

        # Instanciating metrics
        for metric_info in self.model['metrics']:
            self.metrics.append(Metric(metric_info, self.source, logger))

        # Errors count
        self.errors = 0
        self.invalid_remediations = 0

        self.logger = logger

    def run_metrics_sequentially(self):
        for metric in self.metrics:
            self.logger.info("\n")
            metric.run_all_tests()

    def get_results(self):
        '''Returns the results of the tests'''
        return {"errors": self.errors,
                "invalid_remediations": self.invalid_remediations}
