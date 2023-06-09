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

        # Saving reports in an array
        self.reports = []

        self.logger = logger

    def run_metrics_sequentially(self):
        '''
        Run all tests sequentially and returns the results.
        '''
        for metric in self.metrics:
            report = metric.run_all_tests()
            self.reports.append(report)

        return self.get_results()

    def get_results(self):
        '''Returns the results of the tests'''
        res = {"error_count": 0, "warning_count": 0, "ok_count": 0}

        for report in self.reports:
            for key in res.keys():
                res[key] += report[key]

        with open('report-results.txt', 'w') as file:
            file.write(res)

        return res
