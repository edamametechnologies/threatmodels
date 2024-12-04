import json
import yaml
from sys import platform
from metric import Metric, TargetIsNotACLI


class Model(object):
    '''Perform tests over a threat model'''

    def __init__(self, logger, dir_path, ignore_tests_path):
        self.logger = logger
        # Detect platform
        self.source = self.detect_platform()
        # Load the model based on the detected platform
        self.model = self.load_model(dir_path)
        # Loading a list of the tests that should be ignored
        self.ignore_list = self.load_ignore_list(ignore_tests_path)
        # Instantiate metrics
        self.metrics = [Metric(metric_info, self.source, logger, self.ignore_list) for metric_info in self.model['metrics']]
        # Initialize an empty array for reports
        self.reports = []

    def detect_platform(self):
        if platform == "linux" or platform == "linux2":
            return "Linux"
        elif platform == "darwin":
            return "MacOS"
        elif platform == "win32":
            return "Windows"
        else:
            return "Unknown"

    def load_model(self, dir_path):
        with open(f'{dir_path}/threatmodel-{self.source}.json', 'r') as file:
            return json.load(file)

    def load_ignore_list(self, ignore_tests_path):
        with open(ignore_tests_path, 'r') as file:
            config = yaml.safe_load(file)
            return config.get('ignore', {}).get(self.source, [])

    def run_metrics_sequentially(self, implementation_only=False):
        '''
        Run all tests sequentially and returns the results.
        '''
        nb_metrics = len(self.metrics)
        nb_metrics_ok = 0

        for metric in self.metrics:
            try:
                if metric.run_all_tests(implementation_only):
                    nb_metrics_ok += 1
            except TargetIsNotACLI:
                nb_metrics_ok += 1

            self.reports.append(metric.get_report())

        return self.compute_results(nb_metrics, nb_metrics_ok)

    def compute_results(self, nb_metrics, nb_metrics_ok):
        '''Returns the results of the tests'''
        res = {"error_count": 0, "warning_count": 0, "ok_count": 0}

        for report in self.reports:
            for key in res.keys():
                res[key] += report[key]

        report_results = f"{self.source}: {res['error_count']} ❌"\
                         f" {res['warning_count']} ⚠️"\
                         f" {res['ok_count']} ✅"\
                         "| Good metrics: "\
                         f"{nb_metrics_ok}/{nb_metrics}"

        with open('report-results.txt', 'w', encoding='utf-8') as file:
            file.write(report_results)

        return res
