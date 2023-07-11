import json
import os
import subprocess
from sys import platform
from metric import Metric, TargetIsNotACLI


class Model(object):
    '''Perform tests over a threat model'''

    def __init__(self, logger, dir_path):
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
            self.metrics.append(Metric(metric_info, self.source, logger))

        # Saving reports in an array
        self.reports = []

        self.logger = logger

    def pre_run_script(self):
        script_path = f"./src/pre_run/{self.source}"

        if os.path.isfile(script_path):
            self.logger.info(f"Running pre-run script: {script_path}")

            if self.source == "Linux" or self.source == "macOS":
                subprocess.run(f"sudo {script_path}")
            elif self.source == "Windows":
                subprocess.run(script_path)

    def run_metrics_sequentially(self):
        '''
        Run all tests sequentially and returns the results.
        '''
        nb_metrics = len(self.metrics)
        nb_metrics_ok = 0

        for metric in self.metrics:
            try:
                if metric.run_all_tests():
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
