import subprocess
from colorama import Fore, init
from custom_exceptions import (
        ImplementationTargetError, RemediationTargetError,
        RemediationFixInvalid
)

# Initialize colorama
init(autoreset=True)


class Metric(object):
    '''Representation of a metric with associated functions to perform tests'''

    def __init__(self, info, source):
        self.info = info
        self.source = source

        # None: not run yet, False: no remediation, True: need remediation
        self.need_remediation = None

    def implementation(self):
        '''
        Execute the implementation and returns a boolean indicating if it needs
        remediation
        '''
        # Execute the target
        result = self.exec(self.info["implementation"]["target"])

        # stdout with data means that a remediation is needed
        self.need_remediation = result.stdout != ""

        if result.returncode != 0:
            self.display_target(Fore.RED, "implementation", "ER")
            self.print_result(result)
            raise ImplementationTargetError

        elif self.need_remediation:
            self.display_target(Fore.YELLOW, "implementation", "NR")
            self.print_result(result)
        else:
            self.display_target(
                    Fore.GREEN, "implementation", "OK", show_target=False)

        return self.need_remediation

    def remediation(self, force=False):
        '''
        Execute the remediation and verify if the implementation has been fixed
        '''
        if self.need_remediation or force:
            # Execute the target
            result = self.exec(self.info["remediation"]["target"])

            if result.returncode != 0:
                self.display_target(Fore.RED, "remediation", "ER")
                self.print_result(result)
                raise RemediationTargetError

            # Verify implementation
            elif self.implementation():
                self.display_target(Fore.RED, "remediation", "IR")
                self.print_result(result)
                raise RemediationFixInvalid

    def rollback(self):
        '''
        Execute the rollback
        '''
        self.exec(self.info["rollback"]["target"])

    def exec(self, target):
        '''
        Execute a target on the corresponding platform and returns the result
        '''
        if self.source == "Windows":
            result = subprocess.run(
                    ["powershell.exe", "-Command", target],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        elif self.source == "Linux" or self.source == "MacOS":
            result = subprocess.run(
                    target,
                    shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        return result

    def display_target(self, color, target_type,
                       result_code, show_target=True):
        '''
        Display log informations for a specific target

        Parameters:
            color: colorama Fore color
            target_type: implementation, remediation, rollback
            result_code: OK (OK), ER (ERROR), IR (Invalid Remediation),
                         NR (Need remediation)
            show_target: show the target command
        '''
        print(f"{color}[{result_code}][{target_type}] {self.info['name']}")
        if show_target:
            print(f"Target: {self.info[target_type]['target']}")

    @staticmethod
    def print_result(result):
        print(f"Return code: {result.returncode}")
        print(f"{Fore.GREEN}Stdout:\n{result.stdout}")
        print(f"{Fore.RED}Stderr:\n{result.stderr}")
