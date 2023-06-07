import subprocess


class Metric(object):
    '''Representation of a metric with associated functions to perform tests'''

    def __init__(self, info, source, logger):
        self.info = info
        self.source = source
        self.logger = logger

        # None: not run yet, False: no remediation, True: need remediation
        self.need_remediation = None

        self.report = {
                "implementation": {},
                "remediation": {},
                "rollback": {}
        }

    @staticmethod
    def check_error_standard(result):
        '''
        Return a boolean indicating if the provided result was an error.
        In this project we consider a command result as an error when the
        returncode is not 0 and the stderr is not empty.

        Parameter:
            result: subprocess result
        Return:
            the error status of the result
        '''
        return result.returncode != 0 and result.stderr != ""

    def metric_log(self, log_type, target_type, message, result=None):
        if log_type == "error":
            self.logger.error(f"[{target_type}] {message}")

            if result is not None:
                self.logger.error(result)

    def is_target_cli(self, target_type):
        '''Check if the given target type has a cli target'''
        if self.info[target_type]['class'] != 'cli':
            self.logger.info(f"target {target_type} is not a CLI")
            return False
        else:
            return True

    def implementation(self):
        '''
        Execute the implementation and returns a boolean indicating if it needs
        remediation. Return None if an error occured.
        '''
        target_type = "implementation"
        if not self.is_target_cli(target_type):
            return None

        # Execute the target
        result = self.exec(target_type)

        # stdout with data means that a remediation is needed
        self.need_remediation = result.stdout != ""

        if self.check_error_standard(result):
            self.metric_log(
                    "error", target_type, "target returned an error", result)
            return None

        self.report[target_type]["result"] = result

        return self.need_remediation

    def remediation(self, force=False):
        '''
        Execute the remediation and return a boolen indicating if the
        implementation has been fixed. Return None if an error occured.
        '''
        target_type = "remediation"
        if not self.is_target_cli(target_type):
            return None

        if self.need_remediation or force:
            # Execute the target
            result = self.exec(target_type)

            need_remediation = self.implementation()

            if self.check_error_standard(result):
                self.metric_log("error", target_type,
                                "target returned an error", result)
                return None
            elif need_remediation is None:
                return False
            else:
                return not need_remediation

    def rollback(self):
        '''
        Execute the rollback
        '''
        target_type = "rollback"
        if not self.is_target_cli(target_type):
            return None

        for i in range(0, 10):
            result = self.exec(target_type)

            if self.check_error_standard(result):
                self.metric_log("error", target_type,
                                "target returned an error", result)
                return None

            if not self.implementation():
                self.metric_log("error", target_type,
                                "rollback did not revert the change", result)
                return None
                # Not normal!!!
                break

            self.remediation()

    def check_elevations(self, target_type):
        '''
        Checks if the elevations of each targets are not to high or too low.
        Must run targets functions before
        '''
        if "need-perms" in self.report[target_type].keys():
            need_perms = self.report[target_type]["need-perms"]

            if need_perms is not None:
                if need_perms:
                    if self.info[target_type]["elevation"] == "user":
                        # TODO: Optionally modify the permissions automatically

                        self.metric_log("error", target_type,
                                        "target permissions too low")
                else:
                    if self.info[target_type]["elevation"] != "user":
                        # TODO: Optionally modify the permissions automatically

                        self.metric_log("error", target_type,
                                        "target permissions too high")

    def exec(self, target_type):
        '''
        Execute a target on the corresponding platform and returns the result

        Parameters:
            target_type: implementation / remediation / rollback
        Returns:
            subprocess result
        '''
        # Gets the corresponding target command
        command = self.info[target_type]["target"]

        if self.source == "Windows":
            command = f"powershell.exe -Command {command}"

        result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # If there is an error, try to run as root
        if self.check_error_standard(result):
            result = self.exec_as_root(target_type, command)
        else:
            self.report[target_type]["need-perms"] = False
            self.report[target_type]["causes-error"] = False
            self.report[target_type]["result"] = result

        if "need-perms" not in self.report[target_type].keys():
            self.check_elevations(target_type)

        return result

    def exec_as_root(self, target_type, command):
        '''
        Execute a target on the corresponding platform as root and returns the
        result.

        Parameters:
            target_type: implementation / remediation / rollback
            command: the command that couldn't be run without root privileges
        Returns:
            subprocess result
        '''
        if self.source == "Windows":
            command = f"elevate -w {command}"
        else:
            command = f"sudo -- sh -c '{command}'"

        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        if self.check_error_standard(result):
            # Error probably not related to permissions
            self.report[target_type]["need-perms"] = None
            self.report[target_type]["causes-error"] = True
        else:
            # Target need permissions
            self.report[target_type]["need-perms"] = True
            self.report[target_type]["causes-error"] = False

        self.report[target_type]["result"] = result

        return result

    def run_all_tests(self):
        self.logger.info(f"Running `{self.info['name']} tests`")
        self.implementation()
        self.remediation()
        self.rollback()
