import subprocess


class Metric(object):
    '''Representation of a metric with associated functions to perform tests'''

    def __init__(self, info, source, logger):
        self.info = info
        self.source = source
        self.logger = logger

        self.report = {
                "implementation": {"elevation_checked": False},
                "remediation": {"elevation_checked": False},
                "rollback": {"elevation_checked": False},
                "error_count": 0,
                "warning_count": 0,
                "ok_count": 0
        }

    def get_report(self):
        return self.report

    def metric_log(self, log_type, target_type, message,
                   enable_log=True, result=None):
        if not enable_log:
            return

        log = f"{target_type} {message}"

        if log_type == "error":
            self.logger.error(log)
            self.report["error_count"] += 1
        elif log_type == "warning":
            self.logger.warning(log)
            self.report["warning_count"] += 1
        elif log_type == "info":
            self.logger.info(log)
        elif log_type == "ok":
            self.report["ok_count"] += 1
            self.logger.ok(log)

        if result is not None:
            self.logger.error(result)

    def is_target_cli(self, target_type, enable_log=True):
        '''Check if the given target type has a cli target'''
        if self.info[target_type]['class'] != 'cli':
            self.metric_log("warning", target_type,
                            "target  is not a CLI or not implemented yet",
                            enable_log=enable_log)

            raise TargetIsNotACLIException

    def implementation(self, enable_log=True):
        '''
        Execute the implementation and returns a boolean indicating if it needs
        remediation. Return None if an error occured.
        '''
        target_type = "implementation"

        # Check if cli else raises exception
        self.is_target_cli(target_type, enable_log=enable_log)

        # Execute the target
        result = self.exec(target_type)

        # stdout with data means that a remediation is needed
        need_remediation = result.stdout != ""

        if is_error(result):
            self.metric_log("error", target_type, "target returned an error",
                            result=result, enable_log=enable_log)
            return None
        else:
            self.metric_log("ok", target_type,
                            "target passed tests. "
                            f"Need remediation: {need_remediation}",
                            enable_log=enable_log)

            return need_remediation

    def remediation(self, enable_log=True):
        '''
        Execute the remediation and return a boolen indicating if the
        implementation has been fixed. Return None if an error occured.
        '''
        target_type = "remediation"

        # Check if cli else raises exception
        self.is_target_cli(target_type, enable_log=enable_log)

        # Execute the target
        result = self.exec(target_type)

        need_remediation = self.implementation(enable_log=False)

        if is_error(result):
            self.metric_log("error", target_type,
                            "target returned an error",
                            result=result, enable_log=enable_log)
            return None
        elif need_remediation is None:
            self.metric_log("warning", target_type,
                            "target result could not be verified as the "
                            "implementation returned an error",
                            enable_log=enable_log)
            return False
        elif need_remediation:
            self.metric_log("error", target_type,
                            "target ran flawlessly but did not "
                            "resolve the metric",
                            enable_log=enable_log)
            return False
        else:
            self.metric_log("ok", target_type,
                            "target successfuly resolved the metric",
                            enable_log=enable_log)
            return True

    def rollback(self, enable_log=True):
        '''
        Execute the rollback
        '''
        target_type = "rollback"
        self.is_target_cli(target_type, enable_log=enable_log)

        n_attempts = 3

        for i in range(0, n_attempts):
            result = self.exec(target_type)

            if is_error(result):
                self.metric_log("error", target_type,
                                "target returned an error",
                                result=result, enable_log=enable_log)
                return None

            implementation_fixed = self.implementation(enable_log=False)

            if implementation_fixed is None:
                # The implementation itself is not working
                self.metric_log(
                    "warning", target_type,
                    "target cannot be tested as the implementation returned "
                    "an error",
                    enable_log=enable_log)
                return None

            elif not implementation_fixed:
                # Rollback executed well but did not fixed the implementation
                self.metric_log("error", target_type,
                                f"attempt {i} did not revert the "
                                "change",
                                result=result, enable_log=enable_log)
                return None
            else:
                self.metric_log("ok", target_type,
                                f"attempt {i} successfuly reverted changes",
                                enable_log=enable_log)

            if not self.remediation(enable_log=False):
                self.metric_log("warning", "remediation",
                                "target is not working properly, cannot test "
                                "the rollback", enable_log=enable_log)
                return None

        self.metric_log("ok", target_type,
                        f"successfuly reverted the changes over {n_attempts}",
                        enable_log=enable_log)

        return True

    def check_elevations(self, target_type):
        '''
        Checks if the elevations of each targets are not to high or too low.
        Must run targets functions before
        '''
        if "need-perms" in self.report[target_type].keys():
            need_perms = self.report[target_type]["need-perms"]

            self.report[target_type]["elevation_checked"] = True

            if need_perms is None:
                return

            if need_perms:
                if self.info[target_type]["elevation"] == "user":
                    # TODO: Optionally modify the permissions automatically

                    self.metric_log("warning", target_type,
                                    "target permissions too low")
            else:
                if self.info[target_type]["elevation"] != "user":
                    # TODO: Optionally modify the permissions automatically

                    self.metric_log("warning", target_type,
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
        if is_error(result):
            result = self.exec_as_root(target_type, command)
        else:
            self.report[target_type]["need-perms"] = False
            self.report[target_type]["causes-error"] = False
            self.report[target_type]["result"] = result

        if not self.report[target_type]["elevation_checked"]:
            self.check_elevations(target_type)

        return result

    def exec_as_root(self, target_type, command):
        '''
        Execute a target on the corresponding platform as root and returns the
        result.

        Parameters:
            target_type: implementation / remediation / rollback
            command: the command that could not be run without root privileges
        Returns:
            subprocess result
        '''
        if self.source == "Windows":
            command = f"runas /noprofile /user:Administrator {command}"
        else:
            command = f"sudo -- sh -c '{command}'"

        result = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        if is_error(result):
            # Error probably not related to permissions
            self.report[target_type]["need-perms"] = None
            self.report[target_type]["causes-error"] = True
        else:
            # Target need permissions
            self.report[target_type]["need-perms"] = True
            self.report[target_type]["causes-error"] = False

        self.report[target_type]["result"] = result

        return result

    def try_execute(self, function_name):
        '''try executing a function, ignoring certain exceptions'''
        function = self.__getattribute__(function_name)
        try:
            return function()
        except TargetIsNotACLIException:
            pass

    def run_all_tests(self):
        '''Run all the tests for this metric and returns the report'''
        self.logger.info(f"Running `{self.info['name']}` tests")
        try:
            need_remediation = self.implementation()
        except TargetIsNotACLIException:
            self.metric_log("error", "metric",
                            "cancelling tests as implementation is not a "
                            "CLI")
            return None

        if need_remediation:
            # If remediation needed, remediation first
            self.try_execute("remediation")

            # Execute rollback even if remediation is not a CLI
            self.try_execute("rollback")
        else:
            # If remediation not needed, rollback first
            self.try_execute("rollback")

            # Execute remediation even if rollback is not a CLI
            self.try_execute("remediation")

        return self.get_report()


class TargetIsNotACLIException(Exception):
    '''Raised when a target is not a CLI'''
    pass


def is_error(result):
    '''
    Return a boolean indicating if the provided result was an error.
    In this project we consider a command result as an error when the
    returncode is different than 0 and the stderr is not empty.

    Parameter:
        result: subprocess result
    Return:
        the error status of the result
    '''
    return result.returncode != 0 and result.stderr != ""
