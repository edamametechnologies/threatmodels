import subprocess

# Command timeout in seconds
CMD_TIMEOUT = 10


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

    def log(self, log_type, target_type, message, result=None):
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

    def is_target_cli(self, target_type):
        '''Check if the given target type has a cli target'''
        if self.info[target_type]['class'] != 'cli':
            self.log("warning", target_type, "target  is not a CLI or not "
                     "implemented yet")

            raise TargetIsNotACLIException

    def implementation_tests(self):
        '''
        Execute the implementation and returns a boolean indicating if it needs
        remediation.
        '''
        target_type = "implementation"

        # Check if cli else raises exception
        self.is_target_cli(target_type)

        # Execute the elevation test and get the result
        result = self.elevation_test(target_type)

        # stdout with data means that a remediation is needed
        need_remediation = result.stdout != ""

        self.log("ok", target_type, "target passed tests. "
                 f"Need remediation: {need_remediation}")

        return need_remediation

    def remediation_tests(self, enable_log=True):
        '''
        Execute the remediation and return a boolean indicating if it fixed
        the implementation.
        '''
        target_type = "remediation"

        # Check if cli else raises exception
        self.is_target_cli(target_type)

        # Execute the elevation test and get the result
        self.elevation_test(target_type)

        need_remediation = self.execute_target("implementation").stdout != ""

        if need_remediation:
            self.log("error", target_type, "target ran flawlessly but did not "
                     "resolve the metric")
        else:
            self.log("ok", target_type, "target successfuly resolved the "
                     "metric")

        return not need_remediation

    def rollback_test(self):
        '''
        Execute the rollback and return a boolean indicating if the changes
        made by the remediation have been rolled back.
        '''
        target_type = "rollback"

        # Check if cli else raises exception
        self.is_target_cli(target_type)

        # Execute the elevation test and get the result
        self.elevation_test(target_type)

        need_remediation = self.execute_target("implementation").stdout != ""

        if not need_remediation:
            self.log("error", target_type, "dit not revert the changes")
        else:
            self.log("ok", target_type, "successfuly reverted the changes")

        return need_remediation

    def execute_target(self, target_type, permissions=None):
        '''
        Execute a target on the corresponding platform and returns the result
        Raises subprocess.TimeoutExpired and TargetExecutionException

        Parameters:
            target_type: implementation / remediation / rollback
            permissions: set to True to run the target with permissions
        Returns:
            subprocess result or None if timeout
        '''
        # Try to load target permissions if permissions argument is not
        # specified
        if permissions is None\
                and "need_permissions" in self.report[target_type]:
            permissions = self.report[target_type]["need_permissions"]

        # Gets the corresponding target command
        command = self.info[target_type]["target"]

        # Add powershell call on windows
        if self.source == "Windows":
            command = f"powershell.exe -Command {command}"

        # Add sudo or runas when permissions argument is True
        if permissions:
            if self.source == "Windows":
                command = f"runas /noprofile /user:Administrator {command}"
            else:
                command = f"sudo -- sh -c '{command}'"

        # Run the command
        result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=CMD_TIMEOUT
        )

        # Raise an exception if the execution failed
        if is_error(result):
            #self.log("error", target_type, "returned an error", result=result)
            raise TargetExecutionException

        return result

    def elevation_test(self, target_type):
        '''
        Perform an elevation test on a specific target.
        Returns the result of the command if it did not fail.
        Raise exceptions

        Parameters:
            target_type: implementation / remediation / rollback
        Returns:
            the result of the target execution
        '''
        try:
            result = self.execute_target(target_type, permissions=False)
            need_permissions = False
        except subprocess.TimeoutExpired or TargetExecutionException as e:
            self.log("error", target_type, "Execution failed during "
                     f"elevation test: {e}")
            self.log("info", target_type, "retrying with permissions")

            # This call will be able to raise exceptions
            result = self.execute_target(target_type, permissions=True)
            need_permissions = True

        if need_permissions:
            # If execution required permissions and the elevation is set to
            # user, the elevation is too low
            if self.info[target_type]["elevation"] == "user":
                self.log("warning", target_type, "target elevation too low")
            else:
                self.log("ok", target_type, "elevation is at a correct level")
        else:
            # If execution did not require permissions and the elevation is set
            # to something else than user, the elevation is too high
            if self.info[target_type]["elevation"] != "user":
                self.log("warning", target_type, "target elevation too high")
            else:
                self.log("ok", target_type, "elevation is at a correct level")

        self.report[target_type]["need_permissions"] = need_permissions

        return result

    def degradation_tests(self):
        for i in range(3):
            self.execute_target("rollback")

            # If no need remediation
            if not self.execute_target("implementation").stdout != "":
                self.log("error", "rollback", f"dit not revert the "
                         f"changes at the attempt {i}")
                raise DegradationTestException
            else:
                self.log("ok", "rollback", "reverted the changes "
                         f"successfuly at the attempt {i}")

            self.execute_target("remediation")

            # If need remediation
            if self.execute_target("implementation").stdout != "":
                self.log("error", "remediation", f"dit not resolve the "
                         f"implementation at attempt {i}")
                raise DegradationTestException
            else:
                self.log("ok", "remediation", "resolved the "
                         f"implementation successfuly at the attempt {i}")

    def run_all_tests(self):
        '''Run all the tests for this metric'''
        self.logger.info(f"Running `{self.info['name']}` tests")

        need_remediation = self.implementation_tests()

        if need_remediation:
            self.remediation_tests()
            self.rollback_test()
        else:
            self.rollback_test()
            self.remediation_tests()

        self.degradation_tests()


class TargetIsNotACLIException(Exception):
    '''Raised when a target is not a CLI'''
    pass


class TargetExecutionException(Exception):
    '''Raised when a target execution fails'''
    pass


class DegradationTestException(Exception):
    '''Raised when a degradation test fails'''
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
