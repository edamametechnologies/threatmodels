import subprocess
import textwrap

# Command timeout in seconds
CMD_TIMEOUT = 120


class Metric(object):
    '''Representation of a metric with associated functions to perform tests'''

    def __init__(self, info, source, logger, ignore_list, username):
        self.info = info
        self.source = source
        self.logger = logger
        self.ignore_list = ignore_list
        self.username = username

        self.report = {
            "implementation": {},
            "remediation": {},
            "rollback": {},
            "error_count": 0,
            "warning_count": 0,
            "ok_count": 0
        }

    def get_report(self):
        return self.report

    def log(self, log_type, message, result=None):
        if log_type == "error":
            self.logger.error(message)
            self.report["error_count"] += 1
        elif log_type == "warning":
            self.logger.warning(message)
            self.report["warning_count"] += 1
        elif log_type == "info":
            self.logger.info(message)
        elif log_type == "ok":
            self.report["ok_count"] += 1
            self.logger.ok(message)

        if result is not None:
            self.logger.error(result)

    def is_target_cli(self, target_type):
        '''Check if the given target type has a cli target'''
        if self.info[target_type]['class'] != 'cli':
            self.log("warning", f"{target_type} target  is not a `cli` or not "
                                "implemented yet. "
                                f"Class: `{self.info[target_type]['class']}`")
            raise TargetIsNotACLI
        else:
            return True

    def fetch_need_remediation(self):
        result = self.execute_target("implementation")
        return (need_remediation_logic(result, self.source), result)

    def common_target_tests(self, target_type):
        # Check if cli
        if not self.is_target_cli(target_type):
            return False

        try:
            # Execute the target
            self.execute_target(target_type)
        except (subprocess.TimeoutExpired, TargetExecutionError) as e:
            self.log("error", f"{target_type}: {e}")
            return False

        return True

    def implementation_tests(self):
        '''
        Execute implementation tests and returns True if the tests passed
        '''
        target_type = "implementation"

        if not self.common_target_tests(target_type):
            return False

        # stdout with data means that a remediation is needed
        need_remediation, _ = self.fetch_need_remediation()

        self.log("ok", f"{target_type} target passed tests. "
                       f"Need remediation: {need_remediation}")

        return True

    def remediation_tests(self, enable_log=True):
        '''
        Execute the remediation and return a boolean indicating if it fixed
        the implementation.
        '''
        target_type = "remediation"

        if not self.common_target_tests(target_type):
            return False

        need_remediation, result = self.fetch_need_remediation()

        if need_remediation:
            self.log("error", f"{target_type} target ran flawlessly but did not "
                              "resolve the metric", result=result)
        else:
            self.log("ok", f"{target_type} target successfuly resolved the "
                           "metric")

        return not need_remediation

    def rollback_test(self):
        '''
        Execute the rollback and return a boolean indicating if the changes
        made by the remediation have been rolled back.
        '''
        target_type = "rollback"

        if not self.common_target_tests(target_type):
            return False

        need_remediation, result = self.fetch_need_remediation()

        if not need_remediation:
            self.log("error", f"{target_type} dit not revert the changes",
                     result=result)
        else:
            self.log("ok", f"{target_type} successfuly reverted the changes")

        return need_remediation

    def _target_elevation(self, target_type):
        return self.info[target_type].get("elevation", "").lower()

    def _needs_personate(self, target_type):
        return self._target_elevation(target_type) == "admin"

    def _default_permissions_required(self, target_type):
        elevation = self._target_elevation(target_type)
        return elevation != "user"

    def _escape_pwsh_single(self, value):
        return value.replace("'", "''")

    def _build_windows_env_block(self):
        if not self.username:
            return ""
        escaped_username = self._escape_pwsh_single(self.username)
        user_segment = self.username.split("\\")[-1].split("/")[-1]
        escaped_segment = self._escape_pwsh_single(user_segment)
        template = """
        $edamameUser = '{username}'
        $edamameUserFolder = '{segment}'
        $userProfilePath = Join-Path $env:SystemDrive ('Users\\' + $edamameUserFolder)
        if (-not (Test-Path $userProfilePath)) {{
          try {{
            $profileObj = Get-CimInstance Win32_UserProfile -ErrorAction Stop |
              Where-Object {{ $_.LocalPath -like "*\\{segment}" }} |
              Select-Object -First 1
            if ($profileObj -and (Test-Path $profileObj.LocalPath)) {{
              $userProfilePath = $profileObj.LocalPath
            }}
          }} catch {{ }}
        }}
        if (-not (Test-Path $userProfilePath)) {{
          $userProfilePath = Join-Path $env:SystemDrive ('Users\\' + $edamameUserFolder)
        }}
        $env:USERPROFILE = $userProfilePath
        try {{
          $env:HOMEDRIVE = Split-Path $userProfilePath -Qualifier
          $env:HOMEPATH = $userProfilePath.Substring($env:HOMEDRIVE.Length)
        }} catch {{
          $env:HOMEDRIVE = $env:SystemDrive
          $env:HOMEPATH = $userProfilePath.Substring($env:HOMEDRIVE.Length)
        }}
        $env:LOCALAPPDATA = Join-Path $userProfilePath 'AppData\\Local'
        $env:APPDATA = Join-Path $userProfilePath 'AppData\\Roaming'
        """
        return textwrap.dedent(template).format(
            username=escaped_username, segment=escaped_segment
        ).strip()

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
        if permissions is None:
            permissions = self._default_permissions_required(target_type)

        # Gets the corresponding target command
        command = self.info[target_type]["target"]

        needs_personate = self._needs_personate(target_type)

        if self.source == "Windows":
            script = command
            if needs_personate:
                env_block = self._build_windows_env_block()
                if not env_block:
                    raise TargetExecutionError("username required for admin elevation tests")
                script = f"{env_block}\n{script}"
            ps_args = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ]
            result = subprocess.run(
                ps_args,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=CMD_TIMEOUT,
            )
        else:
            # Unix: use sudo for admin and higher elevations
            # Admin mimics production: sudo -H -u <user> to impersonate with elevated rights
            if needs_personate:
                if not self.username:
                    raise TargetExecutionError("username required for admin elevation tests")
                command = f"sudo -H -u {self.username} /bin/bash -c '{command}'"
            elif permissions:
                command = f"sudo -- sh -c '{command}'"
            result = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=CMD_TIMEOUT,
            )

        # Raise an exception if the execution failed
        if is_error(result):
            raise TargetExecutionError(result)

        return result

    def elevation_test(self, target_type):
        '''
        Perform an elevation test on a specific target.
        Raise exceptions

        Parameters:
            target_type: implementation / remediation / rollback
        '''
        try:
            self.execute_target(target_type, permissions=False)
            need_permissions = False
        except subprocess.TimeoutExpired or TargetExecutionError as e:
            self.log("error", f"{target_type} target failed during "
                              f"elevation test: {e}")
            self.log("info", f"{target_type} retrying with permissions")

            # This call will be able to raise exceptions
            self.execute_target(target_type, permissions=True)
            need_permissions = True

        if need_permissions:
            # If execution required permissions and the elevation is set to
            # user, the elevation is too low
            if self.info[target_type]["elevation"] == "user":
                self.log("warning", f"{target_type} target elevation too low. "
                                    "Needed: `Admin`, current: `user`")
            else:
                self.log("ok",
                         f"{target_type} elevation is at a correct level")
        else:
            # If execution did not require permissions and the elevation is set
            # to something else than user, the elevation is too high
            if self.info[target_type]["elevation"] != "user":
                self.log("warning", f"{target_type} target elevation too high."
                                    " Needed: `user`, current: "
                                    f"`{self.info[target_type]['elevation']}`")
            else:
                self.log("ok",
                         f"{target_type} elevation is at a correct level")

        self.report[target_type]["need_permissions"] = need_permissions

    def degradation_tests(self):
        for i in range(3):
            self.execute_target("rollback")

            need_remediation, result = self.fetch_need_remediation()
            # If no need remediation
            if not need_remediation:
                self.log("error", "rollback dit not revert the changes at the "
                                  f"attempt {i}", result=result)
                return False
            else:
                self.log("ok", "rollback reverted the changes successfuly at "
                               f"the attempt {i}")

            self.execute_target("remediation")

            need_remediation, result = self.fetch_need_remediation()
            # If need remediation
            if need_remediation:
                self.log("error", "remediation dit not resolve the "
                                  f"implementation at attempt {i}", result=result)
                return False
            else:
                self.log("ok", "remediation resolved the implementation "
                               f"successfuly at the attempt {i}")

    def should_ignore(self, metric_name, test_type):
        for item in self.ignore_list:
            if item['metric_name'] == metric_name and (test_type in item['tests'] or 'all' in item['tests']):
                return True
        return False

    def run_all_tests(self, implementation_only=False):
        '''Run all the tests for this metric'''

        if self.should_ignore(self.info['name'], 'implementation'):
            self.logger.info(f"Skipping `{self.info['name']}` due to ignore list.")
            return True

        self.logger.info(f"Running `{self.info['name']}` tests")

        if not self.implementation_tests():
            self.log("info", "Skipping other tests because implementation "
                             "failed")
            return False

        if implementation_only:
            return True

        if self.fetch_need_remediation()[0]:
            if not self.should_ignore(self.info['name'], 'remediation'):
                if not self.remediation_tests():
                    self.log("info", "Skipping other tests because remediation "
                                     "failed")
                    return False
            else:
                self.logger.info(f"Skipping `{self.info['name']}` remediation due to ignore list.")

            if not self.should_ignore(self.info['name'], 'rollback'):
                if not self.rollback_test():
                    self.log("info", "Skipping degradation tests because rollback "
                                     "failed")
                    return False
            else:
                self.logger.info(f"Skipping `{self.info['name']}` rollback due to ignore list.")

        else:
            if not self.should_ignore(self.info['name'], 'rollback'):
                if not self.rollback_test():
                    self.log("info", "Skipping other tests because rollback "
                                     "failed")
                    return False
            else:
                self.logger.info(f"Skipping `{self.info['name']}` rollback due to ignore list.")

            if not self.should_ignore(self.info['name'], 'remediation'):
                if not self.remediation_tests():
                    self.log("info", "Skipping degradation because remediation "
                                     "failed")
                    return False
            else:
                self.logger.info(f"Skipping `{self.info['name']}` remediation due to ignore list.")

        if not self.should_ignore(self.info['name'], 'remediation') and not self.should_ignore(self.info['name'], 'rollback'):
            self.degradation_tests()

        return True


class TargetExecutionError(Exception):
    '''Raised when a target execution fails'''
    pass


class TargetIsNotACLI(Exception):
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


def need_remediation_logic(result, platform):
    if platform == "Windows":
        # Windows returns \n when the command succeed
        return result.stdout != "\n"
    else:
        return result.stdout != ""
