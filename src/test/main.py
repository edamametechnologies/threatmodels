from model import Model
import logging
import sys
logging.basicConfig(
        format='[%(asctime)s][%(levelname)s] %(message)s',
        )

OK_LEVEL = 10
logging.addLevelName(OK_LEVEL, "\033[32mOK\033[0m")


def ok(self, message, *args, **kwargs):
    if self.isEnabledFor(OK_LEVEL):
        self._log(OK_LEVEL, message, args, **kwargs)


logging.Logger.ok = ok
logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)

model = Model(logger, dir_path=".", ignore_tests_path='./src/test/ignore-tests.yaml')

# If implementation_only is passed to the script, only implementation tests are run
implementation_only = len(sys.argv) > 1 and sys.argv[1] == "implementation_only"
results = model.run_metrics_sequentially(implementation_only)

print(results)

if results["error_count"] > 0:
    exit(1)
else:
    exit(0)
