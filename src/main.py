from model import Model
import logging

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

model = Model(logger, dir_path=".")
model.run_metrics_sequentially()
results = model.get_results()

print(results)

if results["errors"] > 0 or results["invalid_remediations"] > 0:
    exit(1)
else:
    exit(0)
