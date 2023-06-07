from model import Model
import logging

logging.basicConfig(format='[%(asctime)s][%(levelname)s] %(message)s', level=logging.INFO)

logger = logging.getLogger('logger')

model = Model(logger, dir_path=".")
model.run_metrics_sequentially()
results = model.get_results()

print(results)

if results["errors"] > 0 or results["invalid_remediations"] > 0:
    exit(1)
else:
    exit(0)
