from model import Model

model = Model(dir_path=".")
model.run_implementations()
model.run_remediations(force=True)
results = model.get_results()

print(results)

if results["errors"] > 0 or results["invalid_remediations"] > 0:
    exit(1)
else:
    exit(0)
