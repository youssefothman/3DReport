import os
import subprocess

# Inject API keys into environment
env = os.environ.copy()
env["WHOIS_API_KEY"] = "at_w5FxDIhFFkwqQdYdGs2tiszELl2R0"
env["THREATINT_API_KEY"] = "at_wjKFvkN7iUpqywnneyMtRPquQ9TTw"

# Run their editable script
subprocess.run(["python", "3D_report_builder.py"], env=env)
