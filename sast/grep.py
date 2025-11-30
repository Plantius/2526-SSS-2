import atexit
import json
import logging
import os
import time

import dotenv
import requests

from utils.database import (
    add_timing_to_project,
    change_project_step,
    fetch_project_at_step,
    pause_project,
    save_semgrep_output,
)
from utils.enums import (
    PAUSED_SEMGREP_FAILED,
    PAUSED_SEMGREP_NO_RESULT,
    STEP_ADDED,
    STEP_SEMGREPED,
    STEP_SEMGREPING,
)
from utils.tools import runcommand

dotenv.load_dotenv("../.env")
logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

# Use .php so Semgrep treats it as PHP
DL_FILE_PATH = "/tmp/newscan.php"
timeCounter = 0

# Use built-in PHP rulesets from the Semgrep Registry, focused on security/injection
SEMGREP_CMD = """
timeout 30 semgrep \
  --config=p/phpcs-security-audit \
  --metrics=off \
  --json --output /tmp/out.json \
  $FILE 2>/dev/null >/dev/null
""".strip()

LOCK_FILENAME = "/tmp/0d-grep.running"


def timing_start():
    global timeCounter
    timeCounter = int(time.time() * 1000)


def timing_finish():
    return int(time.time() * 1000) - timeCounter


def pick_lock():
    os.remove(LOCK_FILENAME)


def main():
    while True:
        proj_id, proj_filename, _, file_github_url = fetch_project_at_step(STEP_ADDED)

        if proj_id is None or file_github_url is None:
            print("[*] Waiting for new projects ...")
            time.sleep(5)
            continue

        change_project_step(proj_id, STEP_SEMGREPING)
        timing_start()

        # Download the PHP file
        with open(DL_FILE_PATH, "wb") as f:
            f.write(requests.get(file_github_url).content)

        # Run Semgrep with PHP rules
        exit_code, out, err = runcommand(SEMGREP_CMD.replace("$FILE", DL_FILE_PATH))

        logging.info(out)
        if err != "":
            logging.error(err)

        add_timing_to_project(proj_id, "semgrep", timing_finish())

        if exit_code == 0:
            logging.info("Semgrep ran successfully")
            with open("/tmp/out.json") as f:
                stuff = json.load(f)

            if len(stuff.get("results", [])) > 0:
                # Save all findings (includes injection-type issues)
                save_semgrep_output(proj_id, json.dumps(stuff["results"]))
                logging.info(f"Semgrep found a possible vuln in {proj_id}")
            else:
                pause_project(proj_id, PAUSED_SEMGREP_NO_RESULT)
                logging.info(f"Semgrep couldn't find a vuln in {proj_id}")
        else:
            pause_project(proj_id, PAUSED_SEMGREP_FAILED)
            logging.info("Semgrep failed")

        change_project_step(proj_id, STEP_SEMGREPED)


if __name__ == "__main__":
    if os.path.isfile(LOCK_FILENAME):
        print("Already running")
        exit(0)
    open(LOCK_FILENAME, "w").close()
    atexit.register(pick_lock)

    main()
    logging.info("All projects have been checked")
