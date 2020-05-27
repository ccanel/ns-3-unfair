#! /usr/bin/env python3
"""Runs experiments to generate training data. """

import argparse
import json
import logging
import logging.handlers
import multiprocessing
import os
from os import path
import re
import subprocess
import time
import traceback

import matplotlib.pyplot as plt
import numpy as np


# Bandwidth (Mbps).
BW_MIN_Mbps = 4
BW_MAX_Mbps = 50
BW_DELTA_Mbps = 2
BWS_Mbps = list(range(BW_MIN_Mbps, BW_MAX_Mbps + 1, BW_DELTA_Mbps))
# Link delay (us).
DELAY_MIN_us = 100
DELAY_MAX_us = 1000
DELAY_DELTA_us = 50
DELAYS_us = list(range(DELAY_MIN_us, DELAY_MAX_us + 1, DELAY_DELTA_us))
# Ack period (us).
ACK_PERIOD_MIN_us = 0
ACK_PERIOD_MAX_us = 6_000  # 1 RTT ≈ 4_000
ACK_PERIOD_DELTA_us = 50
ACK_PERIODS_us = list(range(
    ACK_PERIOD_MIN_us, ACK_PERIOD_MAX_us + 1, ACK_PERIOD_DELTA_us))
# Router queue size (packets).
QUEUE = 100
# Simulation duration (s).
DUR_s = 20
# Delay until ACK pacing begins.
WARMUP_s = 5
# Whether to return before running experiments.
DRY_RUN = False
# Whether to capture pcap traces.
PCAP = True
# Whether to run the simulations synchronously or in parallel.
SYNC = False
# Path to the ns-3 top-level directory.
# Warning: If you move this file from the ns-3 top-level directory, then you
#          must update this variable.
NS3_DIR = path.dirname(path.realpath(__file__))
# Used to synchronize writing to the error log.
LOCK = multiprocessing.Lock()
# Name of the error log file.
ERR_FLN = "failed.json"
# Default destination for email updates.
EMAIL_DST = "c.canel@icloud.com"


def check_output(cnf):
    args = ([path.join(NS3_DIR, "build", "scratch", "ai"),] +
            [f"--{arg}={val}" for arg, val in cnf.items()])
    cmd = f"LD_LIBRARY_PATH={os.environ['LD_LIBRARY_PATH']} {' '.join(args)}"
    print(f"Running: {cmd}")
    try:
        res = subprocess.check_output(
            args, stderr=subprocess.STDOUT, env=os.environ).decode().split("\n")
    except subprocess.CalledProcessError:
        traceback.print_exc()
        logging.getLogger().exception("Exception while running:\n%s\n\n", cmd)
        # Only one worker should access the error log at a time.
        LOCK.acquire()
        err_flp = path.join(cnf["out_dir"], ERR_FLN)
        # If the error log already exists, then read the existing log and append
        # to it. Otherwise, start a new log.
        if path.exists(err_flp):
            with open(err_flp, "r") as fil:
                err_log = json.load(fil)
        else:
            err_log = []
        # Record the full command (including LD_LIBRARY_PATH) in the error log
        # for ease of debugging. Do not do "cnf['cmd'] = ..." to maintain the
        # invariant that cnf contains only command line arguments.
        err_log.append(dict(cnf, cmd=cmd))
        with open(err_flp, "w") as fil:
            json.dump(err_log, fil, indent=4)
        LOCK.release()
        # The output is empty.
        res = []
    return res


def run(cnf):
    # Build the arguments array, run the simulation, and iterate over each line
    # in its output.
    for line in check_output(cnf):
        if line.startswith("Throughput"):
            match = re.search(r"Throughput: ([\d.]+) Mb/s", line)
            assert match is not None, f"Improperly formed output line: {line}"
            return float(match.group(1))
    return None


def main():
    print(f"ns-3 dir: {NS3_DIR}")
    # Parse command line arguments.
    psr = argparse.ArgumentParser(description="Generates training data.")
    psr.add_argument(
        "--out-dir",
        help="The directory in which to store output files (required).",
        required=True, type=str)
    psr.add_argument(
        "--log-dst", default=EMAIL_DST,
        help="The email address to which updates will be sent.", type=str)
    args = psr.parse_args()
    # The ID of this experiment.
    eid = str(round(time.time()))
    # Create a new output directory based on the current time.
    out_dir = path.join(args.out_dir, eid)
    # For organization purposes, store the pcap files in a subdirectory.
    sim_dir = path.join(out_dir, "sim")
    # This also creates out_dir.
    os.makedirs(sim_dir)
    # Create email logger.
    # TODO: Create an email logger only if an SMTP server is running on the
    #       local machine.
    log = logging.getLogger()
    log.addHandler(logging.handlers.SMTPHandler(
        mailhost="localhost",
        fromaddr=f"{os.getlogin()}@maas.cmcl.cs.cmu.edu",
        toaddrs=args.log_dst,
        subject=f"[{path.basename(__file__)}] {eid}"))

    # Compile ns-3.
    subprocess.check_call([path.join(NS3_DIR, "waf")])
    # Since we are running the application binary directly, we need to make sure
    # the ns-3 library can be found.
    os.environ["LD_LIBRARY_PATH"] = (
        f"/usr/lib/gcc/x86_64-linux-gnu/7:{path.join(NS3_DIR, 'build')}")

    # Assemble the configurations.
    cnfs = [{"bandwidth_Mbps": bw_Mbps, "delay_us": dly_us,
             "queue_capacity_p": QUEUE, "experiment_duration_s": DUR_s,
             "ack_period_us": per_us, "warmup_s": WARMUP_s,
             "pcap": "true" if PCAP else "false", "out_dir": sim_dir}
            for bw_Mbps in BWS_Mbps
            for dly_us in DELAYS_us
            for per_us in ACK_PERIODS_us]
    # Record the configurations.
    with open(path.join(out_dir, "configurations.json"), "w") as fil:
        json.dump(cnfs, fil, indent=4)

    # Simulate the configurations.
    print(f"Num simulations: {len(cnfs)}")
    if DRY_RUN:
        return
    tim_srt_s = time.time()
    if SYNC:
        data = [run(cnf) for cnf in cnfs]
    else:
        with multiprocessing.Pool() as pool:
            data = pool.map(run, cnfs)
    print(f"Done with simulation - time: {time.time() - tim_srt_s:.2f} seconds")
    data = list(zip(cnfs, data))

    # Graphs results. Generate an achieved throughput vs. ack period graph for
    # each configuration of bandwidth and delay.
    #
    # Returns a sorted list of all unique values for a particular key.
    get_all = lambda key: sorted(list({cnf[key] for cnf in cnfs}))
    # Use get_all() instead of directly looping over BWS_Mbps and DELAYS_us in
    # case we filtered the configurations and did not run all experiments.
    for bw_Mbps in get_all("bandwidth_Mbps"):
        for dly_us in get_all("delay_us"):
            # Select only the results with this bandwidth and delay, and pick
            # the value of the ACK period as the x value. Then, split the (x, y)
            # pairs into a list of xs and a list of ys.
            xs, ys = zip(*[(cnf["ack_period_us"], results)
                           for cnf, results in data
                           if (cnf["bandwidth_Mbps"] == bw_Mbps and
                               cnf["delay_us"] == dly_us)])
            # Convert from us to ms.
            xs = np.array(xs) / 1e3
            plt.plot(xs, ys)
            plt.xlabel("ACK delay (ms)")
            plt.ylabel("Average throughput (Mb/s)")
            plt.ylim(bottom=0, top=bw_Mbps)
            plt.savefig(path.join(
                out_dir,
                f"{bw_Mbps}Mbps_{dly_us}us_{QUEUE}packets_{DUR_s}s.pdf"))
            plt.close()

    print(f"Results in: {out_dir}")
    log.critical("Finished.")


if __name__ == "__main__":
    main()
