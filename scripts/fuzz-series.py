#!/usr/bin/env python3
"""Run a finite warm-start seed series; preserve per-campaign failure status."""
import argparse
import importlib.util
import os
from pathlib import Path
import signal
import sys
import time

spec = importlib.util.spec_from_file_location('campaign', Path(__file__).with_name('fuzz-campaign.py'))
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seeds', type=campaign.positive, nargs='+', required=True)
    parser.add_argument('--seconds', type=campaign.positive, default=600)
    parser.add_argument('--runs', type=campaign.positive, default=1000000000)
    parser.add_argument('--wall-seconds', type=campaign.positive,
                        help='Per-campaign child-process wall deadline.')
    args = parser.parse_args(argv)
    if len(set(args.seeds)) != len(args.seeds):
        parser.error('seed values must be unique')
    os.umask(0o077)
    args.output.mkdir(parents=True)
    state = {'schema':1, 'status':'running', 'pid':os.getpid(),
             'started_unix':time.time(), 'seeds':args.seeds,
             'inputs':campaign.inputs(),
             'budget':{'runs_per_target':args.runs, 'seconds_per_target':args.seconds},
             'campaigns':[], 'corpus_policy':'Sequential warm start; each campaign retains its initial corpus.',
             'limitations':['Not independent trials or cryptographic security proof.',
                            'Only a passed series has completed every planned seed.']}
    state_path = args.output/'series.json'
    campaign.write_report(state_path, state)
    handlers = {}

    def on_signal(signum, frame):
        raise campaign.CampaignInterrupted()

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        handlers[signum] = signal.signal(signum, on_signal)
    result = 1
    try:
        for seed in args.seeds:
            if campaign.inputs() != state['inputs']:
                raise ValueError('source inputs changed between campaigns')
            path = args.output/('seed-'+str(seed))
            item = {'seed':seed, 'output':path.name, 'status':'running'}
            state['campaigns'].append(item)
            campaign.write_report(state_path, state)
            options = ['--output',str(path),'--seed',str(seed),
                       '--runs',str(args.runs),'--seconds',str(args.seconds)]
            if args.wall_seconds:
                options += ['--wall-seconds',str(args.wall_seconds)]
            result = campaign.main(options)
            item.update(returncode=result, status='passed' if result == 0 else
                        'interrupted' if result == 130 else 'timed_out' if result == 124 else 'failed')
            campaign.write_report(state_path, state)
            if result != 0:
                state['status'] = item['status']
                break
        else:
            if campaign.inputs() != state['inputs']:
                raise ValueError('source inputs changed during series')
            state['status'] = 'passed'
    except (campaign.CampaignInterrupted, KeyboardInterrupt):
        result = 130
        state['status'] = 'interrupted'
    except Exception as error:
        state.update(status='failed', error_type=type(error).__name__)
        result = 1
    finally:
        if state['campaigns'] and state['campaigns'][-1]['status'] == 'running':
            state['campaigns'][-1]['status'] = state['status']
        state['finished_unix'] = time.time()
        campaign.write_report(state_path, state)
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    return result


if __name__ == '__main__':
    sys.exit(main())
