#!/usr/bin/env python3
"""Validate required dependency reports and print only non-secret summaries."""
import argparse
import json
from pathlib import Path

CARGO_REPORTS = ('bench.json', 'cryptanalysis.json', 'fuzz.json', 'native.json', 'wasm.json')
REPORTS = (*CARGO_REPORTS, 'gitleaks.json', 'npm.json')
SEVERITIES = ('info', 'low', 'moderate', 'high', 'critical')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mapping(value, label):
    require(isinstance(value, dict), label + ' must be an object')
    return value


def count(value, label):
    require(type(value) is int and value >= 0, label + ' must be a nonnegative integer')
    return value


def text(value, label):
    require(isinstance(value, str) and bool(value), label + ' must be nonempty text')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('non-finite JSON number')


def cargo_summary(name, report):
    report = mapping(report, 'report')
    require('error' not in report, 'cargo reported an audit error')
    database = mapping(report.get('database'), 'database')
    count(database.get('advisory-count'), 'advisory-count')
    text(database.get('last-commit'), 'database commit')
    text(database.get('last-updated'), 'database update')
    findings = mapping(report.get('vulnerabilities'), 'vulnerabilities')
    total = count(findings.get('count'), 'vulnerability count')
    entries = findings.get('list')
    require(isinstance(entries, list) and len(entries) == total, 'vulnerability list/count mismatch')
    require(type(findings.get('found')) is bool and findings['found'] == (total > 0),
            'vulnerability found/count mismatch')
    rows = []
    for item in entries:
        item = mapping(item, 'vulnerability')
        advisory = mapping(item.get('advisory'), 'advisory')
        package = mapping(item.get('package'), 'package')
        rows.append((text(advisory.get('id'), 'advisory id'), text(package.get('name'), 'package name'),
                     text(package.get('version'), 'package version'), text(advisory.get('title'), 'title')))
    warnings = mapping(report.get('warnings'), 'warnings')
    require(all(isinstance(items, list) for items in warnings.values()), 'invalid warning list')
    public_database = {key: database[key] for key in ('advisory-count', 'last-commit', 'last-updated')}
    print(name, 'database:', public_database, 'vulnerabilities:', total)
    for row in rows:
        print(*row)
    for kind, items in warnings.items():
        print(name, 'warning', kind, len(items))
    return total > 0


def npm_summary(report):
    report = mapping(report, 'report')
    require('error' not in report, 'npm reported an audit error')
    require(type(report.get('auditReportVersion')) is int and report['auditReportVersion'] == 2,
            'unsupported npm audit report version')
    metadata = mapping(report.get('metadata'), 'metadata')
    totals = mapping(metadata.get('vulnerabilities'), 'vulnerability totals')
    for severity in (*SEVERITIES, 'total'):
        count(totals.get(severity), severity + ' total')
    require(sum(totals[s] for s in SEVERITIES) == totals['total'], 'npm severity totals mismatch')
    findings = mapping(report.get('vulnerabilities'), 'vulnerabilities')
    require(bool(findings) == (totals['total'] > 0), 'npm findings/totals mismatch')
    rows = []
    for name, item in findings.items():
        item = mapping(item, 'vulnerability')
        require(item.get('severity') in SEVERITIES, 'invalid npm severity')
        require(isinstance(item.get('fixAvailable'), (bool, dict)), 'invalid npm fixAvailable')
        rows.append((name, item['severity'], 'fixAvailable=' + str(item['fixAvailable'])))
    print('npm totals:', totals)
    for row in rows:
        print('npm', *row)
    return totals['total'] > 0


def gitleaks_summary(report):
    require(isinstance(report, list), 'gitleaks report must be a list')
    rows = []
    for item in report:
        item = mapping(item, 'gitleaks finding')
        line = count(item.get('StartLine'), 'finding line')
        require(line > 0 and isinstance(item.get('Commit'), str), 'invalid finding location')
        rows.append((text(item.get('RuleID'), 'rule'), text(item.get('File'), 'file'), line, item['Commit']))
    print('gitleaks history findings:', len(report))
    for row in rows:
        print('gitleaks', *row)  # Never print Secret or Match fields.
    return bool(report)


def summarize(directory):
    failed = False
    for name in REPORTS:
        try:
            report = json.loads((directory / name).read_text(encoding='utf-8'),
                                object_pairs_hook=unique_object, parse_constant=reject_constant)
            if name == 'npm.json':
                findings = npm_summary(report)
            elif name == 'gitleaks.json':
                findings = gitleaks_summary(report)
            else:
                findings = cargo_summary(name, report)
            failed = failed or findings
        except (OSError, ValueError) as error:
            # Include the filename and keep checking the other expected reports.
            print(name + ': invalid or incomplete report (' + str(error) + ')')
            failed = True
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    return summarize(parser.parse_args().directory)


if __name__ == '__main__':
    raise SystemExit(main())
