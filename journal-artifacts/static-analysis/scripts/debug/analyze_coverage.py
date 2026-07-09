import json
from pathlib import Path

base = Path(__file__).resolve().parents[2]
coverage_path = base / "artifacts" / "coverage" / "coverage.json"

with coverage_path.open("r", encoding="utf-8") as f:
    data = json.load(f)

print("=" * 70)
print("TEST COVERAGE ANALYSIS")
print("=" * 70)

# Overall coverage
totals = data['totals']
print(f"\nOVERALL COVERAGE: {totals['percent_covered']:.2f}%")
print(f"Covered Lines: {totals['covered_lines']}/{totals['num_statements']}")
print(f"Missing Lines: {totals['missing_lines']}")

# Per-file breakdown
print("\n" + "=" * 70)
print("COVERAGE BY FILE")
print("=" * 70)

files = data['files']
file_coverage = []

for filepath, filedata in files.items():
    summary = filedata['summary']
    file_coverage.append({
        'file': filepath,
        'percent': summary['percent_covered'],
        'covered': summary['covered_lines'],
        'total': summary['num_statements'],
        'missing': summary['missing_lines']
    })

# Sort by coverage percentage
file_coverage.sort(key=lambda x: x['percent'])

for fc in file_coverage:
    print(f"\n{fc['file']}")
    print(f"  Coverage: {fc['percent']:.1f}% ({fc['covered']}/{fc['total']} lines)")
    print(f"  Missing: {fc['missing']} lines")

# Category breakdown
print("\n" + "=" * 70)
print("COVERAGE BY CATEGORY")
print("=" * 70)

categories = {
    'API/Server': [],
    'Detectors': [],
    'Extractors': [],
    'Report Generator': [],
    'Utilities': [],
    'Tests': []
}

for filepath, filedata in files.items():
    summary = filedata['summary']
    if 'app.py' in filepath:
        categories['API/Server'].append(summary)
    elif 'detector' in filepath:
        categories['Detectors'].append(summary)
    elif 'extractor' in filepath:
        categories['Extractors'].append(summary)
    elif 'report_generator' in filepath:
        categories['Report Generator'].append(summary)
    elif 'test_' in filepath:
        categories['Tests'].append(summary)
    else:
        categories['Utilities'].append(summary)

for category, summaries in categories.items():
    if summaries:
        total_covered = sum(s['covered_lines'] for s in summaries)
        total_statements = sum(s['num_statements'] for s in summaries)
        percent = (total_covered / total_statements * 100) if total_statements > 0 else 0
        print(f"\n{category}:")
        print(f"  Coverage: {percent:.1f}% ({total_covered}/{total_statements} lines)")
        print(f"  Files: {len(summaries)}")
