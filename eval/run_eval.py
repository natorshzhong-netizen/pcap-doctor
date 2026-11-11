"""检测规则评测：按场景统计 precision / recall / 场景完全命中率。

python eval/run_eval.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.pcap_doctor.analyze import analyze_views  # noqa: E402
from src.pcap_doctor.demo import write_demo_pcaps  # noqa: E402
from src.pcap_doctor.load import load_pcap  # noqa: E402

RESULTS_DIR = ROOT / "eval" / "results"


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

    spec = json.loads((ROOT / "eval" / "cases.json").read_text(encoding="utf-8"))
    pcaps = write_demo_pcaps(RESULTS_DIR / "pcaps")

    tp = fp = fn = 0
    exact = 0
    rows = []
    for case in spec["cases"]:
        scenario = case["scenario"]
        expected = set(case["expected"])
        result = analyze_views(load_pcap(pcaps[scenario]), str(pcaps[scenario]))
        detected = {item.code for item in result.findings}
        case_tp = len(expected & detected)
        case_fp = len(detected - expected)
        case_fn = len(expected - detected)
        tp += case_tp
        fp += case_fp
        fn += case_fn
        matched = expected == detected
        exact += int(matched)
        rows.append(
            {
                "scenario": scenario,
                "expected": sorted(expected),
                "detected": sorted(detected),
                "tp": case_tp,
                "fp": case_fp,
                "fn": case_fn,
                "exact": matched,
            }
        )
        print(
            f"{'✓' if matched else '✗'} {scenario:<20} 期望 {len(expected)} · "
            f"命中 {case_tp} · 多报 {case_fp} · 漏报 {case_fn}"
        )

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    exact_rate = exact / len(rows)
    print("-" * 62)
    print(f"precision {precision * 100:.1f}% · recall {recall * 100:.1f}% · 场景完全命中 {exact}/{len(rows)}")
    passed = precision >= 0.9 and recall == 1.0 and exact_rate == 1.0
    print("PASS" if passed else "FAIL")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "latest.json").write_text(
        json.dumps(
            {
                "rows": rows,
                "precision": precision,
                "recall": recall,
                "exact_rate": exact_rate,
                "passed": passed,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"结果：{RESULTS_DIR / 'latest.json'}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
