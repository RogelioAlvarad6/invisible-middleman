"""Bundle the code as .txt files for Canvas (the course only accepts code as .txt),
and render the scenario guides + answer keys from the visualizer's content file.

Run:  uv run python tools/make_submission.py      -> submission/
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "submission"

BUNDLES = {
    "InvisibleMiddleman_engine.txt": [
        "src/invisible_middleman/__init__.py", "src/invisible_middleman/parse.py",
        "src/invisible_middleman/rules.py", "src/invisible_middleman/engine.py",
        "src/invisible_middleman/cli.py", "pyproject.toml"],
    "InvisibleMiddleman_scenarios.txt": [
        "scenarios/build_scenarios.py", "scenarios/export_timelines.py", "tools/make_submission.py"],
    "InvisibleMiddleman_tests.txt": ["tests/test_detection.py", "visualizer/tests/fold.test.js"],
    "InvisibleMiddleman_visualizer.txt": [
        "visualizer/index.html", "visualizer/src/main.js", "visualizer/src/fold.js",
        "visualizer/src/diagram.js", "visualizer/src/style.css", "visualizer/package.json",
        "visualizer/vite.config.js", ".github/workflows/pages.yml"],
}


def bundle():
    OUT.mkdir(exist_ok=True)
    for name, files in BUNDLES.items():
        parts = [f"The Invisible Middleman - {name}\nSeveral source files merged into one file; "
                 "each section header gives the file's path in the repository.\n"]
        for f in files:
            parts.append(f"\n{'=' * 78}\nFILE: {f}\n{'=' * 78}\n{(ROOT / f).read_text(encoding="utf-8")}")
        (OUT / name).write_text("".join(parts), encoding="utf-8")
        print(f"wrote submission/{name}")


def guides():
    c = json.loads((ROOT / "visualizer/public/content/scenarios.json").read_text(encoding="utf-8"))
    L = ["# Scenario guides, checkpoint questions and answer keys\n"]
    for s in c["scenarios"]:
        L.append(f"\n## {s['title']}\n")
        L.append(f"Learning objective {s['objective']} · about {s['minutes']} minutes"
                 + (f" · defenses on at start: {', '.join(s['defaults'])}" if s.get("defaults") else "") + "\n")
        L += ["\n" + p + "\n" for p in s["intro"]]
        for st in s["steps"]:
            L.append(f"\n**Frame {st['frame']}: {st['title']}.** {st['text']}\n")
            if q := st.get("question"):
                L += question(q)
        if quiz := s.get("quiz"):
            L.append(f"\n### {quiz['title']} (pass mark {int(quiz['pass'] * 100)}%)\n")
            for n, q in enumerate(quiz["questions"], 1):
                L += question(q, n)
        if s.get("challenge"):
            a = s["answers"]
            L.append("\n**Answer key.** Attack type: " + s["attack_options"][a["attack_type"]]
                     + f"; attacker MAC: {a['attacker_mac']}; affected host(s): {', '.join(a['affected'])}.\n")
            L.append(f"\n**Debrief.** {s['debrief']}\n")
    L.append("\n## Defense toggles\n")
    for d in c["defenses"].values():
        L.append(f"\n**{d['label']}.** {d['what']} *Limit:* {d['limit']}\n")
    (OUT / "scenario_guides.md").write_text("".join(L), encoding="utf-8")
    print("wrote submission/scenario_guides.md")


def question(q, n=None):
    out = [f"\n{'Q' + str(n) + '. ' if n else 'Question: '}{q['prompt']}\n\n"]
    for k, (opt, fb) in enumerate(zip(q["options"], q["feedback"])):
        mark = "Correct" if k == q["answer"] else "Incorrect"
        out.append(f"- {chr(65 + k)}. {opt}. *{mark}: {fb}*\n")
    return out


if __name__ == "__main__":
    bundle()
    guides()
