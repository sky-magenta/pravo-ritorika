#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E2E-прогон скилла pravo-ritorika по набору cases.jsonl через Claude API.

Каждый пример подаётся модели, у которой в системном контексте загружен весь
скилл (SKILL.md + все references). Ответ модели сверяется с ожиданием:
  • defect  — назван ли ожидаемый дефект подачи (по алиасам / имени);
  • clean   — не выдумана ли уязвимость (вердикт «устойчива / работает / без дефектов»).

Скилл проверяет УБЕДИТЕЛЬНОСТЬ, а не валидность вывода и не право по существу; места,
зависящие от нормы, он помечает флагом [требует проверки], логические дефекты — [→ pravo-logika].

Системный контекст (большой и неизменный) кэшируется prompt caching'ом —
он одинаков для всех запросов, поэтому оплачивается по сути один раз.

Требуется ключ: экспортируйте ANTHROPIC_API_KEY (или войдите через `ant auth login`).

Примеры:
  python run_evals.py --dry-run                 # без сети: проверить сборку промптов
  python run_evals.py --limit 5                 # быстрый прогон на 5 примерах
  python run_evals.py --grader llm              # грейдинг вторым вызовом-судьёй (точнее для clean)
  python run_evals.py --model claude-opus-4-8   # прогнать весь набор
"""
import argparse
import concurrent.futures as cf
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CASES_PATH = os.path.join(HERE, "cases.jsonl")

DEFAULT_MODEL = "claude-opus-4-8"

# Файлы скилла, которые кладём в системный контекст модели.
SKILL_FILES = [
    "SKILL.md",
    "references/status.md",
    "references/dispositio.md",
    "references/audience.md",
    "references/appeals.md",
    "references/refutation.md",
    "references/rhetoric-errors.md",
]

MODE_INSTRUCTIONS = {
    "stress-test": (
        "Режим СТРЕСС-ТЕСТ. Построй сильнейшую добросовестную контрпозицию (steelman) и карту "
        "уязвимостей подачи строго по формату отчёта стресс-теста из SKILL.md: вердикт, позиция "
        "автора, контрпозиция оппонента, карта уязвимостей (критичные / умеренные + способ "
        "укрепления), дефекты валидности одной строкой [→ pravo-logika], флаги к проверке. "
        "Позицию автора не переписывай."
    ),
    "status": (
        "Режим СТАТУС. Разложи ситуацию по четырём статусам (факт / определение / оценка / "
        "процедура) строго по формату статусного разбора из SKILL.md (references/status.md): что "
        "доступно, что доказывать, чем платит позиция; фактический статус текста и проверка на "
        "смешение линий; правило зеркала (статус оппонента); рекомендация условно по "
        "доказательственной базе. Решение о статусе оставь автору."
    ),
    "structure": (
        "Режим СТРУКТУРА. Разбери диспозицию текста строго по формату отчёта по структуре из "
        "SKILL.md (references/dispositio.md, references/rhetoric-errors.md): карта текста (части и "
        "их роли), таблица структурных проблем, предлагаемый порядок с обоснованием перемещений. "
        "Дефекты называй по каталогу rhetoric-errors.md. Текст переписывай только по явной просьбе."
    ),
    "adapt": (
        "Режим АДАПТАЦИЯ. Переупакуй материал под названного адресата строго по формату адаптации "
        "из SKILL.md (references/audience.md, references/appeals.md): модель адресата (решение и "
        "рамки, опасения, язык, аргумент/шум), адаптированный текст (отбор, порядок, регистр — "
        "содержание сохранено), список изменений с указанием свойства адресата, проверка "
        "secondary-адресатов. Содержание позиции не меняй."
    ),
}

# Сигналы «чисто» для быстрого (alias) грейдинга clean-примеров.
# Даны основами (без окончаний), сверка идёт по нормализованному тексту — см. _norm.
CLEAN_SIGNALS = [
    "устойчив", "подача работает", "структура работает", "уязвимостей не",
    "уязвимости не", "критичных уязвимост", "дефектов подачи нет", "дефекта подачи нет",
    "дефектов не найд", "без дефект", "адресация верна", "регистр вер",
    "лестница выстроена", "порядок верн", "порядок соблюд", "гомеров порядок соблюд",
    "статус соблюд", "правило соблюд", "не выдум", "переписывать не требует",
    "позиция устойчива", "смешения нет",
    # сигналы «чисто» для распознавания приёмов оппонента (E): приёма нет, довод добросовестный
    "недобросовестн", "уловки нет", "приёма нет", "не уловка",
    "довод добросовест", "оппонент добросовест", "честный довод", "законн", "steelman",
    # типовые формулировки вердикта «чисто» в живых ответах
    "адаптация верна", "адаптация коррект", "фокус верен", "формулировка защищаем",
    "подача корректна", "выстроена корректно", "соответствует модели", "порядок осознан",
]

# Регэксп-фолбэк для clean: «дефект/уязвимость … нет/отсутствует» в любых формулировках
# (по нормализованному тексту, см. _norm ниже): точный список сигналов хрупок
# к перифразам («дефекта-улики в исходнике нет», «смешения статусов нет»).
import re as _re
_CLEAN_RX = [
    _re.compile(r"(?:дефект|уязвим|улов|при[её]м|смешен|инверс|проблем|наруш)\w*.{0,60}?"
                r"(?:нет|отсутств|не выявлен|не обнаружен|не найден|не создаёт)"),
    _re.compile(r"(?:нет|отсутств|без)\s+(?:\w+\s+){0,3}(?:дефект|уязвим|улов|смешен|проблем)"),
]

# ── Нормализация для морфологически устойчивого сопоставления ──────────────
_PUNCT = "«»„“”\"'`()[]{}<>.,;:!?/\\|—–-… "
_TRANS = {ord(c): " " for c in _PUNCT}


def _norm(s):
    return " ".join(str(s).lower().translate(_TRANS).split())


def _stems(needle):
    out = []
    for w in _norm(needle).split():
        if len(w) <= 2:
            continue
        out.append(w[:5] if len(w) > 5 else w)
    return out


def _hit(needle, norm_text):
    """Алиас найден, если целиком входит в текст ИЛИ все его основы присутствуют."""
    n = _norm(needle)
    if n and n in norm_text:
        return True
    stems = _stems(needle)
    return bool(stems) and all(st in norm_text for st in stems)


def read_skill_context():
    parts = []
    for rel in SKILL_FILES:
        p = os.path.join(ROOT, rel)
        with open(p, encoding="utf-8") as f:
            parts.append(f"===== ФАЙЛ: {rel} =====\n" + f.read())
    header = (
        "Ты действуешь как скилл pravo-ritorika. Ниже — полный текст скилла "
        "(SKILL.md и все references). Действуй строго по нему: проверяй и усиливай "
        "УБЕДИТЕЛЬНОСТЬ подачи, валидность вывода не разбирай (флаг [→ pravo-logika]), "
        "нормы и практику по памяти не подставляй (флаг [требует проверки: норма / практика]).\n\n"
    )
    return header + "\n\n".join(parts)


def load_cases(limit=None, only_mode=None):
    cases = []
    with open(CASES_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            c = json.loads(line)
            if only_mode and c["mode"] != only_mode:
                continue
            cases.append(c)
    if limit:
        cases = cases[:limit]
    return cases


def build_user_prompt(case):
    return (
        MODE_INSTRUCTIONS[case["mode"]]
        + "\n\nТекст:\n"
        + case["input"]
    )


def grade_alias(case, output):
    """Быстрый детерминированный грейдинг по алиасам (морфологически устойчивый)."""
    norm = _norm(output)
    if case["expect"] == "clean":
        hit = (any(_norm(sig) in norm for sig in CLEAN_SIGNALS)
               or any(rx.search(norm) for rx in _CLEAN_RX))
        return hit, ("вердикт «чисто» найден" if hit else "не найден явный вердикт устойчивости/работы подачи")
    # expect == defect
    needles = list(case.get("aliases", []))
    if case.get("defect_lat"):
        needles.append(case["defect_lat"])
    if case.get("defect_ru"):
        needles.append(case["defect_ru"])
    matched = [n for n in needles if _hit(n, norm)]
    return (len(matched) > 0), ("совпало: " + ", ".join(matched[:3]) if matched else "ожидаемый дефект не назван")


JUDGE_SYSTEM = (
    "Ты — строгий проверяющий (грейдер) результатов риторического анализа юридической позиции. "
    "Тебе дают: ожидание и фактический ответ анализатора. Верни СТРОГО JSON "
    "{\"pass\": true|false, \"reason\": \"…\"} без пояснений вокруг."
)


def grade_llm(client, model, case, output):
    if case["expect"] == "clean":
        expectation = (
            "Ожидание: подача РАБОТАЕТ / позиция УСТОЙЧИВА / дефекта адресации или структуры НЕТ. "
            "pass=true, только если анализатор НЕ выдумал уязвимость и по сути согласился, что подача "
            f"корректна (допустимы флаги [требует проверки] и рекомендации по адаптации). Почему корректно: {case.get('why','')}"
        )
    else:
        expectation = (
            f"Ожидаемый дефект подачи: {case.get('defect_ru','')}. "
            f"Синонимы: {', '.join(case.get('aliases', []))}. "
            f"Суть: {case.get('why','')}. "
            "pass=true, если анализатор по существу выявил именно этот дефект подачи (имя может отличаться формулировкой)."
        )
    user = (
        f"{expectation}\n\nФактический ответ анализатора:\n<<<\n{output}\n>>>\n\n"
        "Верни только JSON {\"pass\": …, \"reason\": …}."
    )
    msg = client.messages.create(
        model=model, max_tokens=400,
        system=JUDGE_SYSTEM,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
    try:
        start, end = text.find("{"), text.rfind("}")
        obj = json.loads(text[start:end + 1])
        return bool(obj.get("pass")), str(obj.get("reason", ""))
    except Exception:
        return False, f"судья вернул неразборчивый ответ: {text[:120]}"


def call_model(client, model, system_blocks, case, effort):
    """Один прогон примера. Возвращает текст ответа модели."""
    kwargs = dict(
        model=model,
        max_tokens=2000,
        system=system_blocks,
        messages=[{"role": "user", "content": build_user_prompt(case)}],
    )
    # Пробуем adaptive thinking + effort (новые SDK/модели); при отказе — без них.
    if effort:
        try:
            msg = client.messages.create(
                thinking={"type": "adaptive"},
                output_config={"effort": effort},
                **kwargs,
            )
            return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()
        except TypeError:
            pass  # старый SDK не знает этих параметров
        except Exception as e:
            if "thinking" not in str(e) and "output_config" not in str(e) and "effort" not in str(e):
                raise
    msg = client.messages.create(**kwargs)
    return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text").strip()


def main():
    ap = argparse.ArgumentParser(description="E2E-прогон pravo-ritorika по cases.jsonl")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--limit", type=int, default=None, help="прогнать только первые N примеров")
    ap.add_argument("--mode", choices=["stress-test", "status", "structure", "adapt"], default=None)
    ap.add_argument("--grader", choices=["alias", "llm"], default="alias",
                    help="alias — быстрый детерминированный; llm — вызов-судья (точнее для clean)")
    ap.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], default="high")
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--out", default=os.path.join(HERE, "results.json"))
    ap.add_argument("--dry-run", action="store_true", help="без сети: собрать промпты и выйти")
    args = ap.parse_args()

    cases = load_cases(limit=args.limit, only_mode=args.mode)
    system_text = read_skill_context()
    # Кэшируем большой неизменный системный контекст.
    system_blocks = [{"type": "text", "text": system_text,
                      "cache_control": {"type": "ephemeral"}}]

    if args.dry_run:
        print(f"[dry-run] примеров: {len(cases)}; системный контекст: {len(system_text)} символов "
              f"(~{len(system_text)//4} токенов, кэшируется)")
        ex = cases[0]
        print(f"[dry-run] пример {ex['id']} ({ex['mode']}):\n{build_user_prompt(ex)[:400]}…")
        print("[dry-run] сеть не вызывалась. Экспортируйте ANTHROPIC_API_KEY и уберите --dry-run для реального прогона.")
        return 0

    try:
        import anthropic
    except ImportError:
        print("Не установлен пакет anthropic:  pip install anthropic", file=sys.stderr)
        return 2
    client = anthropic.Anthropic()  # берёт ключ из окружения / профиля ant

    def run_one(case):
        try:
            output = call_model(client, args.model, system_blocks, case, args.effort)
        except Exception as e:
            return {"id": case["id"], "mode": case["mode"], "category": case["category"],
                    "expect": case["expect"], "passed": False, "error": str(e), "output": ""}
        if args.grader == "llm":
            ok, reason = grade_llm(client, args.model, case, output)
        else:
            ok, reason = grade_alias(case, output)
        return {"id": case["id"], "mode": case["mode"], "category": case["category"],
                "expect": case["expect"], "passed": ok, "reason": reason, "output": output}

    results = []
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        for r in ex.map(run_one, cases):
            results.append(r)
            mark = "PASS" if r["passed"] else "FAIL"
            print(f"[{mark}] {r['id']:<4} {r['mode']:<12} {r.get('reason', r.get('error',''))[:80]}")

    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    # Разбивка по разделам каталога (первая буква id).
    from collections import Counter
    sect_total, sect_pass = Counter(), Counter()
    for r in results:
        s = r["id"][0]
        sect_total[s] += 1
        sect_pass[s] += int(r["passed"])

    print("\n===== ИТОГ =====")
    print(f"Всего: {passed}/{total}  ({100*passed/max(total,1):.0f}%)  модель={args.model}  грейдер={args.grader}")
    for s in sorted(sect_total):
        print(f"  раздел {s}: {sect_pass[s]}/{sect_total[s]}")

    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"model": args.model, "grader": args.grader,
                   "passed": passed, "total": total, "results": results},
                  f, ensure_ascii=False, indent=2)
    print(f"\nПодробности: {args.out}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
