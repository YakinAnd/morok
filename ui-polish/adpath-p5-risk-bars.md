# adpath HTML report — P5 micro fix: proportional risk contribution bars

## Контекст
- Файл: `internal/report/html.go` (template — Summary tab risk score breakdown block)
- Можливо також: `internal/report/score.go` (для FuncMap helper)
- Поточна версія: v0.9.9

## Проблема

Зараз у Summary tab блок "Risk contribution by category" показує бари з **відносною** шириною (% від cap кожної категорії). Це візуально вводить в оману.

Приклад поточного рендеру:

| Category       | Score | Cap | Bar width |
|----------------|-------|-----|-----------|
| Attack Paths   | 30    | 30  | **100%**  |
| Dangerous ACLs | 20    | 20  | **100%**  |
| Shadow Creds   | 9     | 10  | **90%**   |
| ADCS           | 10    | 20  | **50%**   |
| Stale Admins   | 6     | 10  | **60%**   |
| No LAPS        | 3     | 5   | **60%**   |
| Policy         | 5     | 15  | **33%**   |

Око читає "Shadow Creds (9 points) майже такий же страшний як Attack Paths (30 points)" — бо бари обидва майже повні. Насправді Attack Paths дає **втричі більше ризику**. Заголовок каже "Risk contribution" — але візуалізація показує "% of cap", не contribution.

## Фікс: бари пропорційні **абсолютному внеску** в total score

Максимум бара = найбільший cap серед усіх категорій (зараз 30 — Attack Paths). Інші категорії показуються пропорційно меншою довжиною — бо їхній максимально можливий внесок в total score менший.

### Крок 1. FuncMap helpers

В `internal/report/html.go` (де ініціалізується template) додай у FuncMap (якщо `capFor` ще немає — додай теж):

```go
funcMap := template.FuncMap{
    // ... existing helpers ...

    "capFor": func(cat string) int {
        caps := map[string]int{
            "Attack Paths":    30,
            "Dangerous ACLs":  20,
            "Kerberoasting":   15,
            "AS-REP Roasting": 10,
            "Delegation":      15,
            "ADCS":            20,
            "Policy":          15,
            "Stale Admins":    10,
            "No LAPS":         5,
            "Shadow Creds":    10,
        }
        return caps[cat]
    },

    // Width as % of the largest cap across ALL categories (currently 30).
    // This makes a score of 30 take 100% width and a score of 5 take ~17% width,
    // making absolute contributions visually comparable.
    "barWidthAbsolute": func(score int) int {
        const maxCap = 30  // largest cap in the system
        if score <= 0 {
            return 0
        }
        width := score * 100 / maxCap
        if width < 2 && score > 0 {
            return 2  // minimum visible width for non-zero scores
        }
        if width > 100 {
            return 100
        }
        return width
    },

    // Color depends on % of category's own cap (high fill = critical for that category)
    "barColor": func(score int, cat string) template.CSS {
        caps := map[string]int{
            "Attack Paths": 30, "Dangerous ACLs": 20, "Kerberoasting": 15,
            "AS-REP Roasting": 10, "Delegation": 15, "ADCS": 20,
            "Policy": 15, "Stale Admins": 10, "No LAPS": 5, "Shadow Creds": 10,
        }
        cap := caps[cat]
        if cap == 0 {
            return template.CSS("var(--text-sev-medium)")
        }
        pct := score * 100 / cap
        switch {
        case pct >= 75:
            return template.CSS("var(--text-sev-critical)")
        case pct >= 40:
            return template.CSS("var(--text-sev-high)")
        default:
            return template.CSS("var(--text-sev-medium)")
        }
    },
}
```

`template.CSS` тут важливий — інакше отримаємо `ZgotmplZ` (той самий клас bug'ів що в P3 #1).

### Крок 2. Заміни template блок Summary tab risk breakdown

Знайди блок (приблизно рядки 549-610 в згенерованому HTML, в template — секція "Risk contribution by category"):

```html
<div style="font-size:0.85rem;color:var(--text-muted);margin-bottom:12px">Risk contribution by category</div>
<div style="display:flex;flex-direction:column;gap:6px">

  {{range $cat, $score := .RiskScore.Breakdown}}
  {{if gt $score 0}}
  <div style="display:flex;align-items:center;gap:12px;font-size:0.82rem">
    <div style="width:140px;color:var(--text-secondary)">{{$cat}}</div>
    <div style="flex:1;background:var(--bg-hover);border-radius:3px;height:6px;overflow:hidden">
      <div style="width:{{$score}}%;height:100%;background:var(--text-sev-critical)"></div>
    </div>
    <div style="width:30px;text-align:right;color:var(--text-main);font-weight:600">{{$score}}</div>
  </div>
  {{end}}
  {{end}}

</div>
```

Заміни на:

```html
<div style="font-size:0.85rem;color:var(--text-muted);margin-bottom:4px">
  Risk contribution by category
</div>
<div style="font-size:0.72rem;color:var(--text-subtle);margin-bottom:12px">
  Bar length is proportional to absolute risk points contributed.
  Color reflects how close each category is to its maximum.
</div>

<div style="display:flex;flex-direction:column;gap:6px">

  {{range $cat, $score := .RiskScore.SortedBreakdown}}
  {{if gt $score.Value 0}}
  <div style="display:flex;align-items:center;gap:12px;font-size:0.82rem">
    <div style="width:140px;color:var(--text-secondary)">{{$score.Name}}</div>
    <div style="flex:1;background:var(--bg-hover);border-radius:3px;height:6px;overflow:hidden">
      <div style="width:{{barWidthAbsolute $score.Value}}%;height:100%;
        background:{{barColor $score.Value $score.Name}};transition:width 0.3s"></div>
    </div>
    <div style="width:64px;text-align:right;color:var(--text-main);font-weight:600;font-variant-numeric:tabular-nums">
      {{$score.Value}}<span style="color:var(--text-muted);font-weight:400">/{{capFor $score.Name}}</span>
    </div>
  </div>
  {{end}}
  {{end}}

</div>
```

Зміни в template:
- Двохрядкова шапка з пояснення про значення довжини і кольору (короткий disclaimer щоб readers не плутались)
- `barWidthAbsolute` замість `{{$score}}%` — тепер 30 = 100% width, 5 = ~17% width
- `barColor` замість завжди-критичного — три-рівневий gradient за % cap
- Колонка справа показує `30/30` замість просто `30` — додає cap context
- `tabular-nums` щоб числа вирівнювались
- `transition:width 0.3s` — м'яка анімація при зміні даних (приємно при `--diff` mode у майбутньому)

### Крок 3. Сортування — найбільший внесок зверху

Зараз `Breakdown` рендериться через `range $cat, $score :=` що в Go templates **не гарантує порядок** для `map`. Тому черговість категорій рандомна між запусками. Це баг — кожен новий звіт показує бари в іншому порядку.

В `internal/report/score.go` додай метод що повертає sorted slice:

```go
type BreakdownEntry struct {
    Name  string
    Value int
}

func (r RiskScore) SortedBreakdown() []BreakdownEntry {
    entries := make([]BreakdownEntry, 0, len(r.Breakdown))
    for name, value := range r.Breakdown {
        entries = append(entries, BreakdownEntry{Name: name, Value: value})
    }
    // Descending by value — largest contribution first
    sort.SliceStable(entries, func(i, j int) bool {
        if entries[i].Value != entries[j].Value {
            return entries[i].Value > entries[j].Value
        }
        return entries[i].Name < entries[j].Name  // stable tie-break by name
    })
    return entries
}
```

Це гарантує що Attack Paths (30) завжди зверху, потім ACLs (20), потім ADCS (10) і т.д. Ще й читачу легше — найважливіше першим.

## Перевірка

```bash
go build ./...
./adpath enum -d sevenkingdoms.local -u user -p pass -o /tmp/test.html
```

Відкрий звіт, Summary tab, переглянь Risk contribution блок:

1. ✅ Категорії посортовані за score спадаючи (Attack Paths першим зі score 30)
2. ✅ Attack Paths бар максимально довгий (~100%), Policy бар короткий (~17%)
3. ✅ Кольори різні: Attack Paths/ACLs червоні (maxed), No LAPS оранжевий (60% cap), Policy жовтий (33% cap)
4. ✅ Числа справа в форматі `30/30`, `20/20`, `5/15`
5. ✅ Між запусками — однаковий порядок категорій
6. ✅ Немає `ZgotmplZ` у згенерованому HTML

Sanity-check для логіки:
```bash
grep -A 1 "barWidthAbsolute\|risk contribution" /tmp/test.html | head -30
```

## Commit

```
fix(report): make risk contribution bars proportional to absolute contribution

Bar length now reflects absolute points contributed to total risk score
(max bar = largest cap of 30), not relative % within each category's cap.
Color encodes how close category is to its own maximum (gradient by % cap).

This prevents misleading visualizations where Shadow Creds (9 points,
90% of its cap) appeared comparable to Attack Paths (30 points, 100% of
much larger cap) — when in absolute terms Attack Paths contributes 3x more.

Also:
- Sort breakdown by score descending for stable, prioritized rendering
- Show /cap suffix (e.g. "30/30") for clearer interpretation
- Add brief explanation under section heading
```
