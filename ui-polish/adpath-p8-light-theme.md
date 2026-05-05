# adpath HTML report — P8 fix: light theme broken colors

При перевірці звіту в light theme знайдено 7 hardcoded color значень які залишились з dark mode. У світлій темі вони виглядають невідповідно: жовто-коричневі плями на білому фоні, текст що зливається з background, інконсистентність severity кольорів між border і text.

## Контекст
- Файл: `internal/report/html.go` (template — CSS block + embedded JavaScript)
- Поточна версія: v0.9.9
- Test: відкрий звіт у браузері, переключи `🌙 → ☀️`, переглянь severity tables, graph tooltip, search highlight

---

## 🔴 Issue #1: severity row borders — hardcoded dark-theme hex

### Проблема

```css
tr.row-critical td:first-child { border-left: 3px solid #e53e3e; }
tr.row-high     td:first-child { border-left: 3px solid #dd6b20; }
tr.row-medium   td:first-child { border-left: 3px solid #d69e2e; }
tr.row-low      td:first-child { border-left: 3px solid #68d391; }
```

Це dark-theme hex значення. У light theme severity **тексти** використовують `--text-sev-*` (`#c53030`, `#c2410c`, `#92400e`), а **border** залишається тим самим яскравим dark-orange/yellow. У результаті в одному рядку:
- text "High" — темно-помаранчевий `#c2410c` ✓
- border-left того ж рядка — світлий `#dd6b20` ✗

Дві різні "помаранчеві" в одному UI елементі.

### Фікс

Заміни в CSS блоці на CSS variables:

```css
tr.row-critical td:first-child { border-left: 3px solid var(--text-sev-critical); }
tr.row-high     td:first-child { border-left: 3px solid var(--text-sev-high); }
tr.row-medium   td:first-child { border-left: 3px solid var(--text-sev-medium); }
tr.row-low      td:first-child { border-left: 3px solid var(--color-ok); }
```

Тепер border автоматично адаптується до theme.

---

## 🔴 Issue #2: `.card.critical .value` hardcoded red

### Проблема

```css
.card.critical .value { color: #e53e3e; }
```

`#e53e3e` — bright red який добре читається на dark. У light theme на білому background він має contrast ~3.5:1 — на межі WCAG AA для bold text. Інші severity класи (`.sev-critical`, `.sev-high`) уже використовують CSS variables — цей не апдейтився.

### Фікс

```css
.card.critical .value { color: var(--text-sev-critical); }
```

Перевір також `.card.warning .value` і `.card.ok .value` — вони вже мають правильно `var(--text-sev-high)` і `var(--color-ok)`. Залишається лише `.critical`.

---

## 🔴 Issue #3: graph node tooltip — повністю hardcoded dark badges

### Проблема

В embedded JavaScript:

```javascript
(d.adminCount ? '<span style="background:#742a2a;color:#e53e3e;padding:2px 6px;border-radius:3px;font-size:11px">Admin</span>' : '') +
(d.kerberoastable ? '<span style="background:#744210;color:#dd6b20;padding:2px 6px;border-radius:3px;font-size:11px">Kerberoastable</span>' : '') +
(d.asrepRoastable ? '<span style="background:#742a2a;color:#feb2b2;padding:2px 6px;border-radius:3px;font-size:11px">AS-REP</span>' : '') +
```

Тут `#742a2a` (темно-бордовий) і `#744210` (коричневий) — це **dark-theme badge backgrounds**. У light theme на білому фоні це **великі темно-коричневі плями** з помаранчевим текстом всередині. Виглядає як bug рендерингу.

### Фікс

Використай існуючі `.badge-*` CSS classes які вже theme-aware:

```javascript
(d.adminCount ? '<span class="badge badge-critical">Admin</span>' : '') +
(d.kerberoastable ? '<span class="badge badge-medium">Kerberoastable</span>' : '') +
(d.asrepRoastable ? '<span class="badge badge-high">AS-REP</span>' : '') +
```

Класи `.badge-critical/.badge-medium/.badge-high` вже визначені з `--badge-*-bg/txt` для обох theme. Це найчистіший фікс.

Якщо `.badge-*` стилі мають іншу padding/font-size (більший відступ ніж потрібно для tooltip), додай інлайн override:

```javascript
'<span class="badge badge-critical" style="padding:2px 6px;font-size:11px">Admin</span>'
```

Або створи окремий клас `.tooltip-badge` з потрібним розміром.

---

## 🔴 Issue #4: graph legend dots — hardcoded blue/purple

### Проблема

```html
<span style="color:#b794f4">●</span> Group &nbsp;
<span style="color:#90cdf4">●</span> Computer &nbsp;
<span style="color:#63b3ed">●</span> User
```

`#b794f4` (light-purple), `#90cdf4` (light-blue), `#63b3ed` (mid-blue) — це **pastel-колори для dark theme**. На світлому фоні `#f0f4f8`:
- `#90cdf4` (Computer) — майже зливається з фоном, ледь видно
- `#b794f4` (Group) — теж блідий

### Фікс

Створи CSS variables для node-кольорів. У `:root` блоці на самому верху додай нічого, в кожній theme — окремі набори:

```css
html[data-theme="dark"] {
  /* ...existing variables... */
  --node-user:     #63b3ed;
  --node-computer: #90cdf4;
  --node-group:    #b794f4;
  --node-admin:    #fc8181;
}
html[data-theme="light"] {
  /* ...existing variables... */
  --node-user:     #2b6cb0;
  --node-computer: #2c5282;
  --node-group:    #6b46c1;
  --node-admin:    #c53030;
}
```

Заміни inline у legend:

```html
<span style="color:var(--node-group)">●</span> Group &nbsp;
<span style="color:var(--node-computer)">●</span> Computer &nbsp;
<span style="color:var(--node-user)">●</span> User
```

Перевір також JavaScript який рендерить self ці nodes у D3 graph (`d3.select(...).attr('fill', ...)`). Якщо там теж hardcoded — заміни на CSS variables. У JS читай так:

```javascript
const nodeColors = {
  user:     getComputedStyle(document.documentElement).getPropertyValue('--node-user').trim(),
  computer: getComputedStyle(document.documentElement).getPropertyValue('--node-computer').trim(),
  group:    getComputedStyle(document.documentElement).getPropertyValue('--node-group').trim(),
  admin:    getComputedStyle(document.documentElement).getPropertyValue('--node-admin').trim(),
};
// usage: nodeColors[d.type]
```

ВАЖЛИВО: при перемиканні theme через `toggleTheme()` додай invalidation — якщо nodes уже намальовані, перерендер їх з оновленими кольорами:

```javascript
function toggleTheme() {
  const html = document.documentElement;
  const newTheme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', newTheme);
  localStorage.setItem('adpath-theme', newTheme);
  // Re-render graph if it was drawn
  if (window._graphRendered && typeof renderGraph === 'function') {
    renderGraph();  // або equivalent функція що redraws
  }
}
```

---

## ⚠️ Issue #5: dead variable `--sev-medium`

### Проблема

```css
/* Dark */ --sev-medium: #faf089;
/* Light */ --sev-medium: #b7791f;
```

Ця змінна визначена в обох theme, але ніде не читається. Усе severity-text використовує `--text-sev-medium` (з префіксом `text-`). Залишилась з минулих ітерацій — створює confusion при code review.

### Фікс

Видали обидва рядки:

```css
/* з обох html[data-theme="..."] блоків видалити: */
--sev-medium:    #faf089;     /* dark */
--sev-medium:    #b7791f;     /* light */
```

Перевір через grep:

```bash
grep -rn "var(--sev-medium)" internal/  # має бути 0 збігів
grep -rn "\-\-sev-medium:" internal/    # має бути 0 збігів після видалення
```

Якщо grep знайде використання — спочатку заміни їх на `var(--text-sev-medium)`, потім видали defining-рядки.

---

## ⚠️ Issue #6: search highlight `<mark>` hardcoded yellow

### Проблема

```javascript
m => '<mark style="background:#f6e05e;color:#1a202c;border-radius:2px;padding:0 1px">' + m + '</mark>'
```

`#f6e05e` працює в обох theme (читається), але стилістично не з brand palette. У dark — норм, у light — занадто bright proти ніжного `#f0f4f8` background, виглядає як спам-highlight.

### Фікс

Додай у обидві theme:

```css
/* Dark */
--mark-bg:  #f6e05e;
--mark-txt: #1a202c;

/* Light */
--mark-bg:  #fef08a;
--mark-txt: #1a202c;
```

Заміни inline:

```javascript
m => '<mark style="background:var(--mark-bg);color:var(--mark-txt);border-radius:2px;padding:0 1px">' + m + '</mark>'
```

---

## ⚠️ Issue #7: findings chart count text — hardcoded white

### Проблема

```javascript
(f.count > 0 ? '<span style="font-size:11px;font-weight:600;color:#fff;text-shadow:0 1px 2px rgba(0,0,0,.4)">'+f.count+'</span>' : '')
```

`color: #fff` (white) працює в dark theme (бар fill темний). У light, якщо bar fill став світло-рожевим/жовтим (`--badge-crit-bg: #fed7d7`), white text **зникає** на ньому повністю.

### Фікс

Використай contrast-aware color. У light theme bar fills світлі — текст має бути темний. У dark bar fills темні — текст білий. Простіше через CSS variable:

```css
/* Dark */ --chart-count-txt: #ffffff;
/* Light */ --chart-count-txt: #1a202c;
```

JS:
```javascript
(f.count > 0 ? '<span style="font-size:11px;font-weight:600;color:var(--chart-count-txt);text-shadow:0 1px 2px rgba(0,0,0,.4)">'+f.count+'</span>' : '')
```

`text-shadow` залишається — на dark створює субтильний glow, на light дає легку тінь під цифрою.

Альтернатива — взагалі видалити цифру **на барі**, винести її **за бар** як label справа:

```
Critical [████████████        ] 38
High     [██████████          ] 40
Medium   [█                   ]  1
```

Це працює універсально для будь-якого theme, нічого не зливається.

---

## ✅ Не баги, але варто перевірити

### Issue #8: `--accent-domain: #c05621` для light theme

```css
/* Light */ --accent-domain: #c05621;  /* dark-orange / brown */
```

У header `sevenkingdoms.local` рендериться цим кольором. На білому background `#c05621` виглядає **brown-orange**, не як accent. Якщо це навмисно для contrast — лиши. Якщо ти очікував "помаранчевий" — заміни на `#dd6b20` або `#ed8936` (більш orange, менш brown).

Спитай себе: чи має domain name виглядати **помаранчевим** як accent (`#ed8936`-ish), чи **темно-теракотовим** як зараз (`#c05621`)? Це дизайнерське рішення, не bug.

### Issue #9: `.cvss-score` text contrast

```css
.cvss-score { color: var(--text-secondary); }
[data-theme="light"] .cvss-score { background: rgba(0,0,0,0.05); }
```

У light: `var(--text-secondary)` = `#718096` (середньо-сірий) на background `rgba(0,0,0,0.05)` (~`#f2f2f2`). Contrast ≈ 3.4:1. Для small text (11px) — **fail WCAG AA**.

### Фікс

Підвищ contrast у light theme:

```css
[data-theme="light"] .cvss-score {
  background: rgba(0,0,0,0.05);
  border-color: rgba(0,0,0,0.12);
  color: var(--text-main);  /* #1a202c — повний contrast */
}
```

---

## Перевірка після всіх фіксів

```bash
go build ./...
./adpath enum -d sevenkingdoms.local -u admin -p '...' --dc ... --report /tmp/test.html
```

Відкрий `/tmp/test.html` у браузері, переключи на light theme, перевір:

1. ✅ **Severity tables**: text і border-left однакового відтінку (`Critical` text + border red)
2. ✅ **Critical card** на Executive: число `38` темно-червоне (`#c53030`), не bright `#e53e3e`
3. ✅ **Graph tooltip** на наведенні на ноду: badges типу `Admin`, `Kerberoastable` мають світлі pastel backgrounds замість темно-бордових плям
4. ✅ **Graph legend**: dots для User/Computer/Group чітко видні на світлому фоні
5. ✅ **Search**: highlight через `<mark>` приглушений жовтий, не "крик"
6. ✅ **Findings chart**: count числа на барах читаються (не зливаються з світлим bar fill)
7. ✅ **CVSS scores**: текст темний, добре читається

Sanity grep:

```bash
# Жодного hardcoded severity hex в CSS і JS:
grep -E "color:\s*#(e53e3e|dd6b20|d69e2e|68d391|f6ad55|faf089)" internal/report/html.go
grep -E "background:\s*#(742a2a|744210|7b2d12|1c4532)" internal/report/html.go
# Очікується: 0 збігів (всі через --text-sev-* або --badge-*-* variables)

# Dead variable видалено:
grep -E "\-\-sev-medium\s*:" internal/report/html.go
# Очікується: 0 збігів (--sev-medium without "text-" prefix)
```

Toggle test:

```javascript
// В браузері DevTools console:
document.documentElement.setAttribute('data-theme', 'light');
// Прокрутити весь звіт — нічого не має "ламатись"
document.documentElement.setAttribute('data-theme', 'dark');
// Те саме
```

## Commit

```
fix(report): consistent severity colors and theme-aware UI elements

Several hardcoded dark-theme hex values caused visual inconsistency in
light theme: severity row borders mismatched their text colors,
graph tooltip badges rendered as dark-brown blobs on white background,
legend dots faded into light page background.

Fixed:
- tr.row-* borders use --text-sev-* variables instead of hex
- .card.critical .value uses --text-sev-critical
- Graph tooltip badges use existing .badge-* CSS classes
- Graph legend + node fills use new --node-{user,computer,group,admin} vars
- Search highlight <mark> uses new --mark-{bg,txt} vars
- Findings chart count text uses --chart-count-txt for contrast
- .cvss-score text uses --text-main in light theme for AA contrast
- Removed dead --sev-medium variable (replaced by --text-sev-medium long ago)

Verified by toggling theme and scrolling all tabs — no broken colors.
```
