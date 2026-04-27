# adpath HTML report — P1 UX improvements

Продовження роботи над `internal/report/html.go`. P0 фікси вже застосовані. Тепер UX-покращення які підвищують professional perception звіту.

## Завдання

### 1. Copy button для exploit команд

Кожен `.acc-cmd` блок повинен мати copy button. У HTML темплейті заміни:

```html
<span class="acc-cmd">{{.Command}}</span>
```

на:

```html
<div class="acc-cmd-wrap">
  <code class="acc-cmd">{{.Command}}</code>
  <button class="acc-cmd-copy" onclick="copyCmd(this)" title="Copy to clipboard">📋</button>
</div>
```

В CSS додай:
```css
.acc-cmd-wrap { position: relative; display: block; margin-top: 4px; }
.acc-cmd-wrap .acc-cmd { display: block; padding-right: 36px; }
.acc-cmd-copy { position: absolute; top: 4px; right: 4px; background: transparent;
  border: 1px solid var(--border); border-radius: 4px; color: var(--text-muted);
  padding: 2px 6px; cursor: pointer; font-size: 0.75rem; transition: all 0.15s; }
.acc-cmd-copy:hover { color: var(--accent); border-color: var(--accent); }
.acc-cmd-copy.copied { color: var(--color-ok); border-color: var(--color-ok); }
```

В JS додай:
```javascript
function copyCmd(btn) {
  const cmd = btn.previousElementSibling.textContent;
  navigator.clipboard.writeText(cmd).then(function() {
    btn.classList.add('copied');
    btn.textContent = '✓';
    setTimeout(function() {
      btn.classList.remove('copied');
      btn.textContent = '📋';
    }, 1500);
  }).catch(function() {
    btn.textContent = '✗';
  });
}
```

Також полагодь `word-break` в `.acc-cmd` — заміни `word-break: break-all` на:
```css
word-break: break-word;
white-space: pre-wrap;
```

Це збереже читабельність команд (ламатиме по пробілах, а не посередині слова).

### 2. Pagination/lazy render для ACL findings

При 5000+ ACL findings на реальному enterprise AD сторінка ляже. У `buildGroupedACL()` додай rendering limit per group:

```javascript
const _ACL_GROUP_LIMIT = 50;

// В forEach по cards в group:
g.cards.forEach(function(card, idx) {
  var clone = card.cloneNode(true);
  clone.style.display = '';
  if (idx >= _ACL_GROUP_LIMIT) {
    clone.classList.add('acl-hidden-overflow');
    clone.style.display = 'none';
  }
  body.appendChild(clone);
});

if (g.cards.length > _ACL_GROUP_LIMIT) {
  const showMore = document.createElement('button');
  showMore.className = 'show-all-btn';
  showMore.textContent = 'Show ' + (g.cards.length - _ACL_GROUP_LIMIT) + ' more in this group';
  showMore.onclick = function() {
    body.querySelectorAll('.acl-hidden-overflow').forEach(function(el) {
      el.style.display = '';
    });
    showMore.remove();
  };
  body.appendChild(showMore);
}
```

Також зроби всі ACL groups **collapsed by default** при кількості груп > 3 (інакше при відкритті вкладки рендеряться всі 72+ карток одразу). У header.onclick init вже є логіка — додай після `container.innerHTML = '';`:

```javascript
const collapseByDefault = order.length > 3;
```

І в forEach по order, після створення body:
```javascript
if (collapseByDefault) {
  body.style.display = 'none';
  const ch = header.querySelector('.group-chevron');
  if (ch) ch.innerHTML = '&#9658;';
}
```

### 3. ARIA атрибути для accessibility

#### Tab navigation
В `.nav` секції зміни структуру:
```html
<div class="nav" role="tablist">
  <button role="tab" aria-selected="true" aria-controls="tab-summary" id="tab-btn-summary"
    class="active" onclick="showTab('summary')">Summary</button>
  <button role="tab" aria-selected="false" aria-controls="tab-paths" id="tab-btn-paths"
    onclick="showTab('paths')">Attack Paths (5)</button>
  <!-- решта аналогічно -->
</div>
```

Кожна `.tab-pane` отримує:
```html
<div id="tab-summary" class="tab-pane active" role="tabpanel"
  aria-labelledby="tab-btn-summary" tabindex="0">
```

У JS функції `showTab`:
```javascript
function showTab(name) {
  document.querySelectorAll('.tab-pane').forEach(function(el) {
    el.classList.remove('active');
    el.setAttribute('aria-hidden', 'true');
  });
  document.querySelectorAll('.nav button').forEach(function(el) {
    el.classList.remove('active');
    el.setAttribute('aria-selected', 'false');
  });
  const pane = document.getElementById('tab-' + name);
  const btn = document.getElementById('tab-btn-' + name);
  if (pane) { pane.classList.add('active'); pane.setAttribute('aria-hidden', 'false'); }
  if (btn) { btn.classList.add('active'); btn.setAttribute('aria-selected', 'true'); }
}
```

#### Accordions
Заміни всі `.acc-toggle` button:
```html
<button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false">
  ▶ &nbsp;🔴 Exploit &nbsp;/&nbsp; 🛡 Fix
</button>
```

В `toggleAcc`:
```javascript
function toggleAcc(btn) {
  const body = btn.nextElementSibling;
  const isOpen = body.classList.contains('open');
  body.classList.toggle('open');
  btn.setAttribute('aria-expanded', String(!isOpen));
  // ... rest of existing logic
}
```

#### Search input
```html
<input id="gs-input" type="text" aria-label="Global search across all report tabs"
  placeholder="🔍  Global search across all tabs..." ...>
```

#### Theme toggle
```html
<button id="theme-toggle" onclick="toggleTheme()" aria-label="Toggle dark/light theme"
  title="Toggle light/dark mode">🌙</button>
```

#### Help icons
```html
<span class="help-icon" role="tooltip" tabindex="0" data-tip="...">?</span>
```

### 4. Замінити emoji на inline SVG (path nodes + accordion icons)

Емодзі `👤 👥 🔴 🛡 ▶ 📋` рендеряться нестабільно крос-платформно. Заміни на inline SVG.

Створи в темплейті reusable SVG snippets (можеш зробити Go template helpers або просто константи):

```html
<!-- User icon (was 👤) -->
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
  stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">
  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
  <circle cx="12" cy="7" r="4"/>
</svg>

<!-- Group icon (was 👥) -->
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
  stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0">
  <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
  <circle cx="9" cy="7" r="4"/>
  <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
  <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
</svg>

<!-- Computer icon -->
<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
  stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
  <line x1="8" y1="21" x2="16" y2="21"/>
  <line x1="12" y1="17" x2="12" y2="21"/>
</svg>
```

Замість `🔴 Exploit / 🛡 Fix` зроби чистіше:
```html
<button class="acc-toggle" onclick="toggleAcc(this)" aria-expanded="false">
  <span class="acc-chevron">▶</span>
  <span style="color:var(--text-sev-critical);font-weight:600">Exploit</span>
  <span style="color:var(--text-muted)">/</span>
  <span style="color:var(--color-ok);font-weight:600">Remediation</span>
</button>
```

В Go — type для `NodeType` (User/Group/Computer) і шаблон рендерить відповідну SVG. Якщо вже є — просто рефактор.

### 5. Footer

Перед `</body>` додай:
```html
<footer style="text-align:center;padding:20px 40px;border-top:1px solid var(--border);
  color:var(--text-muted);font-size:0.8rem;margin-top:40px">
  Generated by <a href="https://github.com/YakinAnd/adpath" target="_blank" rel="noopener"
    style="color:var(--accent);text-decoration:none">adpath v{{.Version}}</a>
  · {{.Timestamp}} · Active Directory Attack Path Analysis
</footer>
```

Передай `Version` з `cmd/adpath/main.go` (де у тебе вже є version constant).

### 6. Уніфікувати фіолетовий колір

В лого SVG (`#7c3aed`, `#5b21b6`, `#a855f7`, `#4c1d95`) і в `.header-logo-name em { color: #9b5ffe; }` — зведи до однієї палітри. Рекомендую:

```css
:root {
  --brand-primary: #7c3aed;
  --brand-light:   #a78bfa;
  --brand-dark:    #5b21b6;
}
```

І замість inline `#9b5ffe` в `em` стилі:
```css
.header-logo-name em { color: var(--brand-primary); font-style: normal; }
```

В лого SVG залишай hardcoded бо це brand asset, але переконайся що все з тієї ж палітри.

## Перевірка

1. `go build ./...`
2. Запусти на test AD з 5000+ ACL findings (можна синтетично згенерувати) — сторінка має відкриватись швидко
3. Lighthouse audit в Chrome DevTools → Accessibility score має бути ≥90
4. Tab keyboard navigation працює (Tab/Shift+Tab проходить по nav buttons, Enter відкриває)
5. Screen reader (NVDA/VoiceOver) озвучує "Tab, Attack Paths, 5, selected"
6. Copy button копіює exploit command, показує ✓ на 1.5s
7. Commit: `feat(report): a11y improvements, copy buttons, lazy ACL render (P1)`
