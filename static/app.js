/* Proxy Bot — frontend */

// ── Темы: system / dark / light ──────────────────────────────────────────────
function _injectThemeToggle() {
  if (document.getElementById('theme-toggle')) return;
  const badge = document.getElementById('user-badge');
  if (!badge) return;
  const btn = document.createElement('button');
  btn.id          = 'theme-toggle';
  btn.className   = 'theme-toggle-btn';
  btn.type        = 'button';
  btn.onclick     = () => ProxyTheme.cycle();
  badge.parentElement.insertBefore(btn, badge);
  ProxyTheme.apply(ProxyTheme.read());
}

let refreshTimer = null;
let pollTimer    = null;
let botUsername  = '';
let _checkRunning = false;
let findSkipIds = new Set();
let navigationVersion = 0;
let proxyLoadVersion = 0;
let accessProgressTimers = [];

// ── Фильтры прокси ────────────────────────────────────────────────────────────
let filterRegion = 'all';
let filterType   = 'all';
let filterSort   = 'recommended';
let filterNetwork = 'unknown';

// ── Таймер (абсолютный, хранится в localStorage) ─────────────────────────────
const TIMER_KEY = 'proxyNextAt';

function setNextUpdateAt(secondsFromNow) {
  const ts = Date.now() + secondsFromNow * 1000;
  try { localStorage.setItem(TIMER_KEY, String(ts)); } catch {}
}

function getSecondsLeft() {
  try {
    const stored = parseInt(localStorage.getItem(TIMER_KEY) || '0', 10);
    if (!stored) return 0;
    return Math.max(0, Math.ceil((stored - Date.now()) / 1000));
  } catch { return 0; }
}

// ── Утилиты ───────────────────────────────────────────────────────────────────
const esc = s =>
  String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
           .replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');

function safePhotoUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return '';
  try {
    const url = new URL(String(value || ''), location.origin);
    return url.protocol === 'https:' || url.protocol === 'http:' && url.origin === location.origin ? url.href : '';
  } catch { return ''; }
}

document.addEventListener('error', event => {
  const img = event.target;
  if (!(img instanceof HTMLImageElement) || !img.matches('.badge-photo, .account-avatar-img')) return;
  const fallback = document.createElement('span');
  fallback.className = img.classList.contains('badge-photo') ? 'badge-avatar' : 'account-avatar-fallback';
  fallback.textContent = img.dataset.initial || 'П';
  img.replaceWith(fallback);
}, true);

function proxyUrl(proxy) {
  const server = String(proxy.server || proxy.host || '');
  const secret = String(proxy.secret || '');
  const port = Number(proxy.port);
  if (!server || server.length > 253 || !secret || secret.length > 1024 || !Number.isInteger(port) || port < 1 || port > 65535) return '';
  return 'tg://proxy?' + new URLSearchParams({server, port: String(port), secret});
}

function timeValue(value) {
  if (typeof value === 'number') return value > 1e12 ? value : value * 1000;
  const stamp = Date.parse(String(value || ''));
  return Number.isFinite(stamp) ? stamp : 0;
}

function evidenceInfo(proxy) {
  const evidence = proxy.evidence && typeof proxy.evidence === 'object' ? proxy.evidence : {};
  const level = String(evidence.level || 'none');
  let status = String(evidence.status || 'unverified');
  if (!['verified', 'stale', 'failed_here', 'failed', 'degraded', 'unverified'].includes(status)) status = 'unverified';
  const until = timeValue(evidence.valid_until);
  if (status === 'verified' && (!until || until <= Date.now())) status = 'stale';
  if (status === 'verified' && !['auth_key', 'auth-key', 'authenticated', 'full'].includes(level)) status = 'unverified';
  const labels = {verified: 'Протокол подтверждён', stale: 'Подтверждение устарело', failed_here: 'Не прошёл проверку здесь', failed: 'Не прошёл проверку', degraded: 'Результат нестабилен', unverified: 'Протокол не подтверждён'};
  const label = labels[status] || labels.unverified;
  const place = String(evidence.coverage_label || evidence.network_key || 'Место проверки не указано').slice(0, 200);
  const checked = timeValue(evidence.checked_at);
  const when = checked ? new Date(checked).toLocaleString('ru-RU', {day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit'}) : 'нет измерения';
  const duration = evidence.duration_ms == null ? NaN : Number(evidence.duration_ms);
  const timing = Number.isFinite(duration) && duration >= 0 ? Math.round(duration) + ' мс' : 'не измерен';
  return {status, label, place, when, timing, reasons: Array.isArray(evidence.reasons) ? evidence.reasons : []};
}

const APP_ROUTES = new Set(['/', '/login', '/register', '/app', '/account', '/subscribe', '/connect_proxy']);

function currentPath() {
  const path = window.location.pathname.replace(/\/+$/, '') || '/';
  return APP_ROUTES.has(path) ? path : '/';
}

function setPath(path, replace = false) {
  const url = new URL(path, location.origin);
  const pathname = url.pathname.replace(/\/+$/, '') || '/';
  const normalized = pathname + url.hash;
  if (window.location.pathname + window.location.hash !== normalized) {
    const method = replace ? 'replaceState' : 'pushState';
    window.history[method]({}, '', normalized);
  }
}

function navigateTo(path, replace = false, options = {}) {
  setPath(path, replace);
  return init(options);
}

function scrollToInstructions() {
  const instructions = document.getElementById('how-it-works');
  if (!instructions) return;
  instructions.querySelectorAll('.reveal').forEach(el => el.classList.add('visible'));
  instructions.scrollIntoView({behavior: 'instant', block: 'start'});
}

function stopTimers() {
  clearInterval(refreshTimer);
  clearInterval(pollTimer);
  refreshTimer = pollTimer = null;
  proxyLoadVersion++;
}

// ── Scroll-reveal animation ───────────────────────────────────────────────────
let _revealObserver = null;
function _initReveal() {
  if (_revealObserver) _revealObserver.disconnect();
  _revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(e => {
      if (e.isIntersecting) {
        e.target.classList.add('visible');
        _revealObserver.unobserve(e.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
  document.querySelectorAll('.reveal').forEach(el => {
    _revealObserver.observe(el);
  });
}

// ── Шаги ─────────────────────────────────────────────────────────────────────
function clearAccessProgress() {
  accessProgressTimers.forEach(clearTimeout);
  accessProgressTimers = [];
  const wrap = document.getElementById('steps-wrap');
  if (!wrap) return;
  wrap.hidden = true;
  wrap.classList.remove('access-progress-enter', 'access-progress-leave');
  wrap.replaceChildren();
}

function showAccessProgress() {
  clearAccessProgress();
  const wrap = document.getElementById('steps-wrap');
  if (!wrap) return;
  const active = 3;
  const labels = ['Вход','Доступ','Подбор'];
  let html = '<div class="steps-wrap"><div class="steps-row">';
  labels.forEach((label, i) => {
    const n   = i + 1;
    const cls = n < active ? 'done' : n === active ? 'active' : '';
    const num = n < active ? '✓' : n;
    html += '<div class="step ' + cls + '">'
          + '<div class="step-circle">' + num + '</div>'
          + '<div class="step-label">' + label + '</div>'
          + '</div>';
    if (i < labels.length - 1)
      html += '<div class="step-line ' + (n < active ? 'done' : '') + '"></div>';
  });
  html += '</div></div>';
  wrap.innerHTML = html;
  wrap.hidden = false;
  wrap.classList.add('access-progress-enter');
  accessProgressTimers.push(setTimeout(() => {
    wrap.classList.remove('access-progress-enter');
    wrap.classList.add('access-progress-leave');
    accessProgressTimers.push(setTimeout(clearAccessProgress, 360));
  }, 2200));
}

function avatarInitial(me) {
  const name = String(me.account_login || me.username || me.first_name || 'Пользователь').trim();
  return Array.from(name)[0]?.toUpperCase() || 'П';
}

// ── Бейдж пользователя ────────────────────────────────────────────────────────
function renderBadge(me) {
  const el = document.getElementById('user-badge');
  if (!el) return;
  if (!me?.authenticated) { el.innerHTML = ''; return; }
  const name = esc(me.account_login || me.username || me.first_name || 'Пользователь');
  const photo = safePhotoUrl(me.photo_url);
  const initial = esc(avatarInitial(me));
  const avatar = photo
    ? '<img class="badge-photo" src="' + esc(photo) + '" data-initial="' + initial + '" alt="" referrerpolicy="no-referrer">'
    : '<span class="badge-avatar">' + initial + '</span>';
  el.innerHTML =
    '<div class="user-badge">'
    + '<button class="user-badge-btn" type="button" onclick="navigateTo(\'/account\')" title="Настройки аккаунта">'
    + avatar
    + '<span class="badge-name">' + name + '</span>'
    + '</button>'
    + '<a class="logout-btn" href="/logout">Выйти</a>'
    + '</div>';
}

function updateHeaderLogoLink(me) {
  const link = document.getElementById('header-logo-link');
  if (!link) return;
  const target = me?.authenticated ? '/connect_proxy' : '/';
  link.href = target;
  link.setAttribute(
    'aria-label',
    me?.authenticated ? 'Auto Proxy — к панели прокси' : 'Auto Proxy — на главную',
  );
}

// ── Шаг 1: Лендинг + Вход / Регистрация ──────────────────────────────────────
function renderLogin() {
  stopTimers();
  clearAccessProgress();
  const handle = /^[A-Za-z0-9_]{5,32}$/.test(botUsername) ? botUsername : 'autotgproxysuperbot';
  const botUrl = 'https://t.me/' + handle;
  document.getElementById('content').innerHTML = `
    <div class="landing-page">
      <section class="hero-section">
        <div class="hero-bg" aria-hidden="true"><div class="hero-orb hero-orb-1"></div><div class="hero-orb hero-orb-2"></div></div>
        <div class="hero-content">
          <div class="hero-copy">
            <div class="hero-badge"><span class="hero-badge-dot"></span>На связи с Telegram</div>
            <h1 class="hero-title"><span class="hero-title-main">Ваш Telegram.</span><span class="hero-title-accent">Снова на связи.</span></h1>
            <p class="hero-subtitle">Подбираем публичные MTProto-прокси по результатам проверок. Показываем, откуда и когда проверен вариант, и предлагаем резервы для следующей попытки.</p>
            <div class="hero-cta-group"><div class="hero-cta-buttons">
              <a class="btn-hero-primary" href="${esc(botUrl)}" target="_blank" rel="noopener noreferrer">Открыть бота ↗</a>
              <button class="btn-hero-secondary" type="button" onclick="navigateTo('/login')">Подключиться на сайте</button>
            </div><p class="hero-note">Бесплатно · Без карты и списаний</p></div>
            <div class="hero-stats">
              <div class="stat-chip"><span class="stat-num">MTProto</span><span class="stat-label">проверка протокола</span></div>
              <div class="stat-chip"><span class="stat-num">Основной + резерв</span><span class="stat-label">разные маршруты</span></div>
              <div class="stat-chip"><span class="stat-num">Место и время</span><span class="stat-label">у каждой проверки</span></div>
              <div class="stat-chip"><span class="stat-num">0 ₽</span><span class="stat-label">за доступ</span></div>
            </div>
          </div>
          <div class="messenger-preview" aria-label="Пример диалога с ботом">
            <div class="preview-top"><img src="/static/favicon.svg" alt="" width="42" height="42"><div><div class="preview-name">Auto Proxy</div><div class="preview-sub">Telegram · бот</div></div><span class="preview-menu" aria-hidden="true">•••</span></div>
            <div class="preview-chat"><div class="preview-date">Подбор с понятным основанием</div>
              <div class="chat-bubble chat-out">Подобрать прокси ↗</div>
              <div class="chat-bubble"><strong>Основной вариант и резервы</strong>Рядом со ссылкой — состояние протокола, место и время проверки.<div class="preview-server">MTProto для Telegram</div>Проверка из Орегона не означает, что соединение уже проверено в вашей сети.<span class="preview-connect">↗ Открыть в Telegram</span></div>
              <div class="chat-bubble chat-out">Если не подключился — возьмём резерв</div>
            </div><div class="preview-caption">Пример интерфейса, не результат текущей проверки</div>
          </div>
        </div>
      </section>
      <div class="how-section" id="how-it-works"><div class="section">
        <h2 class="section-title section-center reveal">Как подключиться</h2>
        <div class="how-steps">
          <div class="how-step reveal"><div class="how-num">1</div><div class="how-step-title">Откройте сайт или бота</div><div class="how-step-desc">Веб-кабинет доступен отдельно, даже если Telegram пока не подключается.</div></div>
          <div class="how-step reveal"><div class="how-num">2</div><div class="how-step-title">Запросите подбор</div><div class="how-step-desc">Выберите тип соединения. Сервис сохраняет ваши фильтры и учитывает актуальность измерений.</div></div>
          <div class="how-step reveal"><div class="how-num">3</div><div class="how-step-title">Посмотрите основание</div><div class="how-step-desc">Узнайте, где проверен вариант. Проверка в российской сети отображается только при наличии её измерения.</div></div>
          <div class="how-step reveal"><div class="how-num">4</div><div class="how-step-title">Подключитесь в Telegram</div><div class="how-step-desc">Подтвердите ссылку в приложении. Если соединения нет, попробуйте резерв или скройте вариант для себя.</div></div>
        </div>
      </div></div>
      <div class="why-section"><div class="why-grid">
        <div class="why-col reveal"><div class="why-label">Как мы проверяем</div><h3 class="why-col-title">Проверка с адресом и временем</h3><div class="why-items">
          <div class="why-item"><span class="why-item-icon">◷</span><span>Старое подтверждение не становится новым после обновления списка.</span></div>
          <div class="why-item"><span class="why-item-icon">↗</span><span>Открытый порт отмечается отдельно от успешной проверки MTProto.</span></div>
          <div class="why-item"><span class="why-item-icon">◎</span><span>Результат относится к сети проверки и версии клиента.</span></div>
        </div></div>
        <div class="why-col reveal"><div class="why-label why-label-good">Что получает пользователь</div><h3 class="why-col-title">Вариант для следующей попытки</h3><div class="why-items">
          <div class="why-item"><span class="why-item-icon">↗</span><span>Основная ссылка и доступные резервы с разными адресами.</span></div>
          <div class="why-item"><span class="why-item-icon">✓</span><span>Прямое подключение в Telegram без изменения настроек остальных приложений.</span></div>
          <div class="why-item"><span class="why-item-icon">↻</span><span>Личная замена варианта, который не работает в вашей сети.</span></div>
        </div></div>
      </div></div>
      <div class="tech-section"><div class="section">
        <div class="tech-section-header reveal"><span class="tech-label">Как устроен подбор</span><h2 class="section-title">Основание видно рядом со ссылкой</h2><p class="section-desc">Доступность зависит от оператора, маршрута и версии Telegram. Мы показываем имеющиеся измерения.</p></div>
        <div class="features-grid" style="margin-top:32px">
          <div class="feat-card reveal"><span class="feat-icon">↗</span><div class="feat-title">Проверка протокола</div><div class="feat-desc">В рекомендацию попадают варианты со свежим подтверждением обмена с Telegram. Если проверяющий движок недоступен, это отмечается явно.</div></div>
          <div class="feat-card reveal"><span class="feat-icon">◷</span><div class="feat-title">Свежесть результата</div><div class="feat-desc">У каждой проверки есть срок действия. История и текущий результат хранятся отдельно.</div></div>
          <div class="feat-card reveal"><span class="feat-icon">◎</span><div class="feat-title">Сеть проверки</div><div class="feat-desc">Основной сервер находится в Орегоне. Российское подтверждение появляется только после проверки подключённой точкой в РФ.</div></div>
          <div class="feat-card reveal"><span class="feat-icon">⇄</span><div class="feat-title">Разнообразные резервы</div><div class="feat-desc">Подбор старается предложить разные адреса и сети размещения. Разные секреты одного адреса не считаются независимыми резервами.</div></div>
          <div class="feat-card reveal"><span class="feat-icon">☰</span><div class="feat-title">Один подбор на сайте и в боте</div><div class="feat-desc">Оба интерфейса используют общий каталог и одинаковые правила выбора.</div></div>
          <div class="feat-card reveal"><span class="feat-icon">✓</span><div class="feat-title">Личные отметки</div><div class="feat-desc">«Не работает» помогает заменить вариант для вас. Подбор не зависит от популярности сервиса и количества голосов.</div></div>
        </div>
      </div></div>
    </div>`;
  _initReveal();
}

// ── Страница входа / регистрации ───────────────────────────────────────────────
function renderAuth(defaultTab) {
  stopTimers();
  clearAccessProgress();
  const tab = defaultTab || (currentPath() === '/register' ? 'register' : 'login');
  const botUrl = botUsername ? 'https://t.me/' + botUsername : 'https://t.me/autotgproxysuperbot';

  const html = [
    '<section class="auth-section" id="auth-anchor">',
      '<button class="auth-back-btn" onclick="navigateTo(\'/\')">← Назад</button>',
      '<h2 class="auth-section-title">Личный кабинет</h2>',
      '<p class="auth-section-sub">Выбирайте и персонально подбирайте прокси через веб-интерфейс</p>',
      '<div class="auth-card fade-up">',
        '<div class="auth-tabs">',
          '<button class="auth-tab ' + (tab==='login'?'active':'') + '" id="tab-login" onclick="switchTab(\'login\')">Войти</button>',
          '<button class="auth-tab ' + (tab==='register'?'active':'') + '" id="tab-register" onclick="switchTab(\'register\')">Регистрация</button>',
        '</div>',
        '<div id="form-login" ' + (tab!=='login'?'style="display:none"':'') + '>',
          '<div class="form-group">',
            '<label for="login-login">Логин аккаунта</label>',
            '<input type="text" id="login-login" placeholder="Ваш логин" autocomplete="username" spellcheck="false">',
            '<span class="form-hint">Ваш логин из аккаунта (или Telegram Ваш логин). Нет аккаунта? Откройте вкладку «Регистрация».</span>',
          '</div>',
          '<div class="form-group">',
            '<label for="login-password">Пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="login-password" placeholder="Пароль" autocomplete="current-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'login-password\',this)" tabindex="-1">👁</button>',
            '</div>',
          '</div>',
          '<div class="form-error" id="login-error"></div>',
          '<button class="btn btn-primary" id="login-btn" onclick="doLogin()">Войти в кабинет</button>',
        '</div>',
        '<div id="form-register" ' + (tab!=='register'?'style="display:none"':'') + '>',
          '<div class="form-group">',
            '<label for="reg-login">Логин аккаунта</label>',
            '<input type="text" id="reg-login" placeholder="Ваш логин" autocomplete="username" spellcheck="false" maxlength="32">',
            '<span class="form-hint">Введите ваш Telegram Ваш логин. Минимум 3 символа. Логин нельзя изменить.</span>',
          '</div>',
          '<div class="form-group">',
            '<label for="reg-password">Пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="reg-password" placeholder="Минимум 10 символов" autocomplete="new-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'reg-password\',this)" tabindex="-1">👁</button>',
            '</div>',
          '</div>',
          '<div class="form-group">',
            '<label for="reg-password2">Повторите пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="reg-password2" placeholder="Повторите пароль" autocomplete="new-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'reg-password2\',this)" tabindex="-1">👁</button>',
            '</div>',
          '</div>',
          '<div class="form-error" id="reg-error"></div>',
          '<button class="btn btn-primary" id="reg-btn" onclick="doRegister()">Создать аккаунт</button>',
          '<p class="auth-legal-note">Создавая аккаунт, вы принимаете <a href="/legal/terms" target="_blank" rel="noopener">условия использования</a>. Как обрабатываются данные: <a href="/legal/privacy" target="_blank" rel="noopener">политика обработки персональных данных</a>.</p>',
        '</div>',
      '</div>',
    '</section>',
  ].join('');

  document.getElementById('content').innerHTML = html;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ── Переключение вкладок ───────────────────────────────────────────────────────
function switchTab(tab) {
  const target = tab === 'register' ? '/register' : '/login';
  if (currentPath() !== target) {
    navigateTo(target);
    return;
  }
  document.getElementById('form-login').style.display    = tab === 'login'    ? '' : 'none';
  document.getElementById('form-register').style.display = tab === 'register' ? '' : 'none';
  document.getElementById('tab-login').classList.toggle('active',    tab === 'login');
  document.getElementById('tab-register').classList.toggle('active', tab === 'register');
}

// ── Показать/скрыть пароль ────────────────────────────────────────────────────
function togglePw(inputId, btn) {
  const inp = document.getElementById(inputId);
  if (!inp) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.textContent = '🙈';
  } else {
    inp.type = 'password';
    btn.textContent = '👁';
  }
}

// ── Вход ──────────────────────────────────────────────────────────────────────
async function doLogin() {
  const loginVal = (document.getElementById('login-login')?.value || '').trim();
  const passVal  = document.getElementById('login-password')?.value || '';
  const errEl    = document.getElementById('login-error');
  const btn      = document.getElementById('login-btn');
  if (btn?.disabled) return;

  if (!loginVal || !passVal) {
    if (errEl) errEl.textContent = 'Введите логин и пароль.';
    return;
  }

  btn.disabled    = true;
  btn.textContent = '⏳ Входим…';
  if (errEl) errEl.textContent = '';

  try {
    const res  = await fetch('/api/auth/login', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({ login: loginVal, password: passVal }),
    });
    const data = await res.json();
    if (data.ok) {
      navigateTo('/subscribe', true);
    } else {
      if (errEl) errEl.textContent = data.error || 'Неверный логин или пароль.';
      btn.disabled    = false;
      btn.textContent = 'Войти в кабинет';
    }
  } catch {
    if (errEl) errEl.textContent = 'Ошибка сети. Попробуйте ещё раз.';
    btn.disabled    = false;
    btn.textContent = 'Войти в кабинет';
  }
}

// ── Регистрация ────────────────────────────────────────────────────────────────
async function doRegister() {
  const loginVal  = (document.getElementById('reg-login')?.value || '').trim();
  const passVal   = document.getElementById('reg-password')?.value || '';
  const pass2Val  = document.getElementById('reg-password2')?.value || '';
  const errEl     = document.getElementById('reg-error');
  const btn       = document.getElementById('reg-btn');
  if (btn?.disabled) return;

  if (errEl) errEl.textContent = '';

  if (!loginVal) { if (errEl) errEl.textContent = 'Введите логин.'; return; }
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(loginVal)) {
    if (errEl) errEl.textContent = 'Логин: 3–32 символа, только буквы a–z, цифры, _';
    return;
  }
  if (!passVal || passVal.length < 10) {
    if (errEl) errEl.textContent = 'Пароль должен быть не короче 10 символов.';
    return;
  }
  if (passVal !== pass2Val) {
    if (errEl) errEl.textContent = 'Пароли не совпадают.';
    return;
  }

  btn.disabled    = true;
  btn.textContent = '⏳ Создаём…';

  try {
    const res  = await fetch('/api/auth/register', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({ login: loginVal, password: passVal }),
    });
    const data = await res.json();
    if (data.ok) {
      navigateTo('/subscribe', true);
    } else {
      if (errEl) errEl.textContent = data.error || 'Ошибка регистрации.';
      btn.disabled    = false;
      btn.textContent = 'Создать аккаунт';
    }
  } catch {
    if (errEl) errEl.textContent = 'Ошибка сети. Попробуйте ещё раз.';
    btn.disabled    = false;
    btn.textContent = 'Создать аккаунт';
  }
}

function renderAccountSettings(me) {
  stopTimers();
  clearAccessProgress();

  const login = esc(me.account_login || me.username || 'не указан');
  const username = me.username ? '@' + esc(me.username) : 'не найден';
  const firstName = me.first_name ? esc(me.first_name) : 'не указано';
  const subText = 'бесплатный доступ · 0 ₽';
  const photo = safePhotoUrl(me.photo_url);
  const initial = esc(avatarInitial(me));
  const avatar = photo
    ? '<img class="account-avatar-img" src="' + esc(photo) + '" data-initial="' + initial + '" alt="" referrerpolicy="no-referrer">'
    : '<div class="account-avatar-fallback">' + initial + '</div>';

  document.getElementById('content').innerHTML = [
    '<div class="account-page">',
      '<div class="account-head fade-up">',
        '<button class="auth-back-btn" onclick="navigateTo(\'/connect_proxy\')">← К прокси</button>',
        '<h2 class="auth-section-title">Настройки аккаунта</h2>',
        '<p class="auth-section-sub">Здесь можно проверить данные входа и сменить пароль.</p>',
      '</div>',

      '<div class="account-card fade-up" style="animation-delay:.06s">',
        '<div class="account-profile-row">',
          avatar,
          '<div>',
            '<div class="account-login">' + login + '</div>',
            '<div class="account-muted">Это логин для входа на сайт. Привязка Telegram выполняется отдельно в личном диалоге с ботом.</div>',
          '</div>',
        '</div>',
        '<div class="account-info-grid">',
          '<div class="account-info-item"><span>Telegram username</span><strong>' + username + '</strong></div>',
          '<div class="account-info-item"><span>Логин</span><strong>@' + login + '</strong></div>',
          '<div class="account-info-item"><span>Имя из Telegram</span><strong>' + firstName + '</strong></div>',
          '<div class="account-info-item"><span>Доступ</span><strong>' + subText + '</strong></div>',
        '</div>',
        '<div class="account-actions">',
          '<button class="btn btn-blue btn-inline" onclick="navigateTo(\'/connect_proxy\')">Открыть выбор прокси</button>',
          '<a class="btn btn-ghost btn-inline" href="/logout">Выйти из аккаунта</a>',
        '</div>',
      '</div>',

      '<div class="account-card fade-up" style="animation-delay:.1s">',
        '<h3 class="account-card-title">Сменить пароль</h3>',
        '<p class="account-muted">Новый пароль нужен только для входа на сайте. В Telegram-боте авторизация остаётся по вашему Telegram аккаунту.</p>',
        '<div class="form-group">',
          '<label for="old-password">Текущий пароль</label>',
          '<div class="pw-wrap">',
            '<input type="password" id="old-password" placeholder="Введите текущий пароль" autocomplete="current-password">',
            '<button class="pw-eye" type="button" onclick="togglePw(\'old-password\',this)" tabindex="-1">👁</button>',
          '</div>',
        '</div>',
        '<div class="form-group">',
          '<label for="new-password">Новый пароль</label>',
          '<div class="pw-wrap">',
            '<input type="password" id="new-password" placeholder="Минимум 10 символов" autocomplete="new-password">',
            '<button class="pw-eye" type="button" onclick="togglePw(\'new-password\',this)" tabindex="-1">👁</button>',
          '</div>',
        '</div>',
        '<div class="form-group">',
          '<label for="new-password2">Повторите новый пароль</label>',
          '<div class="pw-wrap">',
            '<input type="password" id="new-password2" placeholder="Повторите новый пароль" autocomplete="new-password">',
            '<button class="pw-eye" type="button" onclick="togglePw(\'new-password2\',this)" tabindex="-1">👁</button>',
          '</div>',
        '</div>',
        '<div class="form-error" id="account-password-msg"></div>',
        '<button class="btn btn-primary" id="account-password-btn" onclick="changeAccountPassword()">Сохранить новый пароль</button>',
      '</div>',
    '</div>',
  ].join('');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function changeAccountPassword() {
  const oldPassword = document.getElementById('old-password')?.value || '';
  const newPassword = document.getElementById('new-password')?.value || '';
  const newPassword2 = document.getElementById('new-password2')?.value || '';
  const msg = document.getElementById('account-password-msg');
  const btn = document.getElementById('account-password-btn');
  if (btn?.disabled) return;

  if (msg) {
    msg.textContent = '';
    msg.classList.remove('ok');
  }
  if (!oldPassword) { if (msg) msg.textContent = 'Введите текущий пароль.'; return; }
  if (!newPassword || newPassword.length < 10) { if (msg) msg.textContent = 'Новый пароль должен быть не короче 10 символов.'; return; }
  if (newPassword !== newPassword2) { if (msg) msg.textContent = 'Новые пароли не совпадают.'; return; }
  if (oldPassword === newPassword) { if (msg) msg.textContent = 'Новый пароль должен отличаться от текущего.'; return; }

  if (btn) { btn.disabled = true; btn.textContent = 'Сохраняю…'; }
  try {
    const res = await fetch('/api/account/password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.ok) throw new Error(data.error || 'Не удалось сменить пароль.');
    ['old-password', 'new-password', 'new-password2'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    if (msg) {
      msg.textContent = 'Пароль изменён. В следующий раз входите с новым паролем.';
      msg.classList.add('ok');
    }
  } catch (err) {
    if (msg) msg.textContent = err.message || 'Не удалось сменить пароль.';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Сохранить новый пароль'; }
  }
}

function renderSubscribe() {
  clearAccessProgress();
  document.getElementById('content').innerHTML = [
    '<div class="sub-page">',
      '<div class="sub-hero fade-up">',
        '<h2>Бесплатный доступ к подбору</h2>',
        '<p>Актуальные измерения, основной вариант и доступные резервы</p>',
      '</div>',
      '<div class="card fade-up" style="animation-delay:.08s">',
        '<div class="plan-badge">Auto Proxy · бесплатно</div>',
        '<div class="price-block">',
          '<span class="price-amount">0</span>',
          '<div class="price-right">',
            '<span class="price-currency">₽</span>',
            '<span class="price-period">без списаний</span>',
          '</div>',
        '</div>',
        '<ul class="benefits">',
          '<li><span class="bi">🛡️</span><div><strong>Отбор подходящих серверов</strong><br><span class="ben-sub">Некорректные и явно недоступные варианты отсеиваются заранее</span></div></li>',
          '<li><span class="bi">🏆</span><div><strong>Основной вариант и резервы</strong><br><span class="ben-sub">Рекомендации строятся по свежим результатам проверки протокола</span></div></li>',
          '<li><span class="bi">🔄</span><div><strong>Регулярное обновление</strong><br><span class="ben-sub">Срок действия указан у каждой проверки; старые результаты не продлеваются автоматически</span></div></li>',
          '<li><span class="bi">🤖</span><div><strong>Telegram-бот</strong><br><span class="ben-sub">Получайте прокси прямо в мессенджере</span></div></li>',
          '<li><span class="bi">⚡</span><div><strong>Основание рекомендации</strong><br><span class="ben-sub">Состояние протокола, место и время последней проверки</span></div></li>',
        '</ul>',
        '<div class="trust-row">',
          '<span class="trust-item">✅ Бесплатный доступ</span>',
          '<span class="trust-item">🔒 Карта не нужна</span>',
        '</div>',
        '<div class="pay-methods">',
          '<button class="btn btn-sbp" onclick="navigateTo(\'/connect_proxy\', false, {accessGranted:true})">',
            'Открыть прокси бесплатно',
          '</button>',
        '</div>',
        '<p class="pay-note">Откроется панель подбора. Карта и оплата не нужны.</p>',
      '</div>',
    '</div>'
  ].join('');
}

// ── Шаг 3: Прокси ────────────────────────────────────────────────────────────
function renderActive(me, accessGranted = false) {
  clearAccessProgress();
  const initSec = getSecondsLeft() || 180;
  if (!getSecondsLeft()) setNextUpdateAt(initSec);
  document.getElementById('content').innerHTML = `
    <div class="proxy-page">
      <div class="status-bar"><div class="status-left"><span class="status-indicator" aria-hidden="true"></span><span>Обновление каталога через <span id="countdown">${initSec}</span> с</span></div><span class="status-expires">бесплатный доступ</span></div>
      <div class="find-section fade-up">
        <h2 class="find-title">Подобрать соединение</h2>
        <p class="find-caveat">Основной вариант и доступные резервы по свежим проверкам протокола. Место проверки указано рядом со ссылкой. Измерение из Орегона не подтверждает доступность в вашей российской сети.</p>
        <div class="network-choice"><label for="network-context">Ваша сеть</label><select id="network-context" onchange="setNetwork(this.value)"><option value="unknown" ${filterNetwork==='unknown'?'selected':''}>Не указана</option><option value="wifi" ${filterNetwork==='wifi'?'selected':''}>Домашний интернет / Wi-Fi</option><option value="cellular" ${filterNetwork==='cellular'?'selected':''}>Мобильный интернет</option></select></div>
        <button class="btn find-btn" id="find-btn" onclick="findBestProxy('new')">↗ Подобрать прокси</button>
        <div id="find-result" aria-live="polite"></div>
      </div>
      <div class="manual-divider"><span>Каталог ссылок с результатами измерений</span></div>
      <div class="filter-bar fade-up">
        <div class="filter-row"><div class="filter-group"><span class="filter-label">Протокол</span><div class="filter-pills">
          <button class="filter-pill ${filterType==='all'?'active':''}" onclick="setFilter('type','all',this)">Все</button>
          <button class="filter-pill ${filterType==='FakeTLS'?'active':''}" onclick="setFilter('type','FakeTLS',this)">FakeTLS</button>
          <button class="filter-pill ${filterType==='RandPad'?'active':''}" onclick="setFilter('type','RandPad',this)">RandPad</button>
          <button class="filter-pill ${filterType==='Plain'?'active':''}" onclick="setFilter('type','Plain',this)">Plain</button>
        </div></div></div>
        <div class="filter-row filter-sort-row"><span class="filter-label">Порядок</span><div class="filter-pills">
          <button class="filter-pill ${filterSort==='recommended'?'active':''}" onclick="setSort('recommended',this)">Свежие подтверждения</button>
          <button class="filter-pill ${filterSort==='ping'?'active':''}" onclick="setSort('ping',this)">Отклик проверки</button>
        </div><span class="filter-total" id="proxy-total"></span></div>
      </div>
      <p class="catalog-note">В каталоге могут быть ссылки без подтверждения протокола. Это отмечено в карточке; открытый порт сам по себе не считается успешной проверкой Telegram.</p>
      <div id="proxy-list"><div class="empty-state"><p>Загружаем каталог…</p></div></div>
    </div>`;
  loadProxies();
  startCountdown();
  if (accessGranted) {
    window.scrollTo({top: 0, behavior: 'instant'});
    showAccessProgress();
  }
}

function setNetwork(value) {
  filterNetwork = ['wifi', 'cellular'].includes(value) ? value : 'unknown';
  findSkipIds.clear();
  document.getElementById('find-result')?.replaceChildren();
  loadProxies();
}

// ── Таймер ────────────────────────────────────────────────────────────────────
function startCountdown() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    expireRenderedEvidence();
    const left = getSecondsLeft();
    const el   = document.getElementById('countdown');
    if (el) el.textContent = left;
    if (left <= 0) {
      // Keep failed/overdue requests from firing again every second.
      setNextUpdateAt(15);
      loadProxies();
    }
  }, 1000);
}

function setFilter(key, val, btn) {
  if (key === 'region') filterRegion = val;
  if (key === 'type')   filterType   = val;
  btn.parentElement.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  findSkipIds.clear();
  document.getElementById('find-result')?.replaceChildren();
  loadProxies();
}

function setSort(val, btn) {
  filterSort = val;
  btn.parentElement.querySelectorAll('.filter-pill').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('find-result')?.replaceChildren();
  findSkipIds.clear();
  loadProxies();
}

async function replaceProxy(proxyId) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(proxyId)) return;
  const card = document.querySelector('.proxy-card[data-id="' + proxyId + '"]');
  if (card) {
    card.style.opacity = '0.4';
    card.style.pointerEvents = 'none';
  }
  try {
    const res  = await fetch('/api/proxies/replace', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        proxy_id: proxyId,
        region:   filterRegion,
        type:     filterType,
        sort:     filterSort,
      }),
    });
    const data = await res.json();
    if (data.ok && data.proxies) {
      const list = document.getElementById('proxy-list');
      if (list) list.innerHTML = data.proxies.map((p, i) => buildCard(p, i)).join('');
    } else {
      if (card) { card.style.opacity = '1'; card.style.pointerEvents = ''; }
    }
  } catch {
    if (card) { card.style.opacity = '1'; card.style.pointerEvents = ''; }
  }
}

// ── Прокси-карточки ───────────────────────────────────────────────────────────
async function reportProxyWorks(proxyId, btn) {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(proxyId) || !btn) return;
  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = 'Сохраняю…';
  try {
    const res = await fetch('/api/proxies/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: proxyId, outcome: 'works' }),
    });
    const data = await res.json();
    if (!res.ok || !data.ok) throw new Error(data.error || 'feedback_failed');
    btn.textContent = '✅ Спасибо, учтено';
  } catch {
    btn.disabled = false;
    btn.textContent = oldText;
  }
}

function tspuCls(v)  { return v >= 75 ? ['color-high','fill-high'] : v >= 45 ? ['color-mid','fill-mid'] : ['color-low','fill-low']; }
function expireRenderedEvidence() {
  document.querySelectorAll('.proxy-card[data-valid-until]').forEach(card => {
    const until = Number(card.dataset.validUntil);
    if (!until || until > Date.now()) return;
    card.removeAttribute('data-valid-until');
    const status = card.querySelector('.evidence-status');
    if (status) {
      status.classList.remove('evidence-verified');
      status.classList.add('evidence-stale');
      status.textContent = 'Подтверждение устарело';
    }
    const link = card.querySelector('.connect-btn');
    if (link) link.textContent = '↗ Открыть ссылку в Telegram';
  });
}

function pingCls(ms) { return ms <= 120 ? 'color-good' : ms <= 280 ? 'color-ok' : 'color-slow'; }

function buildCard(p, idx) {
  const proof = evidenceInfo(p);
  const pid = String(p.id || '');
  const safeId = /^[A-Za-z0-9_-]{1,64}$/.test(pid) ? pid : '';
  const server = String(p.server || p.host || '');
  const port = Number(p.port);
  const url = proxyUrl(p);
  const type = ['FakeTLS', 'RandPad', 'Plain'].includes(p.type) ? p.type : ({faketls:'FakeTLS', randpad:'RandPad', plain:'Plain'}[p.generation] || 'MTProto');
  const reasons = Array.isArray(p.match_reasons) ? p.match_reasons.filter(reason => reason !== proof.place).slice(0, 3).map(esc).join(' · ') : '';
  return `<article class="proxy-card" data-id="${esc(safeId)}" ${proof.status==='verified' ? 'data-valid-until="' + timeValue(p.evidence.valid_until) + '"' : ''}>
    <div class="card-row"><div class="proxy-rank rank-default">${idx+1}</div><div class="card-info"><div class="card-server" title="${esc(server)}">${esc(server)}</div><div class="card-meta">Порт ${Number.isInteger(port) ? port : '—'}</div></div><span class="badge badge-plain">${esc(type)}</span></div>
    <div class="evidence-status evidence-${esc(proof.status)}">${esc(proof.label)}</div>
    <div class="metrics"><div class="metric metric-grow"><span class="metric-label">Место проверки</span><span class="metric-value">${esc(proof.place)}</span></div><div class="metric"><span class="metric-label">Последняя проверка</span><span class="metric-value">${esc(proof.when)}</span></div><div class="metric"><span class="metric-label">Время теста</span><span class="metric-value">${esc(proof.timing)}</span></div></div>
    ${reasons ? '<p class="card-reasons">' + reasons + '</p>' : ''}
    <div class="card-actions">
      ${url ? '<a class="connect-btn" href="' + esc(url) + '">' + (proof.status==='verified'?'↗ Подключить в Telegram':'↗ Открыть ссылку в Telegram') + '</a>' : '<span class="card-meta">Ссылка некорректна</span>'}
      ${safeId ? '<button class="replace-btn" data-proxy-action="works" data-proxy-id="' + esc(safeId) + '">✓ Работает у меня</button><button class="replace-btn" data-proxy-action="replace" data-proxy-id="' + esc(safeId) + '">Не работает</button>' : ''}
    </div>
  </article>`;
}

// ── Персональный подбор через профиль клиента и серверную проверку ───────────
function collectClientProfile() {
  return {network: filterNetwork, device: 'unknown', platform: 'web'};
}

async function findBestProxy(mode = 'new', proxyId = '') {
  if (_checkRunning) return;
  _checkRunning = true;
  const btn = document.getElementById('find-btn');
  const resultEl = document.getElementById('find-result');
  if (mode === 'new') findSkipIds.clear();
  if (proxyId) findSkipIds.add(proxyId);
  if (btn) { btn.disabled = true; btn.textContent = 'Подбираем…'; }
  if (resultEl) resultEl.innerHTML = '<p class="find-msg">Выбираем по актуальным измерениям…</p>';
  try {
    if (mode === 'failed' && proxyId) {
      const report = await fetch('/api/proxies/ban', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({id:proxyId})});
      if (!report.ok) throw new Error('feedback_failed');
    }
    const res = await fetch('/api/proxies/find-best', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body:JSON.stringify({region:filterRegion, type:filterType, sort:filterSort, network:filterNetwork, profile:collectClientProfile(), skip_ids:Array.from(findSkipIds)}),
    });
    if (res.status === 401) { init(); return; }
    const data = await res.json();
    if (!res.ok) throw new Error('selection_failed');
    if (!resultEl?.isConnected) return;
    if (data.ok && data.proxy) {
      findSkipIds.add(String(data.proxy.id || ''));
      const reserves = Array.isArray(data.reserves) ? data.reserves.slice(0,2) : [];
      resultEl.innerHTML = '<div class="selection-heading"><h3>Основной вариант</h3><p>Откройте ссылку в Telegram. При неудаче попробуйте один из резервов.</p></div>'
        + buildCard(data.proxy, 0)
        + (reserves.length ? '<h3 class="reserve-heading">Резервы · другие адреса</h3>' + reserves.map((proxy, index) => buildCard(proxy, index+1)).join('') : '<p class="catalog-note">Разнообразных резервов по этим условиям пока нет.</p>')
        + '<button class="find-retry-btn" data-proxy-action="next" data-proxy-id="' + esc(String(data.proxy.id || '')) + '">↻ Найти другой набор</button>';
    } else {
      const status = String(data.status || 'pending');
      const message = status === 'empty' ? 'По выбранным условиям пока нет вариантов.' : 'Свежих подтверждений протокола пока нет.';
      resultEl.innerHTML = '<div class="find-fail"><p>' + esc(message) + '</p><small>Подбор использует сохранённые измерения. Российская проверка появляется только при подключённой точке в РФ. Фильтры не снимаются автоматически.</small><button class="find-retry-btn" data-proxy-action="retry">Обновить результат</button></div>';
    }
  } catch {
    if (resultEl?.isConnected) resultEl.innerHTML = '<p class="find-msg find-err">Не удалось получить подбор. Проверьте соединение и повторите.</p>';
  } finally {
    _checkRunning = false;
    if (btn?.isConnected) { btn.disabled = false; btn.textContent = '↗ Подобрать прокси'; }
  }
}

document.addEventListener('click', event => {
  const button = event.target.closest('[data-proxy-action]');
  if (!button) return;
  const id = button.dataset.proxyId || '';
  if (id && !/^[A-Za-z0-9_-]{1,64}$/.test(id)) return;
  const action = button.dataset.proxyAction;
  if (action === 'works') reportProxyWorks(id, button);
  if (action === 'replace') {
    if (button.closest('#find-result')) findBestProxy('failed', id);
    else replaceProxy(id);
  }
  if (action === 'next') findBestProxy('next', id);
  if (action === 'retry') findBestProxy('new');
});

async function checkProxies() { return findBestProxy(); }

async function loadProxies() {
  const version = ++proxyLoadVersion;
  const params = new URLSearchParams({
    region: filterRegion,
    type:   filterType,
    sort:   filterSort,
    network: filterNetwork,
  });
  const res = await fetch('/api/proxies?' + params).catch(() => null);
  if (version !== proxyLoadVersion) return;
  const list = document.getElementById('proxy-list');
  if (!list) return;
  if (!res || !res.ok && res.status !== 401) {
    list.innerHTML = '<div class="empty-state"><p>Не удалось загрузить список. Повторим попытку автоматически.</p><button class="btn btn-ghost btn-inline" onclick="loadProxies()">Повторить</button></div>';
    return;
  }
  if (res.status === 401) { init(); return; }
  const data = await res.json().catch(() => null);
  if (version !== proxyLoadVersion || !list.isConnected || !data) return;

  if (data.next_update_in != null) {
    const currentLeft = getSecondsLeft();
    const next = Math.max(15, Number(data.next_update_in) || 15);
    if (currentLeft <= 15 || next < currentLeft) {
      setNextUpdateAt(next);
      const el = document.getElementById('countdown');
      if (el) el.textContent = next;
    }
  }

  const totalEl = document.getElementById('proxy-total');
  if (totalEl && data.total != null) {
    totalEl.textContent = data.total + ' вариантов в каталоге';
  }

  if (!data.proxies?.length) {
    list.innerHTML = '<div class="empty-state"><div class="eicon">🔍</div>'
      + '<p>По выбранным фильтрам прокси не найдены.<br>Попробуйте изменить фильтры.</p></div>';
    return;
  }
  list.innerHTML = data.proxies.map((p, i) => buildCard(p, i)).join('');
}

// ── Точка входа ───────────────────────────────────────────────────────────────
async function init(options = {}) {
  const version = ++navigationVersion;
  stopTimers();
  clearAccessProgress();
  _injectThemeToggle();
  const path = currentPath();
  if (window.location.pathname !== path && APP_ROUTES.has(path)) setPath(path, true);

  const instructionsRequested = path === '/' && location.hash === '#how-it-works';
  if (instructionsRequested) {
    if (!document.getElementById('how-it-works')) renderLogin();
    scrollToInstructions();
  } else {
    document.getElementById('content').innerHTML =
      '<div class="spinner-wrap">⏳ Загрузка…</div>';
  }

  try {
    const [cfg, me] = await Promise.all([
      fetch('/api/config').then(r => r.json()).catch(() => ({})),
      fetch('/api/me').then(r => { if (!r.ok) throw new Error(); return r.json(); }),
    ]);
    if (version !== navigationVersion) return;
    botUsername = /^[A-Za-z0-9_]{5,32}$/.test(cfg.bot_username || '') ? cfg.bot_username : '';
    updateHeaderLogoLink(me);
    renderBadge(me);

    if (instructionsRequested) return;

    if (!me.authenticated) {
      if (path === '/login') {
        renderAuth('login');
      } else if (path === '/register') {
        renderAuth('register');
      } else if (path === '/app' || path === '/account' || path === '/subscribe' || path === '/connect_proxy') {
        setPath('/login', true);
        renderAuth('login');
      } else {
        renderLogin();
      }
      return;
    }

    if (path === '/login' || path === '/register' || path === '/') {
      setPath('/subscribe', true);
    }

    if (currentPath() === '/account') {
      renderAccountSettings(me);
    } else if (currentPath() === '/subscribe') {
      renderSubscribe();
    } else {
      if (currentPath() === '/app') setPath('/connect_proxy', true);
      renderActive(me, options.accessGranted === true);
    }
  } catch {
    if (version !== navigationVersion) return;
    if (instructionsRequested) return;
    document.getElementById('content').innerHTML =
      '<div class="empty-state"><div class="eicon">⚠️</div>'
      + '<p>Ошибка загрузки.<br>Обновите страницу.</p></div>';
  }
}

document.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    const active = document.activeElement?.id;
    if (active === 'login-login' || active === 'login-password') doLogin();
    if (active === 'reg-login' || active === 'reg-password' || active === 'reg-password2') doRegister();
    if (active === 'old-password' || active === 'new-password' || active === 'new-password2') changeAccountPassword();
  }
});

window.addEventListener('popstate', init);
document.addEventListener('click', event => {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  if (!event.target.closest('a[href="/#how-it-works"]')) return;
  event.preventDefault();
  navigateTo('/#how-it-works');
});
document.addEventListener('DOMContentLoaded', () => { _injectThemeToggle(); init(); });
