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
let landingChannel = 'web';

function telegramBotUrl() {
  const handle = /^[A-Za-z0-9_]{5,32}$/.test(botUsername) ? botUsername : 'autotgproxysuperbot';
  return 'https://t.me/' + handle;
}

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
  window.ProxyMotion?.clear();
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
  const loginLink = document.querySelector('.header-login');
  if (loginLink) loginLink.hidden = Boolean(me?.authenticated);
  if (!me?.authenticated) { el.innerHTML = ''; return; }
  const name = esc(me.account_login || me.username || me.first_name || 'Пользователь');
  const photo = safePhotoUrl(me.photo_url);
  const initial = esc(avatarInitial(me));
  const avatar = photo
    ? '<img class="badge-photo" src="' + esc(photo) + '" data-initial="' + initial + '" alt="" referrerpolicy="no-referrer">'
    : '<span class="badge-avatar">' + initial + '</span>';
  el.innerHTML =
    '<div class="user-badge">'
    + '<button class="user-badge-btn" type="button" onclick="navigateTo(\'/account\')" title="Настройки аккаунта" aria-label="Настройки аккаунта">'
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
  const arrow = '<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M5 19 19 5M5 5h14v14"/></svg>';
  document.getElementById('content').innerHTML = `
    <div class="landing-page home-page">
      <section class="home-hero" id="home-start" data-enter>
        <div class="page-wrap">
          <div class="home-opening">
            <h1 class="home-title"><span>Telegram</span><span>через прокси.</span></h1>
            <div class="home-intro"><p>Бесплатный подбор MTProto-прокси. Основной вариант и резервы по свежим проверкам соединения.</p><a class="home-down-link" href="#how-it-works">Как это работает <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 4v16m-6-6 6 6 6-6"/></svg></a></div>
          </div>
          <div class="home-connect">
            <div class="home-connect-choice">
              <h2>Где начнём?</h2>
              <div class="home-channel-switch" role="group" aria-label="Способ подключения">
                <button class="home-channel" type="button" data-home-channel="web" aria-pressed="${landingChannel === 'web'}"><svg aria-hidden="true" viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="5" width="26" height="22" rx="3"/><path d="M3 11h26M7 8h1m2 0h1m-1 9h12m-12 5h8"/></svg><span>На сайте<small>Если Telegram не открывается</small></span><span class="home-choice-dot" aria-hidden="true"></span></button>
                <button class="home-channel" type="button" data-home-channel="bot" aria-pressed="${landingChannel === 'bot'}"><img src="/static/favicon.svg" width="32" height="32" alt=""><span>В Telegram<small>Если мессенджер уже доступен</small></span><span class="home-choice-dot" aria-hidden="true"></span></button>
              </div>
            </div>
            <div class="home-connect-next">
              <div class="home-route-mark" aria-hidden="true"><span class="home-path-origin">Вы</span><span class="home-path-line"></span><span class="home-path-proxy">MTProto</span><span class="home-path-line"></span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="m4 12 5 5L20 6"/></svg><span>Telegram</span></div>
              <div class="home-route-copy" aria-live="polite" aria-atomic="true"><h3 id="home-route-title"></h3><p id="home-route-description"></p></div>
              <div class="home-network-field">
                <span id="home-network-label">Ваша сеть <small>необязательно</small></span>
                <div class="home-networks" role="group" aria-labelledby="home-network-label">
                  <button type="button" data-landing-network="wifi" aria-pressed="${filterNetwork === 'wifi'}">Wi-Fi</button><button type="button" data-landing-network="cellular" aria-pressed="${filterNetwork === 'cellular'}">Мобильная</button>
                </div>
              </div>
              <div class="home-next-action" id="home-next-action"></div>
              <p class="home-access-note" id="home-access-note"></p>
            </div>
          </div>
          <div class="home-ground-note"><span>Бесплатный доступ</span><span>Только для Telegram</span><span>Основной вариант и резервы</span></div>
        </div>
      </section>

      <section class="home-how" id="how-it-works">
        <div class="page-wrap">
          <div class="home-section-heading"><h2>От подбора<br>к переписке.</h2><p>Прокси добавляется в самом Telegram.<br>Остальные приложения работают как раньше.</p></div>
          <ol class="home-steps">
            <li><div class="home-step-head"><span>01</span><h3>Получите ссылки</h3></div><p>На сайте нужен бесплатный аккаунт. В боте достаточно нажать «Подобрать прокси».</p><div class="home-step-detail"><span>Основной вариант</span><span>Доступные резервы</span></div></li>
            <li><div class="home-step-head"><span>02</span><h3>Откройте Telegram</h3></div><p>Выберите основной вариант. Ссылка откроет окно подключения в приложении.</p><div class="home-step-detail home-step-protocol"><span>MTProto</span><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M4 12h16m-6-6 6 6-6 6"/></svg><span>Telegram</span></div></li>
            <li><div class="home-step-head"><span>03</span><h3>Подтвердите подключение</h3></div><p>Если связи нет, попробуйте резерв. Отметка «Не работает» поможет запросить замену для вас.</p><div class="home-step-detail"><span>Подключение</span><span>Замена при неудаче</span></div></li>
          </ol>
        </div>
      </section>

      <section class="home-proof" aria-labelledby="home-proof-title">
        <div class="page-wrap home-proof-layout">
          <div class="home-proof-heading"><h2 id="home-proof-title">Место и время<br>проверки.</h2><p>У ссылки указаны состояние протокола, место и время измерения. Посмотрите их перед подключением.</p><a class="text-link" href="/legal/selection">Правила подбора ${arrow}</a></div>
          <div class="home-proof-content">
            <div class="home-proof-time"><p><strong>5</strong><span>минут</span></p><div><h3>Срок подтверждения</h3><p>Затем результат считается устаревшим. Обновление списка не продлевает проверку.</p></div></div>
            <dl class="home-proof-places"><div><dt><span class="home-proof-dot" aria-hidden="true"></span>На сервере</dt><dd>Основная проверка проходит в Орегоне. Успех относится к этой сети.</dd></div><div><dt><span class="home-proof-dot home-proof-dot-outline" aria-hidden="true"></span>В вашей сети</dt><dd>Доступность зависит от оператора. Подтверждение из РФ появляется после измерения в российской сети.</dd></div></dl>
          </div>
        </div>
      </section>

      <section class="home-questions" id="questions">
        <div class="page-wrap home-questions-layout">
          <div><h2>Перед<br>подключением.</h2><p class="home-questions-intro">Несколько вещей, которые полезно знать.</p><a class="text-link" href="mailto:autotgproxy@gmail.com">Написать в поддержку ${arrow}</a></div>
          <div class="home-faq">
            <details><summary>Это работает как VPN?<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 5v14M5 12h14"/></svg></summary><p>Этот прокси используется только в Telegram. Он не меняет соединение браузера и остальных приложений.</p></details>
            <details><summary>За доступ нужно платить?<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 5v14M5 12h14"/></svg></summary><p>Нет. Подбор и каталог бесплатны. Банковская карта и подписка не нужны.</p></details>
            <details><summary>Зачем создавать аккаунт на сайте?<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 5v14M5 12h14"/></svg></summary><p>Через аккаунт вы получаете доступ к подбору и личным отметкам о прокси. Его можно создать на сайте, даже если Telegram пока не подключается.</p><a class="text-link" href="/register">Создать аккаунт ${arrow}</a></details>
            <details><summary>Что делать, если прокси не подошёл?<svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 5v14M5 12h14"/></svg></summary><p>Попробуйте резерв из подбора. Кнопка «Не работает» скроет вариант для вас и позволит запросить замену. Проверка из другой сети не гарантирует подключение у вашего оператора.</p></details>
          </div>
        </div>
      </section>
    </div>`;

  function updateChannel(animate = false) {
    const web = landingChannel === 'web';
    document.querySelectorAll('[data-home-channel]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.homeChannel === landingChannel)));
    document.getElementById('home-route-title').textContent = web ? 'Начнём в браузере.' : 'Продолжим в боте.';
    document.getElementById('home-route-description').textContent = web ? 'Получите подбор в браузере. Откройте ссылку в Telegram.' : 'Основной вариант, резервы и результаты проверки появятся прямо в диалоге с ботом.';
    document.getElementById('home-next-action').innerHTML = web
      ? '<a class="btn btn-primary home-start-link" href="/login">Подобрать на сайте ' + arrow + '</a>'
      : '<a class="btn btn-primary home-start-link" data-home-bot-link href="' + esc(telegramBotUrl()) + '" target="_blank" rel="noopener noreferrer">Открыть бота ' + arrow + '</a>';
    document.getElementById('home-access-note').textContent = web ? 'Для подбора нужен бесплатный аккаунт.' : 'Тип сети выберите в меню бота. Настройки с сайта туда не передаются.';
    document.querySelector('.home-network-field').hidden = !web;
    if (animate) window.ProxyMotion?.feedback(document.querySelector('.home-route-copy'));
  }
  updateChannel();
  document.querySelectorAll('[data-home-channel]').forEach(button => button.addEventListener('click', () => {
    landingChannel = button.dataset.homeChannel;
    updateChannel(true);
  }));
  document.querySelectorAll('[data-landing-network]').forEach(button => button.addEventListener('click', () => {
    filterNetwork = button.dataset.landingNetwork;
    document.querySelectorAll('[data-landing-network]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
  }));
  window.ProxyMotion?.enter(document.querySelector('.landing-page'));
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
      '<h1 class="auth-section-title">Личный кабинет</h1>',
      '<p class="auth-section-sub">Ваши прокси, результаты проверок и настройки подключения.</p>',
      '<div class="auth-card fade-up">',
        '<div class="auth-tabs">',
          '<button class="auth-tab ' + (tab==='login'?'active':'') + '" id="tab-login" onclick="switchTab(\'login\')">Войти</button>',
          '<button class="auth-tab ' + (tab==='register'?'active':'') + '" id="tab-register" onclick="switchTab(\'register\')">Регистрация</button>',
        '</div>',
        '<div id="form-login" ' + (tab!=='login'?'style="display:none"':'') + '>',
          '<div class="form-group">',
            '<label for="login-login">Логин аккаунта</label>',
            '<input type="text" id="login-login" placeholder="Ваш логин" autocomplete="username" spellcheck="false">',
            '<span class="form-hint">Логин, созданный на сайте или полученный в боте.</span>',
          '</div>',
          '<div class="form-group">',
            '<label for="login-password">Пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="login-password" placeholder="Пароль" autocomplete="current-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'login-password\',this)" aria-label="Показать пароль" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button>',
            '</div>',
          '</div>',
          '<div role="status" aria-live="polite" class="form-error" id="login-error"></div>',
          '<button class="btn btn-primary" id="login-btn" onclick="doLogin()">Войти в кабинет</button>',
        '</div>',
        '<div id="form-register" ' + (tab!=='register'?'style="display:none"':'') + '>',
          '<div class="form-group">',
            '<label for="reg-login">Логин аккаунта</label>',
            '<input type="text" id="reg-login" placeholder="Ваш логин" autocomplete="username" spellcheck="false" maxlength="32">',
            '<span class="form-hint">От 3 до 32 латинских букв, цифр или знаков _. Логин нельзя изменить.</span>',
          '</div>',
          '<div class="form-group">',
            '<label for="reg-password">Пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="reg-password" placeholder="Минимум 10 символов" autocomplete="new-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'reg-password\',this)" aria-label="Показать пароль" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button>',
            '</div>',
          '</div>',
          '<div class="form-group">',
            '<label for="reg-password2">Повторите пароль</label>',
            '<div class="pw-wrap">',
              '<input type="password" id="reg-password2" placeholder="Повторите пароль" autocomplete="new-password">',
              '<button class="pw-eye" type="button" onclick="togglePw(\'reg-password2\',this)" aria-label="Показать пароль" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button>',
            '</div>',
          '</div>',
          '<div role="status" aria-live="polite" class="form-error" id="reg-error"></div>',
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
  const visible = inp.type === 'password';
  inp.type = visible ? 'text' : 'password';
  btn.setAttribute('aria-label', visible ? 'Скрыть пароль' : 'Показать пароль');
  btn.setAttribute('aria-pressed', String(visible));
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
  btn.textContent = 'Входим…';
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
        '<h1 class="auth-section-title">Настройки аккаунта</h1>',
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
            '<button class="pw-eye" type="button" onclick="togglePw(\'old-password\',this)" aria-label="Показать пароль" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button>',
          '</div>',
        '</div>',
        '<div class="form-group">',
          '<label for="new-password">Новый пароль</label>',
          '<div class="pw-wrap">',
            '<input type="password" id="new-password" placeholder="Минимум 10 символов" autocomplete="new-password">',
            '<button class="pw-eye" type="button" onclick="togglePw(\'new-password\',this)" aria-label="Показать пароль" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button>',
          '</div>',
        '</div>',
        '<div class="form-group">',
          '<label for="new-password2">Повторите новый пароль</label>',
          '<div class="pw-wrap">',
            '<input type="password" id="new-password2" placeholder="Повторите новый пароль" autocomplete="new-password">',
            '<button class="pw-eye" type="button" onclick="togglePw(\'new-password2\',this)" aria-label="Показать пароль" aria-pressed="false"><svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button>',
          '</div>',
        '</div>',
        '<div role="status" aria-live="polite" class="form-error" id="account-password-msg"></div>',
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
  document.getElementById('content').innerHTML = `
    <div class="sub-page">
      <div class="sub-hero"><h1>Доступ открыт.</h1><p>Можно переходить к подбору соединения.</p></div>
      <div class="card">
        <div class="plan-badge">Auto Proxy · бесплатно</div>
        <ul class="benefits">
          <li><div><strong>Основной вариант и резервы</strong><br><span class="ben-sub">Разные адреса по свежим проверкам MTProto.</span></div></li>
          <li><div><strong>Место и время проверки</strong><br><span class="ben-sub">Посмотрите основание перед подключением.</span></div></li>
          <li><div><strong>Замена для вашей сети</strong><br><span class="ben-sub">Если вариант не подключается, запросите другой.</span></div></li>
        </ul>
        <div class="trust-row"><span>0 ₽ за доступ · карта не нужна</span></div>
        <div class="pay-methods"><button class="btn btn-sbp" onclick="navigateTo('/connect_proxy', false, {accessGranted:true})">Открыть прокси бесплатно ↗</button></div>
      </div>
    </div>`;
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
        <div class="workspace-heading"><h1 class="find-title">Ваше соединение.</h1><span class="workspace-protocol">MTProto / Telegram</span></div>
        <p class="find-caveat">Выберите сеть, получите основной вариант и резервы. У каждой ссылки указаны место и время проверки.</p><p class="coverage-inline">Измерение из Орегона не подтверждает доступность в вашей российской сети.</p>
        <div class="find-controls"><div class="network-choice"><label for="network-context">Ваша сеть</label><select id="network-context" onchange="setNetwork(this.value)"><option value="unknown" ${filterNetwork==='unknown'?'selected':''}>Не указана</option><option value="wifi" ${filterNetwork==='wifi'?'selected':''}>Домашний интернет / Wi-Fi</option><option value="cellular" ${filterNetwork==='cellular'?'selected':''}>Мобильный интернет</option></select></div>
        <button class="btn find-btn" id="find-btn" onclick="findBestProxy('new')">Подобрать прокси ↗</button></div>
        <div id="find-result" aria-live="polite"></div>
      </div>
      <div class="catalog-heading"><h2>Каталог прокси</h2><span>Выберите вручную</span></div>
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
    btn.textContent = 'Отметка сохранена';
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
    if (btn?.isConnected) { btn.disabled = false; btn.textContent = 'Подобрать прокси ↗'; }
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
    list.innerHTML = '<div class="empty-state">'
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
      '<div class="spinner-wrap" role="status"><span class="loader-ring"></span>Загружаем кабинет…</div>';
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

    if (instructionsRequested) {
      document.querySelectorAll('[data-home-bot-link]').forEach(link => { link.href = telegramBotUrl(); });
      return;
    }

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
      '<div class="empty-state">'
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
  const link = event.target.closest('a[href]');
  if (!link || link.target || link.hasAttribute('download')) return;
  const url = new URL(link.href, location.origin);
  if (url.origin !== location.origin || !APP_ROUTES.has(url.pathname)) return;
  // Content anchors retain native focus/scroll behavior; application routes keep session choices.
  if (url.hash && url.hash !== '#how-it-works') return;
  event.preventDefault();
  navigateTo(url.pathname + url.hash);
});
document.addEventListener('DOMContentLoaded', () => { _injectThemeToggle(); init(); });
