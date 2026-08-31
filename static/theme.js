/* Theme storage may be unavailable in private or restricted browsers. */
window.ProxyTheme = {
  names: ['system', 'dark', 'light'],
  labels: {system: 'Системная тема', dark: 'Тёмная тема', light: 'Светлая тема'},
  icons: {system: '◐', dark: '☾', light: '☀'},
  read() {
    try {
      const theme = localStorage.getItem('theme');
      return this.names.includes(theme) ? theme : 'system';
    } catch { return 'system'; }
  },
  apply(theme) {
    theme = this.names.includes(theme) ? theme : 'system';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('theme', theme); } catch {}
    const button = document.getElementById('theme-toggle');
    if (button) {
      button.textContent = this.icons[theme];
      button.title = this.labels[theme];
      button.setAttribute('aria-label', this.labels[theme] + '. Переключить тему');
    }
  },
  cycle() {
    const current = document.documentElement.dataset.theme || this.read();
    this.apply(this.names[(this.names.indexOf(current) + 1) % this.names.length]);
  },
};
ProxyTheme.apply(ProxyTheme.read());
