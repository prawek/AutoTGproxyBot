/* Theme storage may be unavailable in private or restricted browsers. */
window.ProxyTheme = {
  names: ['system', 'dark', 'light'],
  labels: {system: 'Системная тема', dark: 'Тёмная тема', light: 'Светлая тема'},
  icons: {
    system: '<circle cx="12" cy="12" r="8"/><path d="M12 4v16a8 8 0 0 0 0-16Z" fill="currentColor" stroke="none"/>',
    dark: '<path d="M20 13a8 8 0 0 1-9-9 8.5 8.5 0 1 0 9 9Z"/>',
    light: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
  },
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
      button.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">' + this.icons[theme] + '</svg>';
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
document.addEventListener('DOMContentLoaded', () => ProxyTheme.apply(ProxyTheme.read()));
