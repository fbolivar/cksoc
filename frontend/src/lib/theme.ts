/** Manejo del tema claro/oscuro (persistido en localStorage). Por defecto: oscuro "SOC". */
export type Theme = 'light' | 'dark';

const KEY = 'soc-theme';

export function getTheme(): Theme {
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
}

export function setTheme(theme: Theme): void {
  document.documentElement.classList.toggle('dark', theme === 'dark');
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* localStorage no disponible: se mantiene solo en memoria */
  }
}

export function toggleTheme(): Theme {
  const next: Theme = getTheme() === 'dark' ? 'light' : 'dark';
  setTheme(next);
  return next;
}
