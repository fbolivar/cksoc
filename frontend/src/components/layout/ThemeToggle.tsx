/** Boton para alternar entre modo claro y oscuro (vive en la Topbar, siempre sobre fondo oscuro). */
import { useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import { getTheme, toggleTheme, type Theme } from '@/lib/theme';

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(() => getTheme());

  return (
    <button
      type="button"
      onClick={() => setTheme(toggleTheme())}
      className="rounded-md p-2 text-white/80 transition-colors hover:bg-white/10 hover:text-white"
      title={theme === 'dark' ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro'}
      aria-label={theme === 'dark' ? 'Activar modo claro' : 'Activar modo oscuro'}
    >
      {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </button>
  );
}
