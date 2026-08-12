import type { Config } from 'tailwindcss';

// HexWatch — tema claro minimalista: coral (#F0512E) + tinta casi negra,
// tarjetas redondeadas y sombras suaves. Tipografía Inter.
const config: Config = {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
        // Semánticos HexWatch
        brand: 'hsl(var(--brand-green))',
        neon: 'hsl(var(--neon-green))',
        warn: 'hsl(var(--warn-orange))',
        ink: 'hsl(var(--ink))',
        success: 'hsl(var(--success))',
        cyan: {
          DEFAULT: 'hsl(var(--cyan))',
          light: 'hsl(var(--cyan-light))',
        },
        gov: {
          yellow: 'hsl(var(--gov-yellow))',
          blue: 'hsl(var(--gov-blue))',
          red: 'hsl(var(--gov-red))',
        },
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 4px)',
        sm: 'calc(var(--radius) - 8px)',
        '2xl': 'calc(var(--radius) + 4px)',
        '3xl': 'calc(var(--radius) + 8px)',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
      },
      boxShadow: {
        glow: '0 10px 24px -12px hsl(var(--primary) / 0.5)',
        soft: '0 1px 2px rgb(17 17 17 / 0.04), 0 14px 32px -20px rgb(17 17 17 / 0.18)',
        card: '0 1px 3px rgb(17 17 17 / 0.05)',
      },
      keyframes: {
        'pulse-soft': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.6' },
        },
      },
      animation: {
        'pulse-soft': 'pulse-soft 2.4s ease-in-out infinite',
      },
    },
  },
  plugins: [require('tailwindcss-animate')],
};

export default config;
