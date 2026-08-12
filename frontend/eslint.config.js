// Configuracion ESLint (flat config) del frontend React + TypeScript.
// Incluye reglas de hooks (dependencias/orden) y de fast-refresh de Vite.
import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist', 'node_modules'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
  {
    // Los archivos de configuracion de build (tailwind/postcss/vite) usan
    // require() para cargar plugins CommonJS: es legitimo fuera del codigo app.
    files: ['**/*.config.{ts,js,cjs,mjs}'],
    rules: { '@typescript-eslint/no-require-imports': 'off' },
  },
);
