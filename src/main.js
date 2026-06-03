import { TrueStudioManager } from './components/TrueStudioManager.js';
import { applyLang, setLang, getLang, t } from './utils/i18n.js';
import { icon } from './utils/icons.js';

window.t = t;

const ICON_MOON = icon('moon');
const ICON_SUN = icon('sun');

function initTheme() {
  const saved = localStorage.getItem('theme');
  if (saved === 'light') document.body.classList.add('light-theme');
  const btn = document.getElementById('themeToggleBtn');
  if (btn) btn.innerHTML = saved === 'light' ? ICON_SUN : ICON_MOON;
}

function toggleTheme() {
  const isLight = document.body.classList.toggle('light-theme');
  const btn = document.getElementById('themeToggleBtn');
  if (btn) btn.innerHTML = isLight ? ICON_SUN : ICON_MOON;
  localStorage.setItem('theme', isLight ? 'light' : 'dark');
}

initTheme();
applyLang();

document.getElementById('themeToggleBtn')?.addEventListener('click', toggleTheme);
document.getElementById('langToggleBtn')?.addEventListener('click', () => {
  setLang(getLang() === 'ar' ? 'en' : 'ar');
});

const studioRoot = document.getElementById('ts-page');
window.trueStudioManager = new TrueStudioManager(studioRoot);

document.addEventListener('DOMContentLoaded', () => {
  window.trueStudioManager.init();
});
