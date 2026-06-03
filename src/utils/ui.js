import { sfx } from './sounds.js';
import { t } from './i18n.js';

let toastHost = null;
const recentToasts = new Map();
const MAX_TOASTS = 6;
const DEDUPE_MS = 1500;

function getToastHost() {
  if (toastHost && document.body.contains(toastHost)) return toastHost;
  toastHost = document.createElement('div');
  toastHost.id = 'toast-host';
  toastHost.className = 'toast-host';
  document.body.appendChild(toastHost);
  return toastHost;
}

const ICON_OK = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
const ICON_BAD = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
const ICON_INFO = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';

export const showNotification = (message, type = 'info') => showToast(message, type);

export const showToast = (message, type = 'info', dur = 3000) => {
  const host = getToastHost();
  const msg = String(message ?? '');
  const key = `${type}:${msg}`;
  const now = Date.now();
  const prev = recentToasts.get(key);

  if (prev && now - prev.ts < DEDUPE_MS && prev.card.isConnected) {
    prev.count += 1;
    prev.ts = now;
    let badge = prev.card.querySelector('.toast-count');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'toast-count';
      prev.card.appendChild(badge);
    }
    badge.textContent = `x${prev.count}`;
    clearTimeout(prev.timer);
    prev.timer = setTimeout(() => closeToast(key, prev.card), dur);
    return;
  }

  const card = document.createElement('div');
  card.className = `toast toast-${type}`;
  const ic = type === 'success' ? ICON_OK : type === 'error' ? ICON_BAD : ICON_INFO;
  card.innerHTML = `<span class="toast-ic">${ic}</span><span class="toast-msg"></span>`;
  card.querySelector('.toast-msg').textContent = msg;
  host.appendChild(card);
  while (host.children.length > MAX_TOASTS) host.removeChild(host.firstChild);

  if (type === 'success') sfx.success?.();
  else if (type === 'error') sfx.fail?.();

  requestAnimationFrame(() => card.classList.add('in'));
  card.addEventListener('click', () => closeToast(key, card));
  const timer = setTimeout(() => closeToast(key, card), dur);
  recentToasts.set(key, { card, count: 1, ts: now, timer });
};

function closeToast(key, card) {
  card.classList.remove('in');
  card.classList.add('out');
  setTimeout(() => card.remove(), 280);
  recentToasts.delete(key);
}

export const showConfirm = (message, { confirmText, cancelText, icon: iconSvg, title } = {}) => {
  return new Promise((resolve) => {
    const modal = document.createElement('div');
    modal.className = 'modal-overlay';
    modal.style.animation = 'fadeIn 0.18s ease-out';

    const content = document.createElement('div');
    content.className = 'modal-content confirm-modal';
    const warnIcon = iconSvg || '<svg viewBox="0 0 24 24" width="26" height="26" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>';

    content.innerHTML = `
      <div class="confirm-icon">${warnIcon}</div>
      ${title ? '<p class="confirm-title"></p>' : ''}
      <p class="confirm-msg"></p>
      <div class="button-group">
        <button class="confirm-yes"></button>
        <button class="secondary confirm-no"></button>
      </div>
    `;

    if (title) content.querySelector('.confirm-title').textContent = title;
    content.querySelector('.confirm-msg').textContent = message;
    content.querySelector('.confirm-yes').textContent = confirmText || t('common.ok') || 'OK';
    content.querySelector('.confirm-no').textContent = cancelText || t('common.cancel') || 'Cancel';

    modal.appendChild(content);
    document.body.appendChild(modal);

    const close = (value) => {
      content.style.animation = 'slideOut 0.15s ease-in forwards';
      modal.style.animation = 'fadeOut 0.15s ease-in forwards';
      setTimeout(() => {
        modal.remove();
        resolve(value);
      }, 140);
    };

    modal.addEventListener('click', (e) => {
      if (e.target === modal) close(false);
    });
    content.querySelector('.confirm-yes').addEventListener('click', () => {
      sfx.click?.();
      close(true);
    });
    content.querySelector('.confirm-no').addEventListener('click', () => {
      sfx.click?.();
      close(false);
    });
  });
};
