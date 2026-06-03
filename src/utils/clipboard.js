import { showNotification } from './ui.js';
import { t } from './i18n.js';

export const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
    showNotification(t('common.copied') || 'Copied', 'success');
  } catch (error) {
    console.error('Failed to copy:', error);
    showNotification(t('common.copy_failed') || 'Copy failed', 'error');
  }
};
