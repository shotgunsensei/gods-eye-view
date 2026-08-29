/** Register the network-only PWA shell and expose Chromium's install prompt. */
export function initPwaInstall() {
  const installButton = document.getElementById('install-app-btn');
  const signOutForm = document.getElementById('sign-out-form');
  let installPrompt = null;

  if (signOutForm) {
    fetch('/auth/status', { cache: 'no-store', credentials: 'same-origin' })
      .then((response) => response.ok ? response.json() : null)
      .then((status) => {
        signOutForm.hidden = status?.enabled !== true;
      })
      .catch(() => {
        signOutForm.hidden = true;
      });
  }

  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('/sw.js').catch((error) => {
        console.warn('PWA service worker registration failed:', error);
      });
    }, { once: true });
  }

  if (!installButton) return;

  const isStandalone = window.matchMedia('(display-mode: standalone)').matches
    || window.navigator.standalone === true;
  if (isStandalone) {
    installButton.hidden = true;
    return;
  }

  window.addEventListener('beforeinstallprompt', (event) => {
    event.preventDefault();
    installPrompt = event;
    installButton.hidden = false;
  });

  installButton.addEventListener('click', async () => {
    if (!installPrompt) return;
    installButton.disabled = true;
    await installPrompt.prompt();
    await installPrompt.userChoice;
    installPrompt = null;
    installButton.hidden = true;
    installButton.disabled = false;
  });

  window.addEventListener('appinstalled', () => {
    installPrompt = null;
    installButton.hidden = true;
  });
}
