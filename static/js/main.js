/**
 * Holidays Travel & Tourism - Client-side UI & Security Script
 * Seguridad Informática - 7° Semestre TI
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initPasswordToggle();
  initFormLoaders();
  initSocialModals();
});

/* ==========================================================================
   1. GESTOR DE TEMA CLARO / OSCURO (CON PERSISTENCIA)
   ========================================================================== */
function initTheme() {
  const themeToggleBtn = document.getElementById('themeToggleBtn');
  const themeIcon = document.getElementById('themeIcon');
  const storedTheme = localStorage.getItem('holidays_theme');
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

  // Determinar tema inicial
  let activeTheme = storedTheme || (prefersDark ? 'dark' : 'light');
  applyTheme(activeTheme);

  if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      const nextTheme = current === 'dark' ? 'light' : 'dark';
      applyTheme(nextTheme);
      localStorage.setItem('holidays_theme', nextTheme);
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    if (themeIcon) {
      if (theme === 'dark') {
        // Ícono de sol para volver a claro
        themeIcon.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="5"></circle>
            <line x1="12" y1="1" x2="12" y2="3"></line>
            <line x1="12" y1="21" x2="12" y2="23"></line>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
            <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
            <line x1="1" y1="12" x2="3" y2="12"></line>
            <line x1="21" y1="12" x2="23" y2="12"></line>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
            <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
          </svg>
        `;
      } else {
        // Ícono de luna para pasar a oscuro
        themeIcon.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
          </svg>
        `;
      }
    }
  }
}

/* ==========================================================================
   2. MOSTRAR / OCULTAR CONTRASEÑA
   ========================================================================== */
function initPasswordToggle() {
  const toggleButtons = document.querySelectorAll('.toggle-password-btn');

  toggleButtons.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = btn.getAttribute('data-target') || 'passwordInput';
      const input = document.getElementById(targetId);

      if (!input) return;

      const isPassword = input.type === 'password';
      input.type = isPassword ? 'text' : 'password';

      // Cambiar icono
      if (isPassword) {
        // Ojo tachado (Ocultar)
        btn.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
            <line x1="1" y1="1" x2="23" y2="23"></line>
          </svg>
        `;
        btn.setAttribute('aria-label', 'Ocultar contraseña');
      } else {
        // Ojo abierto (Mostrar)
        btn.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
        `;
        btn.setAttribute('aria-label', 'Mostrar contraseña');
      }
    });
  });
}

/* ==========================================================================
   3. INDICADOR DE CARGA EN FORMULARIOS (PREVENCIÓN DOBLE SUBMIT)
   ========================================================================== */
function initFormLoaders() {
  const forms = document.querySelectorAll('form');

  forms.forEach(form => {
    form.addEventListener('submit', (e) => {
      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.classList.add('loading');
        // No deshabilitamos inmediatamente con disabled=true antes del envío nativo
        // para asegurar que el evento POST envíe los datos correctamente.
        setTimeout(() => {
          submitBtn.setAttribute('disabled', 'true');
        }, 50);
      }
    });
  });
}

/* ==========================================================================
   4. MODAL SIMULADO OAUTH (GOOGLE / MICROSOFT)
   ========================================================================== */
function initSocialModals() {
  const modal = document.getElementById('socialModal');
  const modalClose = document.getElementById('modalCloseBtn');
  const modalProvider = document.getElementById('modalProviderName');
  const btnGoogle = document.getElementById('btnGoogleLogin');
  const btnMicrosoft = document.getElementById('btnMicrosoftLogin');

  function openModal(provider) {
    if (!modal) return;
    if (modalProvider) modalProvider.textContent = provider;
    modal.classList.add('active');
  }

  function closeModal() {
    if (modal) modal.classList.remove('active');
  }

  if (btnGoogle) {
    btnGoogle.addEventListener('click', () => openModal('Google Workspace'));
  }

  if (btnMicrosoft) {
    btnMicrosoft.addEventListener('click', () => openModal('Microsoft Entra ID'));
  }

  if (modalClose) {
    modalClose.addEventListener('click', closeModal);
  }

  if (modal) {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });
  }
}
