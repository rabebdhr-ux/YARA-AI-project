/**
 * YARA AI Platform — Core Application JavaScript
 * Sidebar, theme, dropdowns, modals, alerts, utilities
 */

(function () {
  'use strict';

  /* --- Sidebar Toggle (Mobile/Tablet) --- */
  const sidebar = document.getElementById('sidebar');
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  const menuToggle = document.getElementById('menuToggle');

  function openSidebar() {
    sidebar?.classList.add('open');
    sidebarOverlay?.classList.add('active');
    document.body.style.overflow = 'hidden';
  }

  function closeSidebar() {
    sidebar?.classList.remove('open');
    sidebarOverlay?.classList.remove('active');
    document.body.style.overflow = '';
  }

  menuToggle?.addEventListener('click', function () {
    if (sidebar?.classList.contains('open')) {
      closeSidebar();
    } else {
      openSidebar();
    }
  });

  sidebarOverlay?.addEventListener('click', closeSidebar);

  window.addEventListener('resize', function () {
    if (window.innerWidth > 768) {
      closeSidebar();
    }
  });

  /* --- Theme Toggle --- */
  const themeToggle = document.getElementById('themeToggle');
  const html = document.documentElement;
  const savedTheme = localStorage.getItem('yara-theme') || 'dark';
  html.setAttribute('data-theme', savedTheme);

  themeToggle?.addEventListener('click', function () {
    const current = html.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    localStorage.setItem('yara-theme', next);
  });

  /* --- Dropdowns --- */
  function setupDropdown(toggleId, dropdownId) {
    const toggle = document.getElementById(toggleId);
    const dropdown = document.getElementById(dropdownId);
    if (!toggle || !dropdown) return;

    toggle.addEventListener('click', function (e) {
      e.stopPropagation();
      const isActive = dropdown.classList.contains('active');
      closeAllDropdowns();
      if (!isActive) dropdown.classList.add('active');
    });
  }

  function closeAllDropdowns() {
    document.querySelectorAll('.notif-dropdown, .profile-dropdown').forEach(function (el) {
      el.classList.remove('active');
    });
  }

  setupDropdown('notifToggle', 'notifDropdown');
  setupDropdown('profileToggle', 'profileDropdown');

  document.addEventListener('click', closeAllDropdowns);

  /* --- Alert Dismiss --- */
  document.querySelectorAll('.alert--dismissible .alert__close').forEach(function (btn) {
    btn.addEventListener('click', function () {
      btn.closest('.alert')?.remove();
    });
  });

  /* --- Modal System --- */
  window.YaraModal = {
    open: function (modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.hidden = false;
        document.body.style.overflow = 'hidden';
      }
    },
    close: function (modalId) {
      const modal = document.getElementById(modalId);
      if (modal) {
        modal.hidden = true;
        document.body.style.overflow = '';
      }
    }
  };

  document.querySelectorAll('[data-modal-close]').forEach(function (el) {
    el.addEventListener('click', function () {
      const modal = el.closest('.modal');
      if (modal) {
        modal.hidden = true;
        document.body.style.overflow = '';
      }
    });
  });

  /* --- Copy to Clipboard (Code Blocks) --- */
  document.querySelectorAll('.code-block__copy').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const block = btn.closest('.code-block');
      const code = block?.querySelector('code');
      if (code) {
        navigator.clipboard.writeText(code.textContent).then(function () {
          btn.setAttribute('aria-label', 'Copied!');
          setTimeout(function () {
            btn.setAttribute('aria-label', 'Copy code');
          }, 2000);
        });
      }
    });
  });

  /* --- Score Ring Animation --- */
  document.querySelectorAll('.score-card__ring').forEach(function (ring) {
    const score = ring.getAttribute('data-score') || 78;
    ring.style.setProperty('--score', score);
  });

  /* --- Utility: Format File Size --- */
  window.formatFileSize = function (bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  /* --- Utility: Get File Extension --- */
  window.getFileExtension = function (filename) {
    return filename.split('.').pop().toUpperCase();
  };

  /* --- Supported File Types --- */
  window.SUPPORTED_TYPES = ['EXE', 'DLL', 'PDF', 'DOC', 'DOCX', 'XLS', 'XLSX', 'JS', 'VBS', 'PS1', 'ZIP', 'TXT', 'BIN'];
  window.MAX_FILE_SIZE = 20 * 1024 * 1024; // 20 MB

  window.validateFile = function (file) {
    if (!file) return { valid: false, error: 'No file selected.' };
    if (file.size > window.MAX_FILE_SIZE) {
      return { valid: false, error: 'File exceeds maximum size of 20 MB.' };
    }
    const ext = window.getFileExtension(file.name);
    if (!window.SUPPORTED_TYPES.includes(ext)) {
      return {
        valid: false,
        error: 'Unsupported file type. Allowed: ' + window.SUPPORTED_TYPES.join(', ')
      };
    }
    return { valid: true };
  };
})();