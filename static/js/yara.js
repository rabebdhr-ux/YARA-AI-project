/**
 * YARA AI Platform — YARA Rule Analyzer
 * Tab switching, file upload, basic syntax highlighting
 */

(function () {
  'use strict';

  /* --- Tab Switching --- */
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanels = document.querySelectorAll('.tab-panel');

  tabBtns.forEach(function (btn) {
    btn.addEventListener('click', function () {
      const tab = btn.getAttribute('data-tab');
      tabBtns.forEach(function (b) {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabPanels.forEach(function (p) {
        p.classList.remove('active');
        p.hidden = true;
      });
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const panel = document.getElementById('tab-' + tab);
      if (panel) {
        panel.classList.add('active');
        panel.hidden = false;
      }
    });
  });

  /* --- YARA File Upload --- */
  const yaraFileInput = document.getElementById('yaraFileInput');
  const yaraSelectFileBtn = document.getElementById('yaraSelectFileBtn');
  const yaraFileName = document.getElementById('yaraFileName');
  const yaraRuleInput = document.getElementById('yaraRuleInput');

  yaraSelectFileBtn?.addEventListener('click', function () {
    yaraFileInput?.click();
  });

  yaraFileInput?.addEventListener('change', function () {
    const file = yaraFileInput.files[0];
    if (!file) return;
    yaraFileName.textContent = file.name;
    const reader = new FileReader();
    reader.onload = function (e) {
      if (yaraRuleInput) yaraRuleInput.value = e.target.result;
    };
    reader.readAsText(file);
  });

  /* --- Basic YARA Syntax Highlighting (CSS classes via overlay approach) --- */
  function highlightYara(text) {
    return text
      .replace(/(\/\/.*$)/gm, '<span class="yara-comment">$1</span>')
      .replace(/\b(rule|meta|strings|condition|and|or|not|any|all|of|them|filesize|matches|contains|startswith|endswith|nocase|wide|ascii|fullword|private|global|import|include)\b/g, '<span class="yara-keyword">$1</span>')
      .replace(/(\$[a-zA-Z0-9_]+)/g, '<span class="yara-var">$1</span>')
      .replace(/("(?:[^"\\]|\\.)*")/g, '<span class="yara-string">$1</span>');
  }

  /* --- Form Submit (demo redirect) --- */
  const yaraForm = document.getElementById('yaraAnalyzeForm');
  yaraForm?.addEventListener('submit', function (e) {
    const ruleText = yaraRuleInput?.value.trim();
    if (!ruleText) {
      e.preventDefault();
      alert('Please enter or upload a YARA rule to analyze.');
      return;
    }
    /* When backend is ready, let form submit normally to POST /yara/analyze */
    /* For demo without backend: */
    if (yaraForm.action.includes('yara_analyze') || yaraForm.action.includes('/yara/analyze')) {
      /* Allow Flask to handle; if no backend, uncomment below */
      /* e.preventDefault();
      window.location.href = '/yara/result'; */
    }
  });
})();
