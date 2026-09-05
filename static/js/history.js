/**
 * YARA AI Platform — Scan History & Reports Filtering
 */

(function () {
  'use strict';

  /* --- History Table Filters --- */
  const historyTable = document.getElementById('historyTable');
  const historyEmpty = document.getElementById('historyEmpty');
  const filterDate = document.getElementById('filterDate');
  const filterThreat = document.getElementById('filterThreat');
  const filterType = document.getElementById('filterType');
  const filterYara = document.getElementById('filterYara');
  const filterSearch = document.getElementById('filterSearch');

  function filterHistory() {
    if (!historyTable) return;
    const rows = historyTable.querySelectorAll('tbody tr');
    const threat = filterThreat?.value || '';
    const type = filterType?.value || '';
    const yara = filterYara?.value || '';
    const search = (filterSearch?.value || '').toLowerCase();
    let visible = 0;

    rows.forEach(function (row) {
      let show = true;
      if (threat && row.getAttribute('data-threat') !== threat) show = false;
      if (type && row.getAttribute('data-type') !== type) show = false;
      if (yara && row.getAttribute('data-yara') !== yara) show = false;
      if (search) {
        const filename = row.getAttribute('data-filename') || '';
        const hash = row.getAttribute('data-hash') || '';
        if (!filename.includes(search) && !hash.includes(search)) show = false;
      }
      row.style.display = show ? '' : 'none';
      if (show) visible++;
    });

    if (historyEmpty) historyEmpty.hidden = visible > 0;
  }

  [filterThreat, filterType, filterYara, filterSearch].forEach(function (el) {
    el?.addEventListener('input', filterHistory);
    el?.addEventListener('change', filterHistory);
  });

  /* --- Delete Modal --- */
  let deleteTargetId = null;

  document.querySelectorAll('[data-delete-scan]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      deleteTargetId = btn.getAttribute('data-delete-scan');
      window.YaraModal?.open('deleteModal');
    });
  });

  document.getElementById('confirmDeleteBtn')?.addEventListener('click', function () {
    if (deleteTargetId) {
      const row = document.querySelector('[data-delete-scan="' + deleteTargetId + '"]')?.closest('tr');
      row?.remove();
      deleteTargetId = null;
      filterHistory();
    }
    window.YaraModal?.close('deleteModal');
  });

  /* --- Reports Table Filters --- */
  const reportsTable = document.getElementById('reportsTable');
  const reportSearch = document.getElementById('reportSearch');
  const reportStatus = document.getElementById('reportStatus');

  function filterReports() {
    if (!reportsTable) return;
    const rows = reportsTable.querySelectorAll('tbody tr');
    const status = reportStatus?.value || '';
    const search = (reportSearch?.value || '').toLowerCase();

    rows.forEach(function (row) {
      let show = true;
      if (status && row.getAttribute('data-status') !== status) show = false;
      if (search) {
        const data = row.getAttribute('data-search') || '';
        if (!data.includes(search)) show = false;
      }
      row.style.display = show ? '' : 'none';
    });
  }

  reportSearch?.addEventListener('input', filterReports);
  reportStatus?.addEventListener('change', filterReports);
})();
