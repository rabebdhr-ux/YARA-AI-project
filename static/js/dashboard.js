/**
 * YARA AI Platform — Dashboard Charts
 * Vanilla JS canvas chart for scan activity
 */

(function () {
  'use strict';

  const canvas = document.getElementById('scanActivityChart');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const data = [42, 58, 35, 72, 65, 48, 81];
  const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  function getThemeColors() {
    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
    return {
      grid: isDark ? '#334155' : '#e2e8f0',
      text: isDark ? '#94a3b8' : '#64748b',
      line: '#3b82f6',
      fill: isDark ? 'rgba(59,130,246,0.15)' : 'rgba(59,130,246,0.1)',
      point: '#3b82f6'
    };
  }

  function drawChart() {
    const colors = getThemeColors();
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = 200 * dpr;
    ctx.scale(dpr, dpr);

    const width = rect.width;
    const height = 200;
    const padding = { top: 20, right: 20, bottom: 30, left: 40 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    ctx.clearRect(0, 0, width, height);

    const maxVal = Math.max(...data) * 1.1;
    const stepX = chartW / (data.length - 1);

    // Grid lines
    ctx.strokeStyle = colors.grid;
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padding.top + (chartH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(padding.left, y);
      ctx.lineTo(width - padding.right, y);
      ctx.stroke();
    }

    // Labels
    ctx.fillStyle = colors.text;
    ctx.font = '11px Inter, sans-serif';
    ctx.textAlign = 'center';
    labels.forEach(function (label, i) {
      const x = padding.left + stepX * i;
      ctx.fillText(label, x, height - 8);
    });

    // Area fill
    ctx.beginPath();
    ctx.moveTo(padding.left, padding.top + chartH);
    data.forEach(function (val, i) {
      const x = padding.left + stepX * i;
      const y = padding.top + chartH - (val / maxVal) * chartH;
      if (i === 0) ctx.lineTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(padding.left + stepX * (data.length - 1), padding.top + chartH);
    ctx.closePath();
    ctx.fillStyle = colors.fill;
    ctx.fill();

    // Line
    ctx.beginPath();
    ctx.strokeStyle = colors.line;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    data.forEach(function (val, i) {
      const x = padding.left + stepX * i;
      const y = padding.top + chartH - (val / maxVal) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    // Points
    data.forEach(function (val, i) {
      const x = padding.left + stepX * i;
      const y = padding.top + chartH - (val / maxVal) * chartH;
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = colors.point;
      ctx.fill();
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2;
      ctx.stroke();
    });
  }

  drawChart();
  window.addEventListener('resize', drawChart);

  document.getElementById('themeToggle')?.addEventListener('click', function () {
    setTimeout(drawChart, 50);
  });
})();
