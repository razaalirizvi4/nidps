// Thin wrapper around Chart.js (vendored at frontend/vendor/chart.umd.min.js, loaded globally as
// window.Chart by index.html) for the traffic-history line chart. Reads colors from the current
// CSS theme variables so it follows the dark/light toggle without a separate chart theme file.
const instances = new Map();

function themeColor(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function renderLineChart(canvasId, { labels, data, label = 'Throughput (KB/s)' }) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !window.Chart) return;

  const existing = instances.get(canvasId);
  if (existing) {
    existing.data.labels = labels;
    existing.data.datasets[0].data = data;
    existing.update();
    return existing;
  }

  const accent = themeColor('--accent') || '#8cc7d9';
  const rule = themeColor('--rule') || '#262b31';
  const textSoft = themeColor('--text-soft') || '#a9aeb5';

  const chart = new window.Chart(canvas.getContext('2d'), {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label,
          data,
          borderColor: accent,
          backgroundColor: `${accent}22`,
          fill: true,
          tension: 0.25,
          pointRadius: 0,
          borderWidth: 1.5,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 200 },
      plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
      scales: {
        x: { ticks: { color: textSoft, maxTicksLimit: 8, font: { family: 'IBM Plex Mono', size: 10 } }, grid: { color: rule } },
        y: { ticks: { color: textSoft, font: { family: 'IBM Plex Mono', size: 10 } }, grid: { color: rule } },
      },
    },
  });
  instances.set(canvasId, chart);
  return chart;
}

export function destroyChart(canvasId) {
  instances.get(canvasId)?.destroy();
  instances.delete(canvasId);
}
