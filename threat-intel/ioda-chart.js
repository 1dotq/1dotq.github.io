(() => {
  const $ = id => document.getElementById(id);
  const slider = $('ioda-interval');
  const bars = $('ioda-bars');
  const HOUR = 3_600_000;
  const format = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'});
  const tick = new Intl.DateTimeFormat(undefined, {hour: 'numeric', minute: '2-digit'});
  let hours = 24, snapshot, buckets = [];
  let selectedMoment;

  function element(tag, text, className) {
    const item = document.createElement(tag);
    if (text) item.textContent = text;
    if (className) item.className = className;
    return item;
  }

  function render(data) {
    snapshot = data;
    const source = data?.sources?.find(item => item.source === 'ioda');
    const usable = ['ok', 'stale'].includes(source?.status);
    const end = Date.parse(data?.ioda_window?.until || data?.generated_at);
    const ready = usable && Number.isFinite(end) && Array.isArray(data.alerts);
    $('ioda-chart-body').hidden = !ready;
    $('ioda-chart-empty').hidden = ready;
    if (!ready) {
      $('ioda-chart-empty').textContent = 'IODA alert data is unavailable for this snapshot.';
      return;
    }
    const start = end - hours * HOUR;
    const step = hours * HOUR / 24;
    buckets = Array.from({length: 24}, (_, index) => ({
      from: start + index * step, to: start + (index + 1) * step, warnings: 0, critical: 0, countries: new Set(),
    }));
    const countries = new Set();
    let total = 0, critical = 0;
    for (const alert of data.alerts) {
      const time = Date.parse(alert.time);
      if (!Number.isFinite(time) || time < start || time > end) continue;
      const item = buckets[Math.min(23, Math.floor((time - start) / step))];
      if (alert.level === 'critical') { item.critical++; critical++; }
      else item.warnings++;
      total++;
      item.countries.add(alert.country_code);
      countries.add(alert.country_code);
    }
    $('ioda-total').textContent = total.toLocaleString();
    $('ioda-critical').textContent = critical.toLocaleString();
    $('ioda-countries').textContent = countries.size.toLocaleString();
    $('ioda-snapshot-status').textContent = (source.status === 'stale' ? 'Last successful snapshot · ' : 'Snapshot through ') +
      format.format(new Date(end));
    $('ioda-chart-start').textContent = tick.format(start);
    $('ioda-chart-middle').textContent = tick.format(start + hours * HOUR / 2);
    $('ioda-chart-end').textContent = tick.format(end);
    const maximum = Math.max(...buckets.map(b => b.critical + b.warnings));
    let stepLabel = 1;
    if (maximum > 4) {
      const power = 10 ** Math.floor(Math.log10(maximum / 4));
      stepLabel = ([1, 2, 5, 10].find(n => n * power >= maximum / 4) || 10) * power;
    }
    const maxScale = 4 * stepLabel;
    $('ioda-ticks').replaceChildren(...[4, 3, 2, 1, 0].map(n => element('span', String(n * stepLabel))));
    bars.replaceChildren(...buckets.map((item, index) => {
      const bar = element('button', '', 'signal-bar');
      bar.type = 'button';
      bar.tabIndex = -1;
      bar.setAttribute('aria-label', format.formatRange(new Date(item.from), new Date(item.to)) +
        ', ' + (item.critical + item.warnings) + ' alerts');
      bar.title = bar.getAttribute('aria-label');
      const fill = element('span', '', 'signal-stack');
      fill.style.height = ((item.warnings + item.critical) / maxScale * 100) + '%';
      if (item.critical) {
        const segment = element('span', '', 'signal-critical');
        segment.style.flexGrow = item.critical;
        fill.append(segment);
      }
      if (item.warnings) {
        const segment = element('span', '', 'signal-warning');
        segment.style.flexGrow = item.warnings;
        fill.append(segment);
      }
      bar.classList.toggle('is-quiet', item.critical + item.warnings === 0);
      bar.append(fill);
      bar.addEventListener('click', () => choose(index, true));
      return bar;
    }));
    const selected = buckets.findIndex(b => selectedMoment >= b.from && selectedMoment < b.to);
    const latest = buckets.findLastIndex(b => b.warnings || b.critical);
    choose(selected >= 0 ? selected : latest >= 0 ? latest : 23);
  }

  function choose(index, keep) {
    const item = buckets[index];
    if (!item) return;
    if (keep) selectedMoment = (item.from + item.to) / 2;
    slider.value = String(index);
    Array.from(bars.children).forEach((bar, i) => bar.setAttribute('aria-pressed', String(index === i)));
    const total = item.warnings + item.critical;
    const interval = format.formatRange(new Date(item.from), new Date(item.to));
    const count = total ? total + (total === 1 ? ' alert' : ' alerts') + ' · ' + item.critical + ' critical' : 'No recorded alerts';
    $('ioda-chart-value').textContent = count;
    $('ioda-chart-time').textContent = interval;
    slider.setAttribute('aria-valuetext', interval + ', ' + count);
    const link = $('ioda-chart-selection');
    const query = new URLSearchParams({at: new Date(item.from).toISOString(), minutes: String((item.to - item.from) / 60_000)});
    if (index === buckets.length - 1) query.set('last', '1');
    link.href = total ? 'map.html?' + query : 'map.html';
    link.textContent = total ? 'View interval on map →' : 'Open the 24-hour map →';
  }

  slider.addEventListener('input', () => choose(Number(slider.value), true));
  document.querySelectorAll('[data-chart-hours]').forEach(button => {
    button.addEventListener('click', () => {
      hours = Number(button.dataset.chartHours);
      selectedMoment = undefined;
      document.querySelectorAll('[data-chart-hours]').forEach(control => {
        control.setAttribute('aria-pressed', String(control === button));
      });
      render(snapshot);
    });
  });
  document.addEventListener('ioda-snapshot', event => render(event.detail));
})();
