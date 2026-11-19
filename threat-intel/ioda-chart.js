(() => {
  const $ = id => document.getElementById(id);
  const canvas = $('ioda-chart');
  const slider = $('ioda-interval');
  const ctx = canvas.getContext('2d');
  const format = new Intl.DateTimeFormat(undefined, {hour: 'numeric', minute: '2-digit'});
  const HOUR = 3_600_000;
  let snapshot, buckets = [], selected = 0, bounds;
  let hours = 24;

  function onSnapshot(data) {
    snapshot = data;
    const end = Date.parse(data?.generated_at);
    const source = data?.sources?.find(item => item.source === 'ioda');
    const ready = Number.isFinite(end) && source?.status === 'ok' && Array.isArray(data.alerts);
    $('ioda-chart-body').hidden = !ready;
    $('ioda-chart-empty').hidden = ready;
    if (!ready) {
      buckets = [];
      $('ioda-chart-empty').textContent = 'IODA alert data is unavailable for this snapshot.';
      return;
    }
    const start = end - hours * HOUR;
    const step = hours * HOUR / 24;
    buckets = Array.from({length: 24}, (_, index) => ({
      from: start + index * step, to: start + (index + 1) * step, total: 0, critical: 0,
    }));
    for (const alert of data.alerts) {
      const time = Date.parse(alert.time);
      if (!Number.isFinite(time) || time < start || time > end) continue;
      const bucket = buckets[Math.min(23, Math.floor((time - start) / step))];
      bucket.total += 1;
      if (alert.level === 'critical') bucket.critical += 1;
    }
    const peak = buckets.reduce((index, bucket, position) =>
      bucket.total >= buckets[index].total ? position : index, 0);
    choose(peak);
  }

  function choose(index) {
    selected = index;
    slider.value = String(index);
    const {from, to, total, critical} = buckets[index];
    const interval = format.formatRange(new Date(from), new Date(to));
    const counts = total + (total === 1 ? ' alert' : ' alerts') + ' · ' + critical + ' critical';
    $('ioda-chart-value').textContent = counts;
    $('ioda-chart-time').textContent = interval;
    slider.setAttribute('aria-valuetext', interval + ', ' + counts);
    const intervalQuery = new URLSearchParams({at: new Date(from).toISOString(), minutes: String((to - from) / 60_000)});
    if (index === buckets.length - 1) intervalQuery.set('last', '1');
    $('ioda-chart-selection').href = 'map.html?' + intervalQuery;
    paint();
  }

  function paint() {
    if (!buckets.length || !ctx || !canvas.clientWidth) return;
    const width = canvas.clientWidth, height = canvas.clientHeight;
    const scale = Math.min(devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    ctx.scale(scale, scale);
    const plot = {left: 31, right: width - 12, top: 15, base: height - 14};
    bounds = plot;
    const peak = Math.max(...buckets.map(b => b.total));
    const step = Math.max(1, Math.ceil(peak / 4));
    const y = count => plot.base - count / (4 * step) * (plot.base - plot.top);
    const x = index => plot.left + index * (plot.right - plot.left) / (buckets.length - 1);
    ctx.font = '11px Inter, system-ui, sans-serif';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#9bb5d0';
    for (let level = 0; level <= 4; level++) {
      const row = y(level * step);
      ctx.strokeStyle = '#2a4563';
      ctx.setLineDash([5, 7]);
      ctx.beginPath();
      ctx.moveTo(plot.left, row);
      ctx.lineTo(plot.right, row);
      ctx.stroke();
      ctx.fillText(String(level * step), 2, row);
    }
    const trace = () => {
      ctx.moveTo(x(0), y(buckets[0].total));
      buckets.slice(1).forEach((bucket, index) => ctx.lineTo(x(index + 1), y(bucket.total)));
    };
    const fill = ctx.createLinearGradient(0, plot.top, 0, plot.base);
    fill.addColorStop(0, 'rgba(255, 125, 116, .38)');
    fill.addColorStop(1, 'rgba(255, 125, 116, .025)');
    ctx.fillStyle = fill;
    ctx.beginPath();
    trace();
    ctx.lineTo(plot.right, plot.base);
    ctx.lineTo(plot.left, plot.base);
    ctx.closePath();
    ctx.fill();
    ctx.strokeStyle = '#ff847a';
    ctx.lineWidth = 3;
    ctx.lineJoin = 'round';
    ctx.setLineDash([]);
    ctx.beginPath();
    trace();
    ctx.stroke();
    const pointX = x(selected), pointY = y(buckets[selected].total);
    ctx.strokeStyle = '#5d7895';
    ctx.lineWidth = 1;
    ctx.setLineDash([4, 4]);
    ctx.beginPath();
    ctx.moveTo(pointX, plot.top);
    ctx.lineTo(pointX, plot.base);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = '#ff9c92';
    ctx.strokeStyle = '#0b1829';
    ctx.lineWidth = 3;
    ctx.beginPath();
    ctx.arc(pointX, pointY, 6, 0, 2 * Math.PI);
    ctx.fill();
    ctx.stroke();
  }

  canvas.addEventListener('pointermove', event => {
    if (event.pointerType === 'mouse') inspect(event);
  });
  canvas.addEventListener('click', inspect);
  function inspect(event) {
    if (!bounds || !buckets.length) return;
    const position = event.clientX - canvas.getBoundingClientRect().left - bounds.left;
    const index = Math.round(position / (bounds.right - bounds.left) * (buckets.length - 1));
    choose(Math.max(0, Math.min(buckets.length - 1, index)));
  }
  slider.addEventListener('input', () => choose(Number(slider.value)));
  document.querySelectorAll('[data-chart-hours]').forEach(button => {
    button.addEventListener('click', () => {
      hours = Number(button.dataset.chartHours);
      document.querySelectorAll('[data-chart-hours]').forEach(control => {
        control.setAttribute('aria-pressed', String(control === button));
      });
      $('ioda-chart-start').textContent = hours + 'h before';
      $('ioda-chart-middle').textContent = hours / 2 + 'h before';
      onSnapshot(snapshot);
    });
  });
  new ResizeObserver(paint).observe(canvas);
  document.addEventListener('ioda-snapshot', event => onSnapshot(event.detail));
})();
