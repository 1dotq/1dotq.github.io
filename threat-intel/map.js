(() => {
  const $ = id => document.getElementById(id);
  const viewport = $('map-viewport');
  const world = $('map-world');
  const overlay = $('map-points');
  const finder = $('map-search');
  const windowPicker = $('map-window');
  const levelPicker = $('map-level');
  const fromUrl = new URLSearchParams(location.search);
  const W = 1080, H = 540, MIN = 1, MAX = 8;
  const format = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'});
  const node = (tag, text = '', cls = '') => {
    const element = document.createElement(tag);
    element.textContent = text;
    if (cls) element.className = cls;
    return element;
  };
  const clamp = (value, min, max) => Math.max(min, Math.min(max, value));
  const requestedStart = Date.parse(fromUrl.get('at'));
  const requestedMinutes = Number(fromUrl.get('minutes'));
  const chartInterval = Number.isFinite(requestedStart) && Math.abs(requestedStart) < 8e15 && [15, 60].includes(requestedMinutes)
    ? {from: requestedStart, to: requestedStart + requestedMinutes * 60_000}
    : null;
  if (chartInterval) {
    const option = node('option', 'Chart interval · ' + format.formatRange(new Date(chartInterval.from), new Date(chartInterval.to)));
    option.value = 'chart';
    windowPicker.prepend(option);
    windowPicker.value = option.value;
  } else if (fromUrl.get('hours') === '6') {
    windowPicker.value = '6';
  }
  if (['warning', 'critical'].includes(fromUrl.get('level'))) levelPicker.value = fromUrl.get('level');
  let snapshot, selected, initialCountry = (fromUrl.get('country') || '').toUpperCase();
  let markers = [], groups = new Map();
  let zoom = 1, center = {x: W / 2, y: H / 2};
  let suppressClickUntil = 0;
  const pointers = new Map();
  let gesture = null;

  function frame() {
    const width = viewport.clientWidth, height = viewport.clientHeight;
    const scale = Math.min(width / W, height / H) * zoom;
    if (!scale) return null;
    center.x = width >= W * scale ? W / 2 : clamp(center.x, width / (2 * scale), W - width / (2 * scale));
    center.y = height >= H * scale ? H / 2 : clamp(center.y, height / (2 * scale), H - height / (2 * scale));
    return {width, height, scale, left: width / 2 - center.x * scale, top: height / 2 - center.y * scale};
  }

  function draw() {
    const view = frame();
    if (!view) return;
    world.style.transform = 'translate(' + view.left + 'px, ' + view.top + 'px) scale(' + view.scale + ')';
    for (const {button, x, y} of markers) {
      const left = view.left + x * view.scale;
      const top = view.top + y * view.scale;
      button.style.left = left + 'px';
      button.style.top = top + 'px';
      const offscreen = left < 0 || left > view.width || top < 0 || top > view.height;
      button.hidden = offscreen;
      button.tabIndex = offscreen ? -1 : 0;
    }
    $('map-zoom-level').value = zoom.toFixed(1) + '×';
    $('map-zoom-in').disabled = zoom >= MAX;
    $('map-zoom-out').disabled = zoom <= MIN;
  }

  function zoomAt(next, point = {x: viewport.clientWidth / 2, y: viewport.clientHeight / 2}) {
    const before = frame();
    if (!before) return;
    const anchor = {x: (point.x - before.left) / before.scale, y: (point.y - before.top) / before.scale};
    zoom = clamp(next, MIN, MAX);
    const scale = Math.min(before.width / W, before.height / H) * zoom;
    center = {
      x: anchor.x - (point.x - before.width / 2) / scale,
      y: anchor.y - (point.y - before.height / 2) / scale,
    };
    draw();
  }

  function pan(dx, dy) {
    const view = frame();
    if (!view) return;
    center.x -= dx / view.scale;
    center.y -= dy / view.scale;
    draw();
  }

  function point(event) {
    const rect = viewport.getBoundingClientRect();
    return {x: event.clientX - rect.left, y: event.clientY - rect.top};
  }
  function midpoint(a, b) {
    return {x: (a.x + b.x) / 2, y: (a.y + b.y) / 2};
  }
  const distance = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);
  function beginGesture() {
    const [a, b] = pointers.values();
    gesture = a ? {at: b ? midpoint(a, b) : a, distance: b ? distance(a, b) : 0, moved: Boolean(b)} : null;
  }

  viewport.addEventListener('pointerdown', event => {
    if (event.pointerType === 'mouse' && event.button !== 0) return;
    if (pointers.size >= 2) return;
    pointers.set(event.pointerId, point(event));
    beginGesture();
    if (pointers.size === 2) {
      for (const id of pointers.keys()) viewport.setPointerCapture(id);
      viewport.dataset.dragging = 'true';
    }
  });
  viewport.addEventListener('pointermove', event => {
    if (!pointers.has(event.pointerId) || !gesture) return;
    pointers.set(event.pointerId, point(event));
    const [a, b] = pointers.values();
    const at = b ? midpoint(a, b) : a;
    if (!gesture.moved && distance(gesture.at, at) < 5) return;
    if (!viewport.hasPointerCapture(event.pointerId)) viewport.setPointerCapture(event.pointerId);
    viewport.dataset.dragging = 'true';
    const separation = b ? distance(a, b) : 0;
    if (separation && gesture.distance) zoomAt(zoom * separation / gesture.distance, gesture.at);
    pan(at.x - gesture.at.x, at.y - gesture.at.y);
    gesture = {at, distance: separation, moved: true};
  });
  function end(event) {
    if (!pointers.delete(event.pointerId)) return;
    if (gesture?.moved) suppressClickUntil = performance.now() + 250;
    beginGesture();
    if (!gesture?.moved) delete viewport.dataset.dragging;
  }
  for (const type of ['pointerup', 'pointercancel', 'lostpointercapture']) viewport.addEventListener(type, end);
  viewport.addEventListener('pointerleave', event => {
    if (!viewport.hasPointerCapture(event.pointerId)) end(event);
  });
  viewport.addEventListener('wheel', event => {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault();
    zoomAt(zoom * (event.deltaY < 0 ? 1.23 : 1 / 1.23), point(event));
  }, {passive: false});

  function reset() {
    zoom = 1;
    center = {x: W / 2, y: H / 2};
    draw();
  }
  $('map-zoom-in').addEventListener('click', () => zoomAt(zoom * 1.5));
  $('map-zoom-out').addEventListener('click', () => zoomAt(zoom / 1.5));
  $('map-reset').addEventListener('click', reset);
  viewport.addEventListener('keydown', event => {
    const vectors = {ArrowLeft: [55, 0], ArrowRight: [-55, 0], ArrowUp: [0, 55], ArrowDown: [0, -55]};
    if (vectors[event.key]) pan(...vectors[event.key]);
    else if (['+', '='].includes(event.key)) zoomAt(zoom * 1.5);
    else if (event.key === '-') zoomAt(zoom / 1.5);
    else if (event.key === 'Home') reset();
    else return;
    event.preventDefault();
  });
  new ResizeObserver(draw).observe(viewport);

  async function load() {
    if (!snapshot) $('live-stamp').textContent = 'Loading public snapshot…';
    try {
      const response = await fetch('public-operations.json', {cache: 'no-cache'});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      if (!Number.isFinite(Date.parse(data.generated_at)) || !Array.isArray(data.alerts)) throw new Error('Invalid snapshot');
      snapshot = data;
      const available = data.sources?.some(source => source.source === 'ioda' && source.status === 'ok');
      $('live-stamp').textContent = available
        ? 'Snapshot ' + format.format(new Date(data.generated_at)) + ' · Refreshes every 5 minutes'
        : 'IODA alerts unavailable in this snapshot';
      render();
    } catch (_) {
      $('live-stamp').textContent = snapshot
        ? 'Refresh unavailable · Showing snapshot from ' + format.format(new Date(snapshot.generated_at))
        : 'Map data unavailable. Check IODA for current measurements.';
      if (!snapshot) $('map-list').replaceChildren(node('p', 'No snapshot loaded.', 'live-empty'));
    }
  }

  function render() {
    if (!snapshot) return;
    const end = Date.parse(snapshot.generated_at);
    const interval = windowPicker.value === 'chart' ? chartInterval
      : {from: end - Number(windowPicker.value) * 3_600_000, to: end};
    const level = levelPicker.value;
    const query = finder.value.trim().toLowerCase();
    groups = new Map();
    for (const alert of snapshot.alerts) {
      const time = Date.parse(alert.time);
      const includeEnd = windowPicker.value !== 'chart' || fromUrl.get('last') === '1';
      const allowed = time >= interval.from && (time < interval.to || includeEnd && time === interval.to);
      const matches = alert.country?.toLowerCase().includes(query) || alert.country_code?.toLowerCase() === query;
      if (!allowed || !matches || (level !== 'all' && alert.level !== level)) continue;
      if (!Number.isFinite(alert.x) || !Number.isFinite(alert.y)) continue;
      if (!groups.has(alert.country_code)) groups.set(alert.country_code, []);
      groups.get(alert.country_code).push(alert);
    }
    const all = [...groups.values()].flat();
    $('map-country-count').textContent = groups.size;
    $('map-alert-count').textContent = all.length;
    $('map-critical-count').textContent = all.filter(alert => alert.level === 'critical').length;
    const list = $('map-list');
    const ordered = [...groups.entries()].sort((a, b) => b[1].length - a[1].length);
    const listItems = [];
    markers = [];
    for (const [code, items] of ordered) {
      items.sort((a, b) => Date.parse(b.time) - Date.parse(a.time));
      const first = items[0];
      const critical = items.some(alert => alert.level === 'critical');
      const count = items.length + (items.length === 1 ? ' alert' : ' alerts');
      const title = first.country + ' · ' + count;
      const marker = node('button', String(items.length), 'map-point' + (critical ? ' critical' : ''));
      const entry = node('button', '', 'live-item');
      for (const button of [marker, entry]) {
        button.type = 'button';
        button.dataset.code = code;
        button.addEventListener('click', event => {
          if (button === marker && event.detail && performance.now() < suppressClickUntil) return;
          select(code, true);
        });
      }
      marker.title = title;
      marker.setAttribute('aria-label', title + (critical ? ' · includes critical alerts' : ''));
      entry.append(node('strong', title), node('small', 'Latest ' + format.format(new Date(first.time)) + ' · ' + first.level));
      markers.push({button: marker, x: first.x, y: first.y});
      listItems.push(entry);
    }
    overlay.replaceChildren(...markers.map(marker => marker.button));
    list.replaceChildren(...listItems);
    if (!ordered.length) {
      const sourceOk = snapshot.sources?.some(source => source.source === 'ioda' && source.status === 'ok');
      list.append(node('p', sourceOk ? 'No located alerts match these filters.' : 'IODA alert data is unavailable.', 'live-empty'));
      $('map-detail').textContent = 'No country selected.';
      draw();
      return;
    }
    if (initialCountry && groups.has(initialCountry)) select(initialCountry, true);
    else select(groups.has(selected) ? selected : ordered[0][0]);
    initialCountry = '';
  }

  function select(code, focusMap = false) {
    const items = groups.get(code);
    const first = items[0];
    selected = code;
    for (const button of document.querySelectorAll('#map-list button, #map-points button')) {
      button.setAttribute('aria-pressed', String(button.dataset.code === code));
    }
    if (focusMap) {
      zoom = Math.max(2.25, zoom);
      center = {x: first.x, y: first.y};
      const url = new URL(location.href);
      url.searchParams.set('country', code);
      if (windowPicker.value !== 'chart') {
        url.searchParams.delete('at');
        url.searchParams.delete('minutes');
        url.searchParams.delete('last');
        url.searchParams.set('hours', windowPicker.value);
      }
      if (levelPicker.value !== 'all') url.searchParams.set('level', levelPicker.value);
      else url.searchParams.delete('level');
      history.replaceState(null, '', url);
    }
    const detail = $('map-detail');
    detail.replaceChildren(node('h3', first.country), node('p', items.length + ' IODA alerts in this view.'));
    const list = node('ul');
    for (const alert of items.slice(0, 12)) {
      const listItem = node('li', [alert.name, alert.level, alert.datasource, format.format(new Date(alert.time))].filter(Boolean).join(' · '));
      list.append(listItem);
    }
    detail.append(list);
    const source = node('a', 'Open IODA country measurements ↗');
    source.href = 'https://ioda.inetintel.cc.gatech.edu/country/' + encodeURIComponent(code);
    detail.append(source);
    draw();
  }

  for (const picker of [windowPicker, levelPicker]) picker.addEventListener('change', render);
  finder.addEventListener('input', render);
  $('map-refresh').addEventListener('click', load);
  load();
  setInterval(load, 300_000);
})();
