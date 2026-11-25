(() => {
  'use strict';

  const $ = id => document.getElementById(id);
  const types = {
    vulnerability: 'CVE', actor: 'Threat actor', campaign: 'Campaign', malware: 'Malware',
    tool: 'Tool', technique: 'ATT&CK technique', sector: 'Sector', incident: 'Incident'
  };
  const priority = ['vulnerability', 'sector', 'incident', 'campaign', 'malware', 'tool', 'technique', 'actor'];
  const namespace = 'http://www.w3.org/2000/svg';
  const pageSize = 12;
  const dayMs = 86400000;
  const cvePattern = /^CVE-\d{4}-\d{4,}$/;
  const initial = new URLSearchParams(location.search);
  const publicData = new Map();
  const adjacent = new Map();
  let nodes = new Map();
  let trail = [];
  let page = 0;
  let selectedEdge = null;
  let latestDay = null;
  let startingActors = [];

  function nextStartingActor() {
    if (!startingActors.length) return null;
    let previous = current()?.id;
    try { previous ||= sessionStorage.getItem('1dotq-graph-starting-actor'); } catch {}
    const index = startingActors.findIndex(actor => actor.id === previous);
    const start = index === -1 ? Math.floor(Math.random() * startingActors.length) : (index + 1) % startingActors.length;
    const next = startingActors[start];
    try { sessionStorage.setItem('1dotq-graph-starting-actor', next.id); } catch {}
    return next;
  }

  function element(tag, text = '', className = '') {
    const node = document.createElement(tag);
    node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  function svg(tag, attributes) {
    const node = document.createElementNS(namespace, tag);
    for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
    return node;
  }

  function button(label, callback, className = 'live-button') {
    const control = element('button', label, className);
    control.type = 'button';
    control.addEventListener('click', callback);
    return control;
  }

  function link(label, href) {
    const anchor = element('a', label);
    anchor.href = href;
    return anchor;
  }

  function citationLink(href) {
    try {
      const url = new URL(href);
      if (url.protocol !== 'https:' || url.username || url.password) return null;
      const anchor = link('Open source ↗', url.href);
      anchor.target = '_blank';
      anchor.rel = 'noopener noreferrer';
      return anchor;
    } catch {
      return null;
    }
  }

  function isoDay(value) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return null;
    const date = new Date(value);
    return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 10) === value ? value : null;
  }

  const dayNumber = date => Date.parse(date) / dayMs;
  const dayString = day => new Date(day * dayMs).toISOString().slice(0, 10);
  const current = () => nodes.get(trail.at(-1)?.id);

  function edgeCitations(edge) {
    if (Array.isArray(edge.citations)) return edge.citations;
    const publisher = {'MITRE ATT&CK STIX': 'MITRE ATT&CK', 'CISA joint advisory': 'Joint government advisory'}[edge.evidence];
    return edge.url || publisher ? [{publisher, url: edge.url}] : [];
  }

  function indexEdges(edges) {
    for (const [index, edge] of edges.entries()) {
      if (!nodes.has(edge.source) || !nodes.has(edge.target)) continue;
      const citations = edgeCitations(edge);
      for (const [center, neighbor] of [[edge.source, edge.target], [edge.target, edge.source]]) {
        if (!adjacent.has(center)) adjacent.set(center, []);
        adjacent.get(center).push({index, neighbor: nodes.get(neighbor), type: edge.type, citations});
      }
    }
    for (const connections of adjacent.values()) {
      connections.sort((a, b) => priority.indexOf(a.neighbor.type) - priority.indexOf(b.neighbor.type)
        || a.neighbor.name.localeCompare(b.neighbor.name) || a.type.localeCompare(b.type));
    }
  }

  function selectDate(value) {
    const date = $('graph-date');
    const valid = isoDay(value);
    date.value = valid && date.max ? [date.max, valid].sort()[0] : '';
    $('graph-slider').value = date.value ? Math.max(dayNumber(date.value), Number($('graph-slider').min)) : latestDay;
  }

  function configureFilters(edges) {
    const evidence = edges.flatMap(edgeCitations);
    const publishers = [...new Set(evidence.map(c => c.publisher).filter(Boolean))].sort();
    const source = $('graph-source');
    for (const publisher of publishers) {
      const option = element('option', publisher);
      option.value = publisher;
      source.append(option);
    }
    if (publishers.includes(initial.get('source'))) source.value = initial.get('source');
    const type = initial.get('type');
    if (Object.hasOwn(types, type)) $('graph-type').value = type;
    const dates = evidence.map(c => isoDay(c.date)).filter(Boolean).sort();
    if (!dates.length) {
      $('graph-date-note').textContent = 'This snapshot has no dated citations.';
      return;
    }
    const slider = $('graph-slider');
    slider.min = dayNumber(dates[0]);
    latestDay = dayNumber(dates.at(-1)) + 1;
    slider.max = latestDay;
    $('graph-date').max = dates.at(-1);
    $('graph-date').disabled = slider.disabled = false;
    selectDate(initial.get('through'));
  }

  function updateAddress() {
    const url = new URL(location.href);
    for (const [key, value] of Object.entries({
      entity: current().external_id || current().id,
      type: $('graph-type').value,
      source: $('graph-source').value,
      through: $('graph-date').value
    })) {
      if (value) url.searchParams.set(key, value);
      else url.searchParams.delete(key);
    }
    history.replaceState(null, '', url);
  }

  function resetPage() {
    page = 0;
    selectedEdge = null;
    setViewport(1, 0, 0);
  }

  function navigate(id, restart = false) {
    if (!nodes.has(id)) return;
    const filter = $('graph-type');
    if (restart) trail = [{id, type: filter.value}];
    else if (id !== current()?.id) {
      if (filter.value && !filteredConnections(id).length) filter.value = '';
      trail.push({id, type: filter.value});
    }
    resetPage();
    $('graph-matches').hidden = true;
    render();
  }

  function backTo(index) {
    if (index < 0) return;
    trail = trail.slice(0, index + 1);
    $('graph-type').value = trail.at(-1).type;
    resetPage();
    render();
  }

  function renderTrail() {
    const list = element('ol');
    const start = Math.max(0, trail.length - 5);
    if (start) list.append(element('li', '…'));
    for (let i = start; i < trail.length; i++) {
      const item = element('li');
      const name = nodes.get(trail[i].id).name;
      if (i === trail.length - 1) {
        item.textContent = name;
        item.setAttribute('aria-current', 'location');
      } else {
        item.append(button(name, () => backTo(i), 'graph-trail-link'));
      }
      list.append(item);
    }
    $('graph-trail').replaceChildren(list);
    $('graph-back').disabled = trail.length < 2;
  }

  function filteredConnections(id, type = $('graph-type').value) {
    const publisher = $('graph-source').value;
    const cutoff = $('graph-date').value;
    const connections = adjacent.get(id) || [];
    return connections.flatMap(edge => {
      if (type && edge.neighbor.type !== type) return [];
      const citations = edge.citations.filter(citation =>
        (!publisher || citation.publisher === publisher) &&
        (!cutoff || (isoDay(citation.date) && citation.date <= cutoff))
      );
      return citations.length || (!publisher && !cutoff) ? [{...edge, citations}] : [];
    });
  }

  function publisherCount(edge) {
    return new Set(edge.citations.map(c => c.publisher).filter(Boolean)).size;
  }

  function openEdge(edge) {
    const detail = $('graph-edge-' + edge.index);
    if (!detail) return;
    if (selectedEdge) $('graph-edge-' + selectedEdge.index)?.removeAttribute('open');
    selectedEdge = edge;
    const canvas = $('graph-canvas');
    canvas.querySelectorAll('.is-selected').forEach(node => node.classList.remove('is-selected'));
    canvas.querySelectorAll('[data-relationship="' + edge.index + '"]').forEach(node => node.classList.add('is-selected'));
    detail.open = true;
    $('graph-active-edge').hidden = false;
    $('graph-active-edge').textContent = edge.type + ' · ' + edge.neighbor.name;
    detail.querySelector('summary').focus();
    detail.scrollIntoView({block: 'nearest'});
  }

  const mapSize = {width: 960, height: 590};
  const clusterHomes = {
    actor: [176, 245], vulnerability: [247, 126], campaign: [245, 339], sector: [337, 492],
    incident: [700, 455], malware: [750, 224], tool: [538, 463], technique: [543, 142]
  };
  const viewport = {scale: 1, x: 0, y: 0};
  let mapWorld, overviewFrame, pointer;

  function setViewport(scale, x, y) {
    viewport.scale = Math.min(3.5, Math.max(1, scale));
    viewport.x = Math.max(mapSize.width * (1 - viewport.scale), Math.min(0, x));
    viewport.y = Math.max(mapSize.height * (1 - viewport.scale), Math.min(0, y));
    mapWorld?.setAttribute('transform', ['translate(' + viewport.x + ' ' + viewport.y + ')', 'scale(' + viewport.scale + ')'].join(' '));
    if (overviewFrame) {
      for (const [key, value] of Object.entries({
        x: -viewport.x / viewport.scale, y: -viewport.y / viewport.scale,
        width: mapSize.width / viewport.scale, height: mapSize.height / viewport.scale
      })) overviewFrame.setAttribute(key, value);
    }
    $('graph-scale').textContent = Math.round(viewport.scale * 100) + '%';
    $('graph-canvas').classList.toggle('can-pan', viewport.scale > 1);
    $('graph-zoom-out').disabled = viewport.scale === 1;
    $('graph-zoom-in').disabled = viewport.scale === 3.5;
    $('graph-zoom-reset').disabled = viewport.scale === 1;
  }

  function zoom(step) {
    const scale = Math.min(3.5, Math.max(1, viewport.scale + step));
    const ratio = scale / viewport.scale;
    const x = mapSize.width / 2;
    const y = mapSize.height / 2;
    setViewport(scale, x - (x - viewport.x) * ratio, y - (y - viewport.y) * ratio);
  }

  function panBy(dx, dy) {
    setViewport(viewport.scale, viewport.x + dx, viewport.y + dy);
  }

  function mapGroups(edges) {
    const groups = new Map();
    for (const edge of edges) {
      const type = edge.neighbor.type;
      if (!groups.has(type)) groups.set(type, []);
      groups.get(type).push(edge);
    }
    return groups;
  }

  function renderClusters(groups) {
    const active = $('graph-type').value;
    const filter = type => {
      $('graph-type').value = type;
      resetPage();
      render();
      $('graph-clusters').querySelector('[aria-pressed=true]')?.focus({preventScroll: true});
    };
    const picks = [button('All types', () => filter(''), 'graph-cluster-filter')];
    picks[0].setAttribute('aria-pressed', String(!active));
    for (const [type, edges] of groups) {
      const pick = button((types[type] || type) + ' ' + edges.length, () => filter(type === active ? '' : type), 'graph-cluster-filter ' + type);
      pick.setAttribute('aria-pressed', String(type === active));
      picks.push(pick);
    }
    $('graph-clusters').replaceChildren(...picks);
  }

  function shorten(text, size) {
    return text.length > size ? text.slice(0, size - 1) + '…' : text;
  }

  function mapPositions(groups, pageEdges) {
    const positions = [];
    const clusters = [];
    const singleCluster = groups.size === 1;
    const center = singleCluster ? [315, 295] : [465, 296];
    const selected = new Set(pageEdges.map(edge => edge.index));
    for (const [type, edges] of groups) {
      const home = singleCluster ? [665, 292] : (clusterHomes[type] || [710, 310]);
      const cap = singleCluster ? 64 : 32;
      const pointEdges = edges.length > cap
        ? [...edges.filter(edge => selected.has(edge.index)), ...edges.filter(edge => !selected.has(edge.index))].slice(0, cap)
        : edges;
      const radius = Math.max(18, (singleCluster ? 18 : 13) * Math.sqrt(pointEdges.length));
      for (const [i, edge] of pointEdges.entries()) {
        const angle = i * Math.PI * (3 - Math.sqrt(5)) - Math.PI / 2;
        const distance = pointEdges.length === 1 ? 0 : radius * Math.sqrt((i + .45) / pointEdges.length);
        positions.push({edge, x: home[0] + Math.cos(angle) * distance, y: home[1] + Math.sin(angle) * distance});
      }
      clusters.push({type, x: home[0], y: home[1] - radius - 9,
        label: edges.length === 1 ? shorten(edges[0].neighbor.name, 36) : (types[type] || type) + ' · ' + edges.length});
    }
    return {positions, clusters, center, selected};
  }

  function mapLabel(text, x, y, className) {
    const tag = svg('g', {class: className, transform: 'translate(' + x + ' ' + y + ')'});
    const label = svg('text', {x: 0, y: 4});
    label.textContent = text;
    tag.append(svg('rect', {x: -text.length * 3.5 - 9, y: -12, width: text.length * 7 + 18, height: 24, rx: 5}), label);
    return tag;
  }

  function drawGraph(node, groups, edges, pageEdges) {
    const canvas = $('graph-canvas');
    const overview = $('graph-overview');
    mapWorld = svg('g', {class: 'graph-world'});
    canvas.replaceChildren(mapWorld);
    overview.replaceChildren();
    const {positions, clusters, center, selected} = mapPositions(groups, pageEdges);
    const [cx, cy] = center;
    for (const {edge, x, y} of positions) {
      const count = publisherCount(edge);
      const style = count > 1 ? 'multiple' : count ? 'single' : 'unresolved';
      const common = {x1: cx, y1: cy, x2: x, y2: y};
      const line = svg('g', {class: 'graph-edge tone ' + edge.neighbor.type + ' ' + style, 'data-relationship': edge.index});
      const title = svg('title', {});
      title.textContent = edge.type + ' · ' + edge.neighbor.name;
      line.append(title, svg('line', {...common, class: 'graph-edge-line'}), svg('line', {...common, class: 'graph-edge-hit'}));
      line.addEventListener('click', () => {
        const targetPage = Math.floor(edges.findIndex(item => item.index === edge.index) / pageSize);
        if (targetPage !== page) {
          page = targetPage;
          render();
        }
        openEdge(edge);
      });
      mapWorld.append(line);
    }

    clusters.forEach(cluster => mapWorld.append(mapLabel(cluster.label, cluster.x, cluster.y, 'graph-cluster-label tone ' + cluster.type)));
    for (const {edge, x, y} of positions) {
      const entity = edge.neighbor;
      const title = svg('title', {});
      title.textContent = entity.name + ' · ' + (types[entity.type] || entity.type);
      const group = svg('g', {class: 'graph-node tone ' + entity.type, tabindex: selected.has(edge.index) ? 0 : -1,
        role: 'button', 'aria-label': 'Explore ' + entity.name, 'data-relationship': edge.index});
      group.append(title, svg('circle', {cx: x, cy: y, r: 11, class: 'graph-point-target'}),
        svg('circle', {cx: x, cy: y, r: 9, class: 'graph-point-halo'}),
        svg('circle', {cx: x, cy: y, r: positions.length > 12 ? 4.4 : 6.5, class: 'graph-point'}));
      group.addEventListener('click', () => navigate(entity.id));
      group.addEventListener('keydown', event => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        event.preventDefault();
        navigate(entity.id);
        $('graph-stage-title').focus();
      });
      const highlight = on => {
        canvas.querySelector('.graph-edge[data-relationship="' + edge.index + '"]')?.classList.toggle('is-highlighted', on);
      };
      group.addEventListener('pointerenter', () => highlight(true));
      group.addEventListener('pointerleave', () => highlight(false));
      group.addEventListener('focus', () => highlight(true));
      group.addEventListener('blur', () => highlight(false));
      mapWorld.append(group);
      overview.append(svg('circle', {cx: x, cy: y, r: 11, class: 'tone ' + entity.type}));
    }
    const centerNode = svg('g', {class: 'graph-focus tone ' + node.type});
    centerNode.append(...[34, 22, 11].map((r, i) => svg('circle', {cx, cy, r, class: 'graph-focus-ring ring-' + i})));
    centerNode.append(mapLabel(shorten(node.name, 42), cx, cy + 51, 'graph-focus-label'));
    mapWorld.append(centerNode);
    overview.append(svg('circle', {cx, cy, r: 16, class: 'tone ' + node.type}));
    overviewFrame = svg('rect', {class: 'graph-overview-frame'});
    overview.append(overviewFrame);
    setViewport(viewport.scale, viewport.x, viewport.y);
    return positions.length;
  }

  function installMapControls() {
    const canvas = $('graph-canvas');
    $('graph-zoom-out').addEventListener('click', () => zoom(-.5));
    $('graph-zoom-in').addEventListener('click', () => zoom(.5));
    $('graph-zoom-reset').addEventListener('click', () => setViewport(1, 0, 0));
    canvas.addEventListener('pointerdown', event => {
      if (viewport.scale <= 1 || event.button !== 0 || event.target.closest('.graph-node, .graph-edge')) return;
      pointer = {id: event.pointerId, x: event.clientX, y: event.clientY};
      canvas.setPointerCapture(event.pointerId);
      canvas.classList.add('is-panning');
    });
    canvas.addEventListener('pointermove', event => {
      if (event.pointerId !== pointer?.id) return;
      const ratio = mapSize.width / canvas.getBoundingClientRect().width;
      panBy((event.clientX - pointer.x) * ratio, (event.clientY - pointer.y) * ratio);
      pointer.x = event.clientX;
      pointer.y = event.clientY;
    });
    canvas.addEventListener('lostpointercapture', () => {
      pointer = null;
      canvas.classList.remove('is-panning');
    });
    canvas.addEventListener('keydown', event => {
      if (event.target !== canvas || viewport.scale <= 1) return;
      const direction = {ArrowLeft: [38, 0], ArrowRight: [-38, 0], ArrowUp: [0, 38], ArrowDown: [0, -38]}[event.key];
      if (direction) {
        event.preventDefault();
        panBy(...direction);
      }
    });
  }

  function renderEvidence(edges) {
    const container = $('graph-relationships');
    container.replaceChildren();
    if (!edges.length) container.append(element('p', 'No documented connections match this view.', 'graph-help'));
    for (const edge of edges) {
      const item = element('article', '', 'graph-relation');
      const intro = element('div', '', 'graph-relation-title ' + edge.neighbor.type);
      intro.dataset.nodeType = edge.neighbor.type;
      intro.append(button(edge.neighbor.name, () => {
        navigate(edge.neighbor.id);
        $('graph-stage-title').focus();
      }, 'graph-entity-link'), element('small', (types[edge.neighbor.type] || edge.neighbor.type) + ' · ' + edge.type));
      const disclosure = element('details');
      disclosure.id = 'graph-edge-' + edge.index;
      const count = publisherCount(edge);
      disclosure.append(element('summary', count ? count + (count === 1 ? ' cited publisher' : ' cited publishers') : 'Source details'));
      if (!edge.citations.length) disclosure.append(element('p', 'This export does not identify a citation.'));
      for (const citation of edge.citations) {
        const source = element('div', '', 'graph-citation');
        source.append(element('strong', citation.publisher || 'Publisher unavailable'));
        if (citation.summary) source.append(element('p', citation.summary));
        if (citation.date) source.append(element('small', (citation.date_type || 'Evidence date') + ' · ' + citation.date));
        if (citation.updated && citation.updated !== citation.date) {
          const suffix = $('graph-date').value && citation.updated > $('graph-date').value ? ' · after selected cutoff' : '';
          source.append(element('small', 'STIX record updated · ' + citation.updated + suffix));
        }
        if (citation.start_time) source.append(element('small', 'Source gives relationship start · ' + citation.start_time));
        if (citation.stop_time) source.append(element('small', 'Source gives relationship end · ' + citation.stop_time));
        if (citation.id) source.append(element('small', citation.id, 'graph-citation-id'));
        const anchor = citationLink(citation.url);
        if (anchor) source.append(anchor);
        disclosure.append(source);
      }
      item.append(intro, disclosure);
      container.append(item);
    }
  }

  function optionalData(path) {
    if (!publicData.has(path)) {
      publicData.set(path, fetch(path, {cache: 'no-cache'}).then(response => response.ok ? response.json() : null).catch(() => null));
    }
    return publicData.get(path);
  }

  function score(value, max) {
    if (typeof value !== 'number' && (typeof value !== 'string' || !value.trim())) return null;
    const n = Number(value);
    return Number.isFinite(n) && n >= 0 && n <= max ? n : null;
  }

  async function renderCve(id, panel) {
    const [catalog, details, intelligence] = await Promise.all([
      optionalData('kev.json'), optionalData('public-details.json'), optionalData('intelligence.json')
    ]);
    const kev = catalog?.vulnerabilities?.find(row => row.cveID === id);
    const live = details?.records?.[id];
    const snapshot = intelligence?.records?.[id];
    const dossier = kev ? null : await optionalData('dossiers/' + encodeURIComponent(id) + '.json');
    if (!panel.isConnected) return;
    const validDossier = dossier?.cve_id === id ? dossier : null;
    const cna = snapshot?.cve?.containers?.cna;
    const description = kev?.shortDescription || validDossier?.summary || cna?.descriptions?.find(d => d.lang?.startsWith('en'))?.value;
    const legacyCvss = [cna, ...(snapshot?.cve?.containers?.adp || [])].flatMap(container => container?.metrics || [])
      .flatMap(metric => [metric.cvssV4_0, metric.cvssV3_1, metric.cvssV3_0]).find(rating => score(rating?.baseScore, 10) !== null);
    const [cvss, epss] = [
      score(live?.cve?.scores?.find(rating => score(rating.score, 10) !== null)?.score ?? validDossier?.cvss?.score ?? legacyCvss?.baseScore, 10),
      score(live?.epss?.score ?? validDossier?.epss?.score ?? snapshot?.epss?.data?.find(row => row.cve === id)?.epss, 1)
    ];
    const metrics = element('dl', '', 'graph-cve-metrics');
    for (const [label, value] of Object.entries({
      'CISA KEV': kev || validDossier?.kev ? 'Listed' : catalog?.vulnerabilities ? 'Not listed in this snapshot' : 'Unavailable',
      CVSS: cvss === null ? 'Unavailable' : cvss + ' / 10',
      EPSS: epss === null ? 'Unavailable' : (epss * 100).toFixed(2) + '%'
    })) metrics.append(element('dt', label), element('dd', value));
    panel.replaceChildren(element('h3', 'Current CVE snapshot'), metrics);
    if (description) panel.append(element('p', description));
  }

  function renderEntity(node) {
    const detail = $('graph-detail');
    if (detail.dataset.entity === node.id) return;
    detail.dataset.entity = node.id;
    detail.replaceChildren(element('small', types[node.type] || node.type, 'graph-entity-type'), element('h2', node.name));
    if (node.external_id && node.external_id !== node.name) detail.append(element('p', node.external_id, 'graph-identifier'));
    const aliases = (node.aliases || []).filter(alias => alias.toLowerCase() !== node.name.toLowerCase());
    if (node.description) {
      const description = node.description.replace(/\[([^\]]+)\]\(https?:\/\/[^)]+\)/g, '$1')
        .replace(/\(Citation:[^)]*\)|\[\d+\]/g, ' ').replace(/\s{2,}/g, ' ').trim();
      detail.append(element('p', description, 'graph-description'));
    }
    if (aliases.length) {
      const list = element('details', '', 'graph-aliases');
      list.append(element('summary', 'Aliases · ' + aliases.length), element('p', aliases.join(', ')));
      detail.append(list);
    }
    const source = citationLink(node.url);
    if (source) detail.append(source);
    const id = [node.external_id, node.name].find(value => cvePattern.test(value || ''));
    if (id) {
      const panel = element('div', '', 'graph-cve');
      panel.append(element('p', 'Loading current CVE metrics…'));
      detail.append(panel, link('Open full CVE details →', 'cve.html?id=' + encodeURIComponent(id)));
      renderCve(id, panel);
    }
  }

  function render() {
    const node = current();
    if (!node) return;
    const type = $('graph-type').value;
    trail.at(-1).type = type;
    const available = filteredConnections(node.id, '');
    const filtered = type ? available.filter(edge => edge.neighbor.type === type) : available;
    const offset = page * pageSize;
    const visible = filtered.slice(offset, offset + pageSize);
    $('graph-evidence-count').textContent = filtered.length ? (offset + 1) + '–' + (offset + visible.length) + ' / ' + filtered.length : '0';
    $('graph-active-edge').hidden = true;
    $('graph-more').hidden = offset + visible.length >= filtered.length;
    $('graph-prev').hidden = page === 0;
    updateAddress();
    renderTrail();
    renderEntity(node);
    renderEvidence(visible);
    renderClusters(mapGroups(available));
    const plotted = drawGraph(node, mapGroups(filtered), filtered, visible);
    $('graph-count').textContent = plotted + ' plotted · ' + filtered.length + ' matching connections';
  }

  function search(event) {
    event.preventDefault();
    const query = $('actor-search').value.trim().toLowerCase();
    if (!query || !nodes.size) return;
    const exact = [], partial = [];
    for (const node of nodes.values()) {
      const names = [node.name, node.external_id, ...(node.aliases || [])].filter(Boolean).map(value => value.toLowerCase());
      if (names.includes(query)) exact.push(node);
      else if (names.some(name => name.includes(query))) partial.push(node);
    }
    const matches = exact.length ? exact : partial;
    if (matches.length === 1) {
      navigate(matches[0].id, true);
      $('graph-stage-title').focus();
      return;
    }
    const box = $('graph-matches');
    box.hidden = false;
    box.replaceChildren(element('p', matches.length ? (matches.length + ' matches · choose an entity') : 'No matching entity in this snapshot.', 'graph-help'));
    for (const match of matches.slice(0, 10)) {
      const title = match.name + ' · ' + (types[match.type] || match.type);
      box.append(button(title, () => {
        navigate(match.id, true);
        $('graph-stage-title').focus();
      }));
    }
  }

  async function load() {
    try {
      const response = await fetch('threat-graph.json', {cache: 'no-cache'});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const graph = await response.json();
      nodes = new Map(graph.nodes.map(node => [node.id, node]));
      indexEdges(graph.edges);
      configureFilters(graph.edges);
      const actors = graph.nodes.filter(node => node.type === 'actor').sort((a, b) => a.name.localeCompare(b.name));
      for (const actor of actors) {
        const option = element('option', actor.name);
        option.value = actor.name;
        $('actor-options').append(option);
      }
      const requested = initial.get('entity');
      const match = nodes.get(requested) || nodes.get(graph.redirects?.[requested])
        || graph.nodes.find(node => node.external_id && node.external_id === requested);
      const connectedActors = actors.filter(node => adjacent.has(node.id));
      startingActors = connectedActors.filter(node => adjacent.get(node.id).length >= 20 && mapGroups(adjacent.get(node.id)).size >= 4);
      if (startingActors.length < 2) startingActors = connectedActors;
      $('graph-next-actor').disabled = startingActors.length < 2;
      $('live-stamp').textContent = actors.length + ' threat actors · '
        + (isoDay(graph.generated_at?.slice(0, 10)) ? 'Snapshot ' + graph.generated_at.slice(0, 10) + ' UTC' : 'Public snapshot');
      if (!match && requested) $('live-stamp').textContent += ' · Requested entity unavailable';
      const entry = match || nextStartingActor() || graph.nodes[0];
      if (entry) navigate(entry.id, true);
      else $('graph-detail').append(element('p', 'No entities are available in this snapshot.'));
    } catch {
      $('live-stamp').textContent = 'The threat graph could not be loaded.';
      $('graph-detail').replaceChildren(element('p', 'Reload the page to retry.'), link('Open MITRE ATT&CK', 'https://attack.mitre.org/'));
    }
  }

  $('graph-search').addEventListener('submit', search);
  $('graph-mobile-filters').addEventListener('click', event => {
    const toggle = event.currentTarget;
    toggle.setAttribute('aria-expanded', String(toggle.getAttribute('aria-expanded') !== 'true'));
  });
  $('graph-back').addEventListener('click', () => backTo(trail.length - 2));
  $('graph-next-actor').addEventListener('click', () => {
    const actor = nextStartingActor();
    if (!actor) return;
    $('graph-type').value = '';
    navigate(actor.id, true);
  });
  for (const id of ['graph-type', 'graph-source']) {
    $(id).addEventListener('change', () => { resetPage(); render(); });
  }
  $('graph-date').addEventListener('change', () => {
    selectDate($('graph-date').value);
    resetPage();
    render();
  });
  $('graph-slider').addEventListener('input', () => {
    const day = Number($('graph-slider').value);
    selectDate(day === latestDay ? '' : dayString(day));
    resetPage();
    render();
  });
  $('graph-reset').addEventListener('click', () => {
    $('graph-type').value = $('graph-source').value = '';
    selectDate('');
    resetPage();
    render();
  });
  $('graph-more').addEventListener('click', () => { page++; selectedEdge = null; render(); $('graph-evidence-title').focus(); });
  $('graph-prev').addEventListener('click', () => { page--; selectedEdge = null; render(); $('graph-evidence-title').focus(); });
  installMapControls();
  load();
})();
