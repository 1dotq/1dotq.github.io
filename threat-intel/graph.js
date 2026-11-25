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

  function filteredConnections(id) {
    const type = $('graph-type').value;
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
    detail.open = true;
    $('graph-active-edge').hidden = false;
    $('graph-active-edge').textContent = 'Selected relationship: ' + edge.neighbor.name;
    detail.querySelector('summary').focus();
    detail.scrollIntoView({block: 'nearest'});
  }

  function drawGraph(node, edges) {
    const canvas = $('graph-canvas');
    canvas.replaceChildren();
    const center = [380, 250];
    const positions = edges.map((edge, index) => {
      const angle = -Math.PI / 2 + index * 2 * Math.PI / edges.length;
      return {edge, x: center[0] + Math.cos(angle) * 275, y: center[1] + Math.sin(angle) * 172};
    });
    for (const {edge, x, y} of positions) {
      const count = publisherCount(edge);
      const style = count > 1 ? 'multiple' : count ? 'single' : 'unresolved';
      const common = {x1: center[0], y1: center[1], x2: x, y2: y};
      const line = svg('g', {class: 'graph-edge ' + style});
      const title = svg('title', {});
      title.textContent = edge.type + ' · ' + edge.neighbor.name;
      line.append(title, svg('line', {...common, class: 'graph-edge-line'}), svg('line', {...common, class: 'graph-edge-hit'}));
      line.addEventListener('click', () => openEdge(edge));
      canvas.append(line);
    }
    function draw(entity, x, y, focused) {
      const group = svg('g', {class: 'graph-node ' + entity.type + (focused ? ' graph-node-current' : '')});
      const title = svg('title', {});
      title.textContent = entity.name + ' · ' + (types[entity.type] || entity.type);
      group.append(title, svg('circle', {cx: x, cy: y, r: focused ? 31 : 17}));
      const label = svg('text', {x, y: y + (focused ? 53 : 34)});
      label.textContent = entity.name.length > 24 ? entity.name.slice(0, 22) + '…' : entity.name;
      group.append(label);
      if (!focused) {
        group.setAttribute('tabindex', '0');
        group.setAttribute('role', 'button');
        group.setAttribute('aria-label', 'Explore ' + entity.name);
        group.addEventListener('click', () => navigate(entity.id));
        group.addEventListener('keydown', event => {
          if (event.key !== 'Enter' && event.key !== ' ') return;
          event.preventDefault();
          navigate(entity.id);
          $('graph-stage-title').focus();
        });
      }
      canvas.append(group);
    }
    positions.forEach(({edge, x, y}) => draw(edge.neighbor, x, y, false));
    draw(node, ...center, true);
  }

  function renderEvidence(edges) {
    const container = $('graph-relationships');
    container.replaceChildren();
    if (!edges.length) container.append(element('p', 'No documented connections match this view.', 'graph-help'));
    for (const edge of edges) {
      const item = element('article', '', 'graph-relation');
      const intro = element('div', '', 'graph-relation-title');
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
    if (node.aliases?.length) detail.append(element('p', 'Also known as ' + node.aliases.join(', ')));
    if (node.description) detail.append(element('p', node.description.replace(/\[(\d+)\]/g, '')));
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
    trail.at(-1).type = $('graph-type').value;
    const filtered = filteredConnections(node.id);
    const offset = page * pageSize;
    const visible = filtered.slice(offset, offset + pageSize);
    const total = (adjacent.get(node.id) || []).length;
    $('graph-count').textContent = filtered.length
      ? (offset + 1) + '–' + (offset + visible.length) + ' of ' + filtered.length + ' matching connections' + (filtered.length < total ? ' · ' + total + ' total' : '')
      : '0 matching connections' + (total ? ' · ' + total + ' total' : '');
    $('graph-active-edge').hidden = true;
    $('graph-more').hidden = offset + visible.length >= filtered.length;
    $('graph-prev').hidden = page === 0;
    updateAddress();
    renderTrail();
    renderEntity(node);
    renderEvidence(visible);
    drawGraph(node, visible);
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
      const fallback = actors.find(node => node.external_id === 'G0016' && adjacent.has(node.id))
        || actors.find(node => adjacent.has(node.id)) || graph.nodes[0];
      $('live-stamp').textContent = actors.length + ' threat actors · '
        + (isoDay(graph.generated_at?.slice(0, 10)) ? 'Snapshot ' + graph.generated_at.slice(0, 10) + ' UTC' : 'Public snapshot');
      if (!match && requested) $('live-stamp').textContent += ' · Requested entity unavailable';
      if (match || fallback) navigate((match || fallback).id, true);
      else $('graph-detail').append(element('p', 'No entities are available in this snapshot.'));
    } catch {
      $('live-stamp').textContent = 'The threat graph could not be loaded.';
      $('graph-detail').replaceChildren(element('p', 'Reload the page to retry.'), link('Open MITRE ATT&CK', 'https://attack.mitre.org/'));
    }
  }

  $('graph-search').addEventListener('submit', search);
  $('graph-back').addEventListener('click', () => backTo(trail.length - 2));
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
  load();
})();
