(() => {
  const INDEX = 'outage-observatory.json';
  const regions = {'vm': '1DOTQ VM', 'US': 'United States', 'DE': 'Germany'};
  const labels = {reachable: 'Reachable', failed: 'Failed', inconclusive: 'Inconclusive',
    unavailable: 'Unavailable', stale: 'Stale'};
  const $ = id => document.getElementById(id);
  const make = (tag, text = '', cls = '') => {
    const element = document.createElement(tag);
    element.textContent = text;
    if (cls) element.className = cls;
    return element;
  };
  const link = (text, href, cls) => {
    const a = make('a', text, cls);
    a.href = href;
    return a;
  };
  const external = (text, href) => {
    try {
      const url = new URL(href);
      if (url.protocol === 'https:' && !url.username && !url.password) return link(text, url.href);
    } catch (_) { /* Ignore invalid upstream URLs. */ }
    return make('span', 'Source link unavailable');
  };
  const serviceUrl = id => 'outage.html?service=' + encodeURIComponent(id);
  const incidentUrl = id => 'outage.html?id=' + encodeURIComponent(id);
  const time = value => {
    const t = new Date(value);
    return value && Number.isFinite(t.getTime()) ? t.toLocaleString([], {
      month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', timeZoneName: 'short',
    }) : 'Unknown';
  };
  const when = value => {
    const element = make('time', time(value));
    if (value) element.dateTime = value;
    return element;
  };
  const summary = item => [item.kind === 'measurement' ? 'Independent checks' : item.provider + ' status',
    item.impact, item.status].filter(Boolean).join(' · ');
  async function read(path) {
    const response = await fetch(path, {cache: 'no-cache'});
    if (!response.ok) throw new Error('HTTP ' + response.status);
    return response.json();
  }
  function outcome(samples, region, fresh = true) {
    const reading = samples?.find(x => x.region === region);
    if (!reading) return 'unavailable';
    const allowance = (region === 'vm' ? 12 : 25) * 60_000;
    if (fresh && Date.now() - Date.parse(reading.at) > allowance) return 'stale';
    return reading.outcome;
  }
  function mark(state, text) {
    const marker = make('span', text || labels[state], 'monitor-state');
    marker.dataset.state = state;
    return marker;
  }
  function checkedRegions(service) {
    const strip = make('div', '', 'monitor-regions');
    for (const [key, name] of [['vm', 'VM'], ['US', 'US'], ['DE', 'DE']]) {
      const state = outcome(service.latest, key);
      const marker = mark(state, name);
      marker.setAttribute('aria-label', regions[key] + ': ' + labels[state]);
      marker.title = regions[key] + ': ' + labels[state];
      strip.append(marker);
    }
    return strip;
  }
  function incidentList(items, empty) {
    if (!items.length) return make('p', empty, 'monitor-empty');
    const list = make('ul', '', 'monitor-incident-list');
    for (const item of items) {
      const entry = make('li');
      const a = link('', incidentUrl(item.id), 'monitor-incident');
      a.append(make('small', summary(item)), make('strong', item.title), make('small', time(item.updated_at)));
      entry.append(a);
      list.append(entry);
    }
    return list;
  }
  function priority(item) {
    if (!item.resolved_at && item.kind === 'measurement') return 0;
    if (!item.resolved_at && ['major', 'critical'].includes(item.impact)) return 1;
    return 2;
  }
  let lastIndex;
  window.observatoryIncidentLink = source =>
    lastIndex?.incidents.find(item => item.source_id === source)?.id;
  async function home() {
    try {
      const index = await read(INDEX);
      lastIndex = index;
      document.dispatchEvent(new Event('observatory-ready'));
      const age = Date.now() - Date.parse(index.generated_at);
      $('monitor-stamp').textContent = (age > 25 * 60_000 ? 'Snapshot delayed · ' : 'Snapshot · ') +
        time(index.generated_at);
      $('monitor-services').replaceChildren(...index.services.map(service => {
        const li = make('li');
        const a = link('', serviceUrl(service.id), 'monitor-service');
        const name = make('div');
        name.append(make('strong', service.name), make('small', service.scope));
        a.append(name, checkedRegions(service));
        li.append(a);
        return li;
      }));
      const incidents = [...index.incidents].sort((a, b) => priority(a) - priority(b)).slice(0, 6);
      $('monitor-incidents').replaceChildren(incidentList(incidents, 'No recent incident records.'));
    } catch (_) {
      $('monitor-stamp').textContent = lastIndex ? 'Refresh delayed · ' + time(lastIndex.generated_at) :
        'Monitoring snapshot unavailable. Provider incident feeds appear below.';
    }
  }
  function section(title) {
    const container = make('section', '', 'evidence-section');
    container.append(make('h2', title));
    return container;
  }
  function heading(label, title, description) {
    const wrapper = make('div', '', 'evidence-heading');
    wrapper.append(make('p', label, 'live-kicker'), make('h1', title), make('p', description));
    document.title = title + ' | 1DOTQ Threat Intel';
    return wrapper;
  }
  function measurement(check, compact = false) {
    const status = labels[check.outcome] || 'Unavailable';
    const bits = [compact ? regions[check.region] + ' · ' + status : status];
    if (check.http_code) bits.push('HTTP ' + check.http_code);
    if (check.latency_ms != null) bits.push(check.latency_ms + ' ms');
    return mark(check.outcome, bits.join(' · '));
  }
  function timeline(events) {
    const list = make('ol', '', 'evidence-events');
    for (const event of events) {
      const entry = make('li');
      entry.append(when(event.at));
      if (event.label) entry.append(make('h3', event.label.replaceAll('_', ' ')));
      if (event.body) entry.append(make('p', event.body));
      if (event.checks?.length) {
        const strip = make('div', '', 'evidence-samples');
        for (const check of event.checks) strip.append(measurement(check, true));
        const proof = [...new Set(event.checks.map(check => check.reference).filter(Boolean))];
        for (const url of proof) strip.append(external('Globalping measurement ↗', url));
        entry.append(strip);
      }
      list.append(entry);
    }
    return list;
  }
  function renderService(index, service) {
    const intro = heading('Service monitor', service.name, service.scope);
    intro.append(external('Provider status ↗', service.status_url));
    const state = section('Latest checks');
    const cells = make('div', '', 'evidence-readouts');
    for (const [region, name] of Object.entries(regions)) {
      const cell = make('div', '', 'evidence-readout');
      const check = service.latest.find(item => item.region === region);
      const current = outcome(service.latest, region);
      cell.append(make('h3', name), check && current === check.outcome ? measurement(check) : mark(current),
        make('p', 'Last measured ' + time(check?.at)),
        make('p', 'Last successful ' + time(service.last_success[region])));
      if (check?.reference) cell.append(external('Measurement ↗', check.reference));
      cells.append(cell);
    }
    state.append(cells, make('p', 'Checks show this endpoint’s reachability from the listed locations. The VM runs every five minutes; external checks run every fifteen minutes. Snapshot time: ' + time(index.generated_at) + '.'));
    const history = section('Recent checks');
    history.append(service.history.length ? timeline(service.history) : make('p', 'Checks are still being collected.'));
    const incidents = section('Incidents and provider reports');
    incidents.append(incidentList(index.incidents.filter(i => i.service === service.id || i.services?.includes(service.id)),
      'There are no recent incident records for this monitored function.'));
    return [intro, state, incidents, history];
  }
  function renderIncident(item) {
    const intro = heading(summary(item), item.title, item.summary);
    intro.append(external(item.kind === 'provider' ? 'Original provider report ↗' : 'Provider status page ↗', item.url));
    const evidence = section('Evidence timeline');
    evidence.append(make('p', 'First reported or observed ' + time(item.started_at) +
      (item.resolved_at ? ' · Recovery ' + time(item.resolved_at) : '')));
    evidence.append(timeline(item.timeline || []));
    const interpretation = section('What the evidence establishes');
    if (item.kind === 'provider') {
      interpretation.append(make('p', 'The provider reported this incident. Follow the original report for the provider’s impact and cause assessment.'));
      if (item.services?.length) {
        const listed = make('ul', '', 'evidence-list');
        for (const id of item.services) {
          const li = make('li');
          li.append(link('View ' + id.replaceAll('-', ' ') + ' checks', serviceUrl(id)));
          listed.append(li);
        }
        interpretation.append(listed);
      }
    } else {
      interpretation.append(make('p', 'Both external locations failed in two consecutive rounds. The checks establish a loss of reachability for this endpoint. The cause is unknown from these checks.'));
      if (item.service) interpretation.append(link('Latest service checks →', serviceUrl(item.service)));
      if (item.related_reports?.length) {
        interpretation.append(make('h3', 'Provider reports for the same monitored function'));
        const linked = make('ul', '', 'evidence-list');
        for (const report of item.related_reports) {
          const li = make('li');
          li.append(link(report.title, incidentUrl(report.id)));
          const difference = report.minutes_before_ack;
          if (difference != null) li.append(make('p', difference === 0 ? 'First check failure and acknowledgment fell within a minute.' :
            'First check failure was ' + Math.abs(difference) + ' minutes ' + (difference > 0 ? 'before' : 'after') + ' provider acknowledgment.'));
          linked.append(li);
        }
        interpretation.append(linked);
      }
    }
    return [intro, evidence, interpretation];
  }
  async function detail() {
    const target = $('evidence-content');
    const query = new URLSearchParams(location.search);
    const service = query.get('service'), incident = query.get('id');
    const slug = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
    try {
      if (service && slug.test(service)) {
        const index = await read(INDEX);
        const found = index.services.find(item => item.id === service);
        if (found) return target.replaceChildren(...renderService(index, found));
      } else if (incident && slug.test(incident) && incident.length < 100) {
        const record = await read('outage-incidents/' + incident + '.json');
        if (record.id === incident) return target.replaceChildren(...renderIncident(record));
      }
      target.replaceChildren(make('p', 'This service or incident could not be found.'));
    } catch (_) {
      target.replaceChildren(make('p', 'This evidence record is unavailable. Please try refreshing.'));
    }
  }
  if ($('monitor-home')) {
    home();
    setInterval(home, 300_000);
  }
  if ($('monitor-detail')) detail();
})();
