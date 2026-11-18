'use strict';
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const https=v=>{try{const u=new URL(v);return u.protocol==='https:'?u.href:null}catch{return null}};
const link=(url,label)=>https(url)?`<a href="${esc(https(url))}" target="_blank" rel="noopener noreferrer">${esc(label)} ↗</a>`:esc(label);
const id=new URLSearchParams(location.search).get('id');
const cisa='https://www.cisa.gov/known-exploited-vulnerabilities-catalog';
const empty=text=>`<p class="empty-state">${esc(text)}</p>`;
const date=v=>v?String(v).slice(0,10):'Not collected';
function metadata(title,description){
  document.title=title+' | 1DOTQ Threat Intel';
  let canonical=document.querySelector('link[rel="canonical"]');
  if(!canonical){canonical=document.createElement('link');canonical.rel='canonical';document.head.append(canonical)}
  canonical.href='https://1dotq.github.io/threat-intel/cve.html?id='+encodeURIComponent(id);
  for(const [selector,attribute,key,content] of [
    ['meta[name="description"]','name','description',description],
    ['meta[property="og:title"]','property','og:title',document.title],
    ['meta[property="og:description"]','property','og:description',description],
    ['meta[property="og:url"]','property','og:url',canonical.href]
  ]){let tag=document.querySelector(selector);if(!tag){tag=document.createElement('meta');tag.setAttribute(attribute,key);document.head.append(tag)}tag.content=String(content||'').slice(0,240)}
}
function chart(points,label,percent=false){
  if(!points.length)return empty('No observations collected for this series. This does not mean no activity.');
  const sorted=points.filter(p=>Number.isFinite(p.y)&&Number.isFinite(Date.parse(p.date))).sort((a,b)=>a.date.localeCompare(b.date));
  if(!sorted.length)return empty('No valid dated observations available.');
  const min=Date.parse(sorted[0].date),max=Date.parse(sorted.at(-1).date),ceiling=percent?100:Math.max(1,...sorted.map(p=>p.y));
  const x=p=>55+(Date.parse(p.date)-min)/Math.max(86400000,max-min)*590,y=p=>190-p.y/ceiling*150;
  return `<svg class="chart" viewBox="0 0 700 245" role="img" aria-label="${esc(label)}"><title>${esc(label)}</title><path d="M55 40V190H645" fill="none" stroke="#8da6c2"/><path d="M55 115H645M55 40H645" stroke="#33506d"/><text x="10" y="44">${ceiling}${percent?'%':''}</text><text x="24" y="194">0</text>${percent ? `<polyline points="${sorted.map(p=>x(p)+','+y(p)).join(' ')}" fill="none" stroke="#61a0ff" stroke-width="3"/>` : sorted.map(p=>`<rect x="${x(p)-5}" y="${y(p)}" width="10" height="${190-y(p)}" fill="#61a0ff"/>`).join('')}${sorted.map(p=>`<circle cx="${x(p)}" cy="${y(p)}" r="4" fill="#61a0ff"><title>${esc(p.date)}: ${p.y.toFixed(2)}${percent?'%':''}</title></circle>`).join('')}<text x="55" y="220">${esc(sorted[0].date)}</text><text x="550" y="220">${esc(sorted.at(-1).date)}</text></svg><details><summary>View chart data</summary><div class="table-scroll"><table><thead><tr><th>Date</th><th>${esc(label)}</th></tr></thead><tbody>${sorted.map(p=>`<tr><td>${esc(p.date)}</td><td>${p.y.toFixed(2)}${percent?'%':''}</td></tr>`).join('')}</tbody></table></div></details>`;
}
async function renderDossier(){
  const response=await fetch('dossiers/'+encodeURIComponent(id)+'.json',{cache:'no-store'});
  if(!response.ok)throw Error('This CVE dossier is not available yet. Browse the latest signals for source links.');
  const d=await response.json();
  if(d.cve_id!==id)throw Error('CVE dossier identifier did not match.');
  const score=Number(d.cvss?.score),ep=Number(d.epss?.score);
  const sources=(d.sources||[]).filter(s=>https(s.url)).slice(0,20);
  const affected=(d.affected||[]).flatMap(g=>(g.items||[]).map(a=>[a.vendor,a.product,a.package?.name].filter(Boolean).join(' / '))).filter(Boolean).slice(0,20);
  metadata(d.title||id,d.summary||'Public-source CVE intelligence.');
  document.getElementById('dossier').innerHTML=`<p class="eyebrow blue">VULNERABILITY INTELLIGENCE / ${esc(id)}</p><h1>${esc(d.title||id)}</h1><p class="lede">${esc(d.summary||'Review the original source records for the current description.')}</p><p class="stamp">Source-backed editorial dossier · Updated ${esc(date(d.modified))} · Verify current vendor guidance before acting</p><div class="metric-grid"><div class="metric"><small>CISA KEV</small><strong>${d.kev?'Listed':'Not established here'}</strong><small>${d.kev?'Known exploitation':'Check CISA for current listing'}</small></div><div class="metric"><small>CVSS · SOURCE RATING</small><strong>${Number.isFinite(score)?esc(score)+' / 10':'Not collected'}</strong><small>${esc(d.severity||'Unscored')}</small></div><div class="metric"><small>EPSS · 30-DAY PROBABILITY</small><strong>${Number.isFinite(ep)?(ep*100).toFixed(2)+'%':'Not collected'}</strong><small>Prediction, not observed attacks</small></div></div><nav class="detail-nav" aria-label="CVE sections"><a href="#sources">Original sources</a><a href="#affected">Affected products</a><a href="#action">Response</a><a href="signals.html">Latest signals</a></nav><section id="sources"><h2>Original sources</h2><p>Source claims may change. Open the original notices for current scope and remediation.</p>${sources.map(s=>`<div class="evidence-item">${link(s.url,s.name||new URL(s.url).hostname)}<small>${esc(s.url)}</small></div>`).join('')||empty('Source links were not included in this dossier.')}</section><section id="affected"><h2>Affected products</h2>${affected.length?`<ul>${affected.map(a=>`<li>${esc(a)}</li>`).join('')}</ul>`:empty('Product and version detail has not been collected. Consult the original notice.')}</section><section id="action"><h2>Response</h2><p>${esc(d.action||'Compare your deployed versions with the vendor advisory and follow its current guidance.')}</p></section>`;
  document.getElementById('loading').hidden=true;
}
async function main(){
  if(!/^CVE-\d{4}-\d{4,}$/.test(id||''))throw Error('Choose a valid CVE from the catalog.');
  const response=await fetch('kev.json');if(!response.ok)throw Error('Catalog unavailable.');
  const catalog=await response.json(),r=catalog.vulnerabilities.find(r=>r.cveID===id);
  if(!r)return renderDossier();
  let bundle={records:{}};
  try{const q=await fetch('intelligence.json');if(q.ok)bundle=await q.json()}catch{}
  let current={records:{}};
  try{const q=await fetch('public-details.json',{cache:'no-store'});if(q.ok)current=await q.json()}catch{}
  const live=current.records?.[id]||{};
  const e=bundle.records[id]||{},cv=e.cve||{},meta=cv.cveMetadata||{},cna=cv.containers?.cna||{},adp=cv.containers?.adp||[];
  const providers=[cna,...adp], refs=new Map();
  providers.forEach(p=>(p.references||[]).forEach(ref=>{if(https(ref.url))refs.set(ref.url,{...ref,provider:p.providerMetadata?.shortName||'CVE contributor'})}));
  (live.cve?.references||[]).forEach(url=>{if(https(url))refs.set(url,{url,provider:'CVE Program',tags:[]})});
  (r.notes?.match(/https:\/\/[^\s;]+/g)||[]).forEach(url=>{if(https(url)&&!refs.has(url))refs.set(url,{url,provider:'CISA notes',tags:[]})});
  const scores=providers.flatMap(p=>(p.metrics||[]).flatMap(m=>['cvssV4_0','cvssV3_1','cvssV3_0'].filter(k=>m[k]).map(k=>({...m[k],provider:p.providerMetadata?.shortName||'CVE contributor'}))));
  const liveScore=live.cve?.scores?.find(s=>Number.isFinite(Number(s.score))&&Number(s.score)>=0&&Number(s.score)<=10);
  const metric=liveScore?{baseScore:liveScore.score,version:liveScore.version,provider:liveScore.source||'CVE Program'}:scores[0];
  const ep=live.epss?{epss:live.epss.score,date:live.epss.date}:e.epss?.data?.find(p=>p.cve===id);
  const affected=live.cve?.affected?.length?live.cve.affected:(cna.affected||[]);
  const epss=ep?[ep,...(ep['time-series']||[])].filter(p=>Number.isFinite(Number(p.epss))&&Number(p.epss)>=0&&Number(p.epss)<=1):[];
  const uniqueEpss=[...new Map(epss.map(p=>[p.date,p])).values()];
  const repos=Array.isArray(e.poc)?[...new Map(e.poc.filter(p=>https(p.html_url)&&new URL(p.html_url).hostname==='github.com').map(p=>[p.html_url,p])).values()]:[];
  const repoDates=new Map();repos.forEach(p=>{if(p.created_at){const d=date(p.created_at);repoDates.set(d,(repoDates.get(d)||0)+1)}});
  const events=[
    ...(meta.datePublished?[{date:meta.datePublished,title:'CVE record published',url:e.sources?.cve,detail:'CVE Program metadata'}]:[]),
    {date:r.dateAdded,title:'Added to CISA KEV',url:cisa,detail:'CISA catalog evidence of exploitation in the wild'},
    ...(meta.dateUpdated?[{date:meta.dateUpdated,title:'CVE record updated',url:e.sources?.cve,detail:'Latest source record update; not a new disclosure'}]:[]),
    {date:r.dueDate,title:'Federal agency remediation deadline',url:cisa,detail:'Not a universal patch deadline'},
    ...repos.filter(p=>p.created_at).map(p=>({date:p.created_at,title:'Indexed repository created',url:p.html_url,detail:p.full_name+' — creation date, not verified first exploit publication'}))
  ].sort((a,b)=>a.date.localeCompare(b.date));
  const related=catalog.vulnerabilities.filter(x=>x.cveID!==id&&x.vendorProject===r.vendorProject).sort((a,b)=>(Number(b.product===r.product)-Number(a.product===r.product))||b.dateAdded.localeCompare(a.dateAdded)).slice(0,6);
  metadata(r.vulnerabilityName,r.shortDescription);
  document.getElementById('dossier').innerHTML=`
    <p class="eyebrow blue">VULNERABILITY INTELLIGENCE / ${esc(id)}</p><h1>${esc(r.vulnerabilityName)}</h1>
    <p class="lede">${esc(r.shortDescription)}</p><p class="stamp">CISA catalog ${esc(catalog.catalogVersion)} · Enrichment checked ${live.cve?.checked_at?esc(date(live.cve.checked_at))+' UTC':e.cve?esc(date(bundle.retrieved_at))+' UTC':'not collected for this CVE'} · Source-derived, not editorially reviewed</p>
    <div class="metric-grid"><div class="metric"><small>KNOWN EXPLOITATION</small><strong>Listed in KEV</strong><small>Added ${esc(r.dateAdded)}</small></div><div class="metric"><small>CVSS · SOURCE RATING</small><strong>${metric?esc(metric.baseScore)+' / 10':'Not collected'}</strong><small>${metric?esc(metric.provider)+' · v'+esc(metric.version):'KEV is not a severity score'}</small></div><div class="metric"><small>EPSS · 30-DAY PROBABILITY</small><strong>${ep?(Number(ep.epss)*100).toFixed(2)+'%':'Not collected'}</strong><small>${ep?'FIRST · '+esc(ep.date):'Not evidence of observed attacks'}</small></div><div class="metric"><small>PUBLIC REPOSITORY REFERENCES</small><strong>${e.poc?repos.length:'Not collected'}</strong><small>PoC-in-GitHub index · unverified code claims</small></div></div>
    <p><a class="button primary" style="color:white" href="signals.html">View latest source signals →</a></p><nav class="detail-nav" aria-label="CVE sections">${[['activity','Public signals'],['timeline','Timeline'],['versions','Affected versions'],['evidence','Online evidence'],['discussions','Conversations'],['questions','Questions'],['related','Related']].map(([k,v])=>`<a href="#${k}">${v}</a>`).join('')}</nav>
    <section id="activity"><h2>Public exploit signals</h2><p>Separate public code references from predicted exploitation and confirmed KEV inclusion. Neither chart measures attack volume.</p><div class="signal-tabs"><button id="epss-tab" aria-pressed="true" aria-controls="epss-panel">EPSS history</button><button id="repo-tab" aria-pressed="false" aria-controls="repo-panel">Repository activity</button></div><div id="epss-panel"><h3>Predicted exploitation probability (%)</h3>${chart(uniqueEpss.map(p=>({date:p.date,y:Number(p.epss)*100})),'EPSS probability',true)}<p class="note">${link('https://www.first.org/epss/','FIRST EPSS')} estimates exploitation over the next 30 days; this is not measured attack frequency.</p></div><div id="repo-panel" hidden><h3>Creation dates of repositories in the current index</h3>${chart([...repoDates].map(([d,n])=>({date:d,y:n})),'Indexed repositories created')}<p class="note">Retrospective view of current index membership. Repository creation dates are not first-observed dates or proof that exploit code existed then. Missing dates are not zero activity.</p></div></section>
    <div class="section-grid"><section id="timeline"><h2>Evidence timeline</h2><ol class="timeline">${events.map(v=>`<li><time>${esc(date(v.date))}</time><b>${link(v.url,v.title)}</b><span>${esc(v.detail)}</span></li>`).join('')}</ol></section><section id="versions"><h2>Affected versions</h2><p class="note">As reported by the CVE publisher. Verify deployment and current vendor guidance.</p>${affected.map(a=>`<h3>${esc(a.vendor)} / ${esc(a.product)}</h3><ul>${(a.versions||[]).map(v=>`<li><b>${esc(v.status)}</b>: ${esc(v.version)}${v.lessThan?' to &lt; '+esc(v.lessThan):''}${v.lessThanOrEqual?' through '+esc(v.lessThanOrEqual):''}${v.changes?.length?' · Additional status changes exist; consult the source record.':''}</li>`).join('')}</ul>`).join('')||empty('Version ranges have not been collected for this CVE. Missing fix data does not mean no fix exists.')}<h3>CISA required action</h3><p>${esc(r.requiredAction)}</p></section></div>
    <section id="evidence"><h2>Online evidence & source references</h2><p class="note">Evidence categories describe what each source can establish. Repository listings are unverified claims, not proof of successful exploitation.</p><div class="evidence-item">${link(cisa,'CISA KEV')}<small>Supports catalog inclusion and the listed action · snapshot ${esc(catalog.catalogVersion)}</small></div><div class="evidence-item">${link('https://www.cve.org/CVERecord?id='+id,'CVE Program record')}<small>Identifier, publisher description and affected-version statements</small></div>${[...refs.values()].map(ref=>`<div class="evidence-item">${link(ref.url,new URL(ref.url).hostname)}<small>${esc(ref.provider)} · ${esc((ref.tags||[]).join(', ')||'Source reference')} · ${esc(ref.url)}</small></div>`).join('')}<h3>Public repository references</h3>${repos.map(p=>`<div class="evidence-item">${link(p.html_url,p.full_name||p.html_url)}<p>${esc(p.description||'No description provided')}</p><small>Indexed by PoC-in-GitHub · created ${esc(date(p.created_at))} · not executed or independently validated</small></div>`).join('')||empty('No repository data collected. This is not a claim that public exploits do not exist.')}<p class="note">${link('https://github.com/nomi-sec/PoC-in-GitHub','Repository index attribution')}</p></section>
    <section id="discussions"><h2>Public conversations</h2><p class="note">Coverage: Hacker News story search, exact CVE mentions in the latest 20 search hits. Checked ${esc(date(bundle.retrieved_at))} UTC. Comment totals are a snapshot, not a measure of current activity.</p>${e.discussions ? ((e.discussions.hits||[]).filter(h=>/^\d+$/.test(h.objectID)).map(h=>`<div class="evidence-item">${link('https://news.ycombinator.com/item?id='+h.objectID,h.title||'Hacker News discussion')}<small>Posted ${esc(date(h.created_at))} · ${esc(h.num_comments??'Unknown')} comments at collection time</small></div>`).join('')||empty('No exact-CVE story matches returned by the checked Hacker News search. Other discussions may exist.')) : empty('Discussion data was not collected for this CVE.')}<p>Additional public searches below are shortcuts, not verified evidence.</p><div class="record-links">${link('https://github.com/search?q='+encodeURIComponent(id)+'&type=issues','GitHub issues')}${link('https://hn.algolia.com/?q='+encodeURIComponent(id),'Hacker News')}${link('https://www.reddit.com/search/?q='+encodeURIComponent(id),'Reddit')}</div></section>
    <section id="questions"><h2>Questions about ${esc(id)}</h2><p class="note">Answers assembled from the displayed source fields, not generated claims.</p>${[
      ['Is it known to be exploited?', 'CISA lists this CVE in KEV, added '+r.dateAdded+'. This establishes known exploitation, not the number or current frequency of attacks.'],
      ['Does public code mean attacks are occurring?', 'No. Indexed repositories may contain analysis, detection tooling, or claimed proofs of concept. They have not been independently validated here.'],
      ['Am I affected?', 'CISA names '+r.vendorProject+' '+r.product+'. Compare your actual deployment with the publisher version details and vendor advisory. This site has no knowledge of your assets.'],
      ['What action does CISA list?',r.requiredAction],
      ['What does EPSS tell me?', ep?'FIRST reports '+(Number(ep.epss)*100).toFixed(2)+'% on '+ep.date+'. It predicts exploitation in the next 30 days; it is not a severity or attack-volume metric.':'EPSS data has not been collected for this CVE.'],
      ['Is the deadline for everyone?', 'The '+r.dueDate+' date is a CISA remediation deadline for covered federal agencies. Assess your own response according to exposure and vendor guidance.']
    ].map(([q,a])=>`<details class="question"><summary>${esc(q)}</summary><p>${esc(a)}</p></details>`).join('')}</section>
    <section id="related"><h2>Related vulnerabilities</h2><p class="note">Same vendor in the KEV catalog, with same-product matches first. These links do not establish an exploit chain.</p>${related.map(x=>`<a class="related" href="cve.html?id=${encodeURIComponent(x.cveID)}"><b>${esc(x.cveID)} ↗</b><span>${esc(x.vulnerabilityName)} · ${x.product===r.product?'Same product':'Same vendor'}</span></a>`).join('')||empty('No same-vendor records in this snapshot.')}</section>`;
  const actions=document.createElement('div');actions.className='research-actions';
  for(const [href,label] of [['compare.html?ids='+encodeURIComponent(id),'Compare this CVE →'],['watchlist.html?cve='+encodeURIComponent(id),'Add to watchlist →'],['explore.html?vendor='+encodeURIComponent(r.vendorProject||''),'Explore vendor →']]){const a=document.createElement('a');a.href=href;a.textContent=label;actions.append(a)}
  const copy=document.createElement('button');copy.type='button';copy.textContent='Copy CVE link';copy.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(location.href);copy.textContent='Link copied'}catch{copy.textContent='Copy URL from address bar'}});actions.append(copy);
  document.getElementById('dossier').querySelector('.metric-grid')?.after(actions);
  document.getElementById('loading').hidden=true;
  for(const name of ['epss','repo'])document.getElementById(name+'-tab').addEventListener('click',()=>{for(const n of ['epss','repo']){document.getElementById(n+'-panel').hidden=n!==name;document.getElementById(n+'-tab').setAttribute('aria-pressed',String(n===name))}});
}
main().catch(error=>{document.getElementById('loading').textContent=error.message;document.getElementById('dossier').innerHTML='<p><a href="index.html#catalog">Return to catalog</a></p>'});
