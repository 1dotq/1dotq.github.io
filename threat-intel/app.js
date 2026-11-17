'use strict';
const $ = id => document.getElementById(id);
const results = $('results'), search = $('search'), vendor = $('vendor'), sort = $('sort');
const since = $('since'), until = $('until'), product = $('product'), ransomware = $('ransomware'), pageSize = $('page-size');
let records = [], filteredRecords = [], page = 1, pageCount = 1, timer, dataReady = false, catalogVersion = '', catalogReleased = '';
const safe = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const dateValue = value => /^\d{4}-\d{2}-\d{2}$/.test(value || '') ? value : '';
const compare = (a,b) => String(a || '').localeCompare(String(b || ''), undefined, {numeric:true,sensitivity:'base'});
const status = message => { $('action-status').textContent = message; };
function stateUrl() {
  const url = new URL(location.href); url.search = '';
  const state = {q:search.value.trim(),vendor:vendor.value,product:product.value.trim(),sort:sort.value === 'recent' ? '' : sort.value,since:since.value,until:until.value,ransomware:ransomware.value,size:pageSize.value === '8' ? '' : pageSize.value,p:page > 1 ? String(page) : ''};
  Object.entries(state).forEach(([key,value]) => {if (value) url.searchParams.set(key,value)});
  url.hash = 'catalog'; return url;
}
function applyParams() {
  const p = new URLSearchParams(location.search);
  search.value = (p.get('q') || '').slice(0,160); product.value = (p.get('product') || '').slice(0,100);
  vendor.value = p.get('vendor') || ''; sort.value = ['recent','oldest','vendor','cve','product','due'].includes(p.get('sort')) ? p.get('sort') : 'recent';
  since.value = dateValue(p.get('since')); until.value = dateValue(p.get('until'));
  ransomware.value = ['known','unknown'].includes(p.get('ransomware')) ? p.get('ransomware') : '';
  pageSize.value = ['8','16','32'].includes(p.get('size')) ? p.get('size') : '8';
  page = Math.max(1,Math.min(100000,Number.parseInt(p.get('p'),10) || 1));
}
function filtered() {
  const terms = search.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const productTerm = product.value.trim().toLowerCase();
  return records.filter(r => {
    const haystack = [r.cveID,r.vendorProject,r.product,r.vulnerabilityName,r.shortDescription].join(' ').toLowerCase();
    const date = dateValue(r.dateAdded);
    return terms.every(t => haystack.includes(t)) && (!vendor.value || r.vendorProject === vendor.value) && (!productTerm || String(r.product || '').toLowerCase().includes(productTerm)) && (!since.value || (date && date >= since.value)) && (!until.value || (date && date <= until.value)) && (!ransomware.value || (ransomware.value === 'known' ? r.knownRansomwareCampaignUse === 'Known' : r.knownRansomwareCampaignUse !== 'Known'));
  }).sort((a,b) => (sort.value === 'vendor' ? compare(a.vendorProject,b.vendorProject) : sort.value === 'product' ? compare(a.product,b.product) : sort.value === 'cve' ? compare(a.cveID,b.cveID) : sort.value === 'due' ? compare(a.dueDate,b.dueDate) : sort.value === 'oldest' ? compare(a.dateAdded,b.dateAdded) : compare(b.dateAdded,a.dateAdded)) || compare(a.cveID,b.cveID));
}
function recordHtml(r) {
  const detailUrl = new URL(location.href); detailUrl.search = ''; detailUrl.searchParams.set('q',r.cveID); detailUrl.hash='catalog';
  const ransomwareText = r.knownRansomwareCampaignUse || 'Not provided';
  const cwes = Array.isArray(r.cwes) ? r.cwes.filter(x => /^CWE-\d+$/.test(x)) : [];
  const cweLinks = cwes.map(x => `<a href="https://cwe.mitre.org/data/definitions/${encodeURIComponent(x.slice(4))}.html" target="_blank" rel="noopener noreferrer">${safe(x)} ↗</a>`).join(', ');
  return `<details class="record"><summary><div><span class="cve">${safe(r.cveID)}</span><h3>${safe(r.vulnerabilityName || 'Name unavailable')}</h3><p>${safe(r.vendorProject || 'Vendor unknown')} <span> / </span> ${safe(r.product || 'Product unknown')}</p></div><div class="record-side"><span class="badge">KNOWN EXPLOITED</span><small>Added ${safe(r.dateAdded || 'unknown')}</small><b aria-hidden="true">+</b></div></summary><div class="record-detail"><p>${safe(r.shortDescription || 'No description supplied.')}</p><p><strong>CISA required action:</strong> ${safe(r.requiredAction || 'Not supplied')}</p><p><strong>Federal agency due date:</strong> ${safe(r.dueDate || 'Not supplied')}</p><p><strong>CISA ransomware campaign use:</strong> ${safe(ransomwareText)}</p>${cweLinks ? `<p><strong>Weaknesses:</strong> ${cweLinks}</p>` : ''}${r.notes ? `<p class="notes"><strong>CISA notes:</strong> ${safe(r.notes)}</p>` : ''}<div class="record-links"><a class="detail-cta" href="cve.html?id=${encodeURIComponent(r.cveID)}">Full intelligence →</a><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(r.cveID)}" target="_blank" rel="noopener noreferrer">NVD record ↗</a><a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(r.cveID)}" target="_blank" rel="noopener noreferrer">CVE record ↗</a><a href="${safe(detailUrl.href)}">Link to this CVE ↗</a></div></div></details>`;
}
function render(updateUrl = false) {
  if (!dataReady) return;
  filteredRecords = filtered();
  const perPage = Number(pageSize.value); pageCount = Math.max(1,Math.ceil(filteredRecords.length/perPage));
  page = Math.max(1,Math.min(page,pageCount));
  const first = filteredRecords.length ? (page-1)*perPage+1 : 0, last = Math.min(page*perPage,filteredRecords.length);
  $('count').textContent = `${filteredRecords.length.toLocaleString()} ${filteredRecords.length === 1 ? 'record' : 'records'} · showing ${first}–${last}`;
  $('page').textContent = `Page ${page} of ${pageCount}`; $('prev').disabled = page === 1; $('next').disabled = page === pageCount;
  $('jump-page').max = String(pageCount); $('jump-page').value = String(page);
  const invalidRange = since.value && until.value && since.value > until.value;
  $('filter-status').textContent = invalidRange ? 'The start date is after the end date. Adjust the date range.' : (filteredRecords.length !== records.length ? 'Filters are active. Exports include all matching records, not only this page.' : 'Showing the collected CISA catalog.');
  $('export-csv').disabled = $('export-json').disabled = !filteredRecords.length;
  results.innerHTML = filteredRecords.slice((page-1)*perPage,page*perPage).map(recordHtml).join('') || '<p class="empty">No records match your filters. Try another term or clear the filters.</p>';
  if (updateUrl) history.replaceState(null,'',stateUrl());
}
function validate(data) {
  if (!data || !Array.isArray(data.vulnerabilities) || !data.vulnerabilities.length || data.count !== data.vulnerabilities.length || data.vulnerabilities.some(r => !/^CVE-\d{4}-\d{4,}$/.test(r.cveID || ''))) throw Error('Invalid catalog');
  if (new Set(data.vulnerabilities.map(r => r.cveID)).size !== data.vulnerabilities.length) throw Error('Duplicate identifiers');
}
function init(data) {
  validate(data); records = data.vulnerabilities; const released = String(data.dateReleased || '').slice(0,10); catalogVersion = data.catalogVersion || ''; catalogReleased = data.dateReleased || '';
  $('catalog-date').textContent = `CISA ${data.catalogVersion || 'version unavailable'} · checked ${data.collectedAt ? new Date(data.collectedAt).toLocaleString() : 'time unavailable'}`;
  const age = Math.floor((Date.now()-Date.parse(data.collectedAt || `${released}T00:00:00Z`))/86400000);
  $('freshness').textContent = Number.isFinite(age) && age > 1 ? `Our last successful CISA check was ${age} days ago. Verify newer information at CISA.` : (age < 0 ? 'This device clock differs from the source timestamp. Check CISA for current data.' : `CISA released this catalog ${dateValue(released) || 'on an unknown date'}. Source facts can change; verify vendor guidance.`);
  const vendors = [...new Set(records.map(r => r.vendorProject).filter(Boolean))].sort(compare);
  vendors.forEach(v => {const o=document.createElement('option');o.value=v;o.textContent=v;vendor.appendChild(o)});
  $('stat-total').textContent=records.length.toLocaleString(); $('stat-vendors').textContent=vendors.length.toLocaleString();
  $('stat-known').textContent=records.filter(r=>r.knownRansomwareCampaignUse==='Known').length.toLocaleString();
  $('stat-latest').textContent=records.map(r=>dateValue(r.dateAdded)).sort().pop() || 'Unknown';
  applyParams(); dataReady=true; results.setAttribute('aria-busy','false'); render();
}
function download(name,type,content) {
  const url=URL.createObjectURL(new Blob([content],{type})), link=document.createElement('a');
  link.href=url; link.download=name; document.body.appendChild(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function csvCell(value) {
  let text=String(value ?? ''); if (/^[\t\r\n ]*[=+@\-]/.test(text)) text="'"+text;
  return '"' + text.replace(/"/g,'""') + '"';
}
fetch('kev.json').then(r => {if (!r.ok) throw Error('Catalog unavailable');return r.json()}).then(init).catch(()=>{$('catalog-date').textContent='Catalog unavailable';$('count').textContent='Unable to load the catalog';results.setAttribute('aria-busy','false');$('export-csv').disabled=$('export-json').disabled=true;results.innerHTML='<p class="empty">The catalog could not be loaded. Use a web server or GitHub Pages, check kev.json, or visit the CISA source link above.</p>'});
function delayedRender(){clearTimeout(timer);timer=setTimeout(()=>{page=1;render(true)},150)}
[search,product].forEach(el=>el.addEventListener('input',delayedRender));
[vendor,sort,since,until,ransomware,pageSize].forEach(el=>el.addEventListener('change',()=>{page=1;render(true)}));
$('prev').addEventListener('click',()=>{page--;render(true)}); $('next').addEventListener('click',()=>{page++;render(true)});
$('jump').addEventListener('click',()=>{page=Number.parseInt($('jump-page').value,10)||1;render(true);status(`Showing page ${page} of ${pageCount}`)});
$('clear').addEventListener('click',()=>{clearTimeout(timer);search.value='';vendor.value='';product.value='';sort.value='recent';since.value='';until.value='';ransomware.value='';pageSize.value='8';page=1;render(true);search.focus()});
$('copy-search').addEventListener('click',async()=>{try{await navigator.clipboard.writeText(stateUrl().href);status('Search link copied');$('copy-search').textContent='Link copied';setTimeout(()=>{$('copy-search').textContent='Copy search link'},2000)}catch{status('Copy the search URL from your address bar');$('copy-search').textContent='Copy URL from address bar'}});
$('export-json').addEventListener('click',()=>{clearTimeout(timer);render(true);if(!filteredRecords.length)return;download('1dotq-cisa-kev-filtered.json','application/json',JSON.stringify({source:'CISA KEV',source_url:'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',catalog_version:catalogVersion,catalog_released:catalogReleased,exported_at:new Date().toISOString(),count:filteredRecords.length,vulnerabilities:filteredRecords},null,2));status('JSON export prepared')});
$('export-csv').addEventListener('click',()=>{clearTimeout(timer);render(true);if(!filteredRecords.length)return;const cols=['cveID','vendorProject','product','vulnerabilityName','dateAdded','dueDate','knownRansomwareCampaignUse','shortDescription','requiredAction'];const csv=[cols,...filteredRecords.map(r=>cols.map(c=>r[c] ?? ''))].map(row=>row.map(csvCell).join(',')).join('\r\n');download('1dotq-cisa-kev-filtered.csv','text/csv;charset=utf-8','\ufeff'+csv);status('CSV export prepared')});
document.addEventListener('keydown',event=>{const tag=event.target.tagName;if(event.key==='/' && !event.ctrlKey && !event.metaKey && !event.altKey && !['INPUT','TEXTAREA','SELECT'].includes(tag)){event.preventDefault();search.focus();status('Search focused')} });
$('jump-page').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();$('jump').click()}});
window.addEventListener('popstate',()=>{if(dataReady){applyParams();render()}});
