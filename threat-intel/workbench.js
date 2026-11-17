'use strict';
const $=id=>document.getElementById(id), C=WorkbenchCore, KEY='1dotq.workspace.v1';
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let state=C.fresh(),records=[],byId=new Map(),page=1,comparison=null,reviewId='',studioRecord=null,logoReady=false,graphicValid=false,storageOK=true;
const logo=new Image(),canvas=$('graphic'),ctx=canvas.getContext('2d');
const announce=message=>{$('notice').textContent=message};
const today=()=>{const d=new Date();return [d.getFullYear(),String(d.getMonth()+1).padStart(2,'0'),String(d.getDate()).padStart(2,'0')].join('-')};
try{const raw=localStorage.getItem(KEY);if(raw)state=C.validate(JSON.parse(raw))}catch{storageOK=false;announce('Existing workspace could not be read. Export any new work before leaving; the existing stored data will not be overwritten.')}
function persist(){if(!storageOK)return false;try{localStorage.setItem(KEY,JSON.stringify(state));return true}catch{storageOK=false;announce('Browser storage is unavailable. Changes are in memory only; export your workspace.');return false}}
function save(message){announce(persist()?message:message+' In memory only—export your workspace before leaving.')}
function download(name,type,content){const u=URL.createObjectURL(new Blob([content],{type})),a=document.createElement('a');a.href=u;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)}
function pickOptions(){
  const vendor=$('watch-vendor').value,products=[...new Set(records.filter(r=>r.vendorProject===vendor).map(r=>r.product))].sort();
  $('watch-product').innerHTML='<option value="">All products from this vendor</option>'+products.map(p=>`<option value="${esc(p)}">${esc(p)}</option>`).join('');
}
function render(){
  $('watch-tags').innerHTML=state.watches.length?state.watches.map((w,i)=>`<span class="chip">${esc(w.vendor)} / ${esc(w.product||'All products')}<button data-remove="${i}" aria-label="Unfollow ${esc(w.vendor+' '+w.product)}">×</button></span>`).join(''):'<p class="hint">Choose a vendor and product above to start your watchlist.</p>';
  const matched=records.filter(r=>C.matches(r,state.watches));
  $('watch-count').textContent=state.watches.length;$('match-count').textContent=matched.length;$('saved-count').textContent=state.saved.length;$('review-count').textContent=Object.values(state.reviews).filter(r=>r.status==='reviewed').length;$('digest').disabled=!matched.length;
  const mode=$('match-mode').value,q=$('match-search').value.trim().toLowerCase();
  const list=(mode==='all'?records:mode==='saved'?records.filter(r=>state.saved.includes(r.cveID)):matched).filter(r=>[r.cveID,r.vendorProject,r.product,r.vulnerabilityName].join(' ').toLowerCase().includes(q)).sort((a,b)=>b.dateAdded.localeCompare(a.dateAdded)||a.cveID.localeCompare(b.cveID));
  const pages=Math.max(1,Math.ceil(list.length/10));page=Math.max(1,Math.min(page,pages));
  $('match-summary').textContent=`${list.length} matching records · sorted by CISA addition date`;
  $('watch-page').textContent=`Page ${page} of ${pages}`;$('watch-prev').disabled=page===1;$('watch-next').disabled=page===pages;
  $('watch-results').innerHTML=list.slice((page-1)*10,page*10).map(r=>`<article class="bench-card"><a href="cve.html?id=${r.cveID}">${r.cveID} ↗</a><h3>${esc(r.vulnerabilityName)}</h3><p>${esc(r.vendorProject)} / ${esc(r.product)} · KEV added ${esc(r.dateAdded)}</p><span class="review-tag">${esc(state.reviews[r.cveID]?.status||'unreviewed')}</span><div class="actions"><button data-save="${r.cveID}" aria-pressed="${state.saved.includes(r.cveID)}">${state.saved.includes(r.cveID)?'Unsave':'Save CVE'}</button><button data-review="${r.cveID}">Review</button><button data-studio="${r.cveID}">Create graphic</button></div></article>`).join('')||'<p class="empty-state">No matching records. Follow a product, change the view, or clear your search.</p>';
  const filter=$('queue-filter').value,queue=Object.entries(state.reviews).filter(([,r])=>!filter||(filter==='due'?C.due(r,today()):r.status===filter)).sort((a,b)=>b[1].updatedAt.localeCompare(a[1].updatedAt));
  $('queue-list').innerHTML=queue.map(([id,r])=>`<article class="bench-card"><button data-review="${id}">${id}</button> <span class="review-tag">${esc(r.status)}</span><p>Saved ${esc(r.updatedAt)}${r.nextReview?' · Review '+esc(r.nextReview):''}</p>${C.due(r,today())?'<p class="overdue">Review date reached</p>':''}<p>${esc(r.notes.slice(0,250))}${r.notes.length>250?'…':''}</p></article>`).join('')||'<p class="empty-state">No review entries in this view.</p>';
  renderChanges();
}
function openReview(id){
  if(!byId.has(id)){announce('Choose a CVE in the current catalog.');return}
  reviewId=id;const r=byId.get(id),v=state.reviews[id]||{status:'unreviewed',notes:'',nextReview:''};
  $('review-cve').value=id;$('review-status').value=v.status;$('review-notes').value=v.notes;$('review-date').value=v.nextReview;
  $('review-context').innerHTML=`<h3>${esc(r.vulnerabilityName)}</h3><p class="hint">${esc(r.shortDescription)}</p><a href="cve.html?id=${id}">Open source evidence ↗</a>`;
  $('review-form').hidden=false;$('notes-length').textContent=v.notes.length+' / 4000 characters · Ctrl+Enter saves this review.';$('review-status').focus();
}
function renderChanges(){
  if(!comparison)return;
  const kind=$('change-filter').value,watched=$('change-watched').checked;
  const events=comparison.events.filter(e=>(!kind||e.kind===kind)&&(!watched||(byId.has(e.id)&&C.matches(byId.get(e.id),state.watches))));
  $('change-meta').textContent=`${comparison.oldVersion||'Previous'} → ${comparison.newVersion||'Candidate'} · ${events.length} matching events${watched?' · Removed entries without a current catalog match cannot be matched to your watchlist.':''}`;
  $('change-list').innerHTML=events.slice(0,100).map(e=>`<article class="bench-card"><span class="event-label">${esc(e.kind)}</span><h3>${esc(e.id)}</h3><p>${esc(e.fields.join(', ')|| (e.kind==='removed'?'Removed from candidate; review the source.':'New in candidate snapshot.'))}</p>${comparison.details[e.id]?`<details><summary>Before / after source fields</summary><pre>${esc(JSON.stringify(comparison.details[e.id],null,2))}</pre></details>`:''}${byId.has(e.id)?`<button data-review="${e.id}">Review record</button>`:'<p class="hint">Not in the current catalog; inspect the candidate source.</p>'}</article>`).join('')||'<p class="empty-state">No matching source changes.</p>';
  if(events.length>100)$('change-list').insertAdjacentHTML('beforeend','<p class="hint">Showing the first 100 events. Use the original report for the complete list.</p>');
}
function invalidate(){ $('studio-approved').checked=false;drawGraphic() }
function loadStudio(id){
  if(!byId.has(id)){announce('Choose a CVE in the current catalog.');return}
  studioRecord=byId.get(id);$('studio-cve').value=id;
  $('studio-headline').value=studioRecord.vendorProject+' '+studioRecord.product;
  $('studio-summary').value=C.excerpt(studioRecord.shortDescription,220);
  $('studio-action').value='Check the vendor advisory for affected versions and the appropriate remediation.';
  $('studio-source').innerHTML=`<p class="hint">Source: CISA KEV · added ${esc(studioRecord.dateAdded)} · <a href="cve.html?id=${id}">Review evidence</a></p>`;
  if(studioRecord.shortDescription.length>220)announce('Source description shortened for the graphic. Rewrite it into a complete, accurate summary before approval.');
  invalidate();
}
function wrap(text,width,size,weight='400'){
  ctx.font=`${weight} ${size}px Arial`;let lines=[],line='';
  for(const word of text.trim().split(/\s+/)){const candidate=line?line+' '+word:word;if(ctx.measureText(candidate).width>width&&line){lines.push(line);line=word}else line=candidate}
  if(line)lines.push(line);return lines;
}
function drawGraphic(){
  const format=$('studio-format').value,template=$('studio-template').value;canvas.height=format==='story'?1920:format==='portrait'?1350:1080;canvas.width=1080;
  const h=canvas.height;ctx.fillStyle='#0B1F3B';ctx.fillRect(0,0,1080,h);ctx.fillStyle='#0057D6';ctx.fillRect(0,0,1080,14);
  if(logoReady)ctx.drawImage(logo,54,38,240,240);
  ctx.fillStyle='#F6F8FB';ctx.font='700 22px Arial';ctx.fillText('1DOTQ / THREAT INTEL',570,114);
  ctx.fillStyle='#83B5FF';ctx.font='700 24px Arial';ctx.fillText(template==='alert'?'CISA KEV ALERT':template==='action'?'DEFENSIVE ACTION':'INTELLIGENCE BRIEF',64,310);

  let headline=$('studio-headline').value.trim(),summary=$('studio-summary').value.trim(),action=$('studio-action').value.trim();
  let titleSize=64,titleLines=wrap(headline,952,titleSize,'700');
  while(titleLines.length>3&&titleSize>42){titleSize-=2;titleLines=wrap(headline,952,titleSize,'700')}
  let y=380;ctx.fillStyle='#F6F8FB';ctx.font=`700 ${titleSize}px Arial`;titleLines.forEach(line=>{ctx.fillText(line,64,y);y+=titleSize*1.14});
  y+=22;ctx.fillStyle='#83B5FF';ctx.font='700 34px Arial';ctx.fillText(studioRecord?.cveID||'Select a CVE to begin',64,y);y+=58;
  const body=template==='action'?action:summary,bodyLines=wrap(body,940,32);
  ctx.fillStyle='#F6F8FB';ctx.font='400 32px Arial';bodyLines.forEach(line=>{ctx.fillText(line,64,y);y+=44});
  const badgeY=y+30;const fits=badgeY+(studioRecord?.severity?125:0)<h-200&&titleLines.length<=3&&[...titleLines].every(l=>{ctx.font=`700 ${titleSize}px Arial`;return ctx.measureText(l).width<=952})&&bodyLines.every(l=>{ctx.font='400 32px Arial';return ctx.measureText(l).width<=940});
  if(studioRecord?.severity){const v=studioRecord.severity;const colors={CRITICAL:'#B42335',HIGH:'#AF4A00',MEDIUM:'#775300',LOW:'#206341',NONE:'#526579',Unavailable:'#526579'};ctx.fillStyle=colors[v.label]||'#526579';ctx.fillRect(64,badgeY,446,120);ctx.fillStyle='#FFFFFF';ctx.font='700 19px Arial';ctx.fillText('CVSS SEVERITY',84,badgeY+29);ctx.font='700 37px Arial';ctx.fillText(v.score===null?'UNAVAILABLE':v.label,84,badgeY+72);ctx.font='700 24px Arial';ctx.fillText(v.score===null?'No score found':`${v.score.toFixed(1)}  ·  CVSS ${v.version}`,84,badgeY+105);}
  ctx.fillStyle='#06152B';ctx.fillRect(0,h-180,1080,180);ctx.fillStyle='#FFFFFF';ctx.font='700 27px Arial';ctx.fillText('Known exploitation: listed in CISA KEV',64,h-118);
  ctx.font='400 22px Arial';ctx.fillText('Source: CISA KEV · Added '+(studioRecord?.dateAdded||'—'),64,h-73);ctx.fillText(studioRecord?.severity?.score!==null&&studioRecord?.severity?'CVSS source: CVE record · Verify vendor guidance.':'Verify current vendor guidance before acting.',64,h-35);
  $('studio-length').textContent=`Headline ${headline.length}/70 · Summary ${summary.length}/220 · Action ${action.length}/180`;
  graphicValid=Boolean(studioRecord&&logoReady&&headline&&body&&fits&&headline.length<=70&&summary.length<=220&&action.length<=180);
  $('studio-feedback').textContent=!studioRecord?'Choose a CVE to populate the template.':!fits?'Text exceeds the safe layout. Shorten it or choose a taller format.':!logoReady?'Loading original brand image…':'Preview ready. Confirm the facts and layout to enable export.';
  $('studio-png').disabled=$('studio-caption').disabled=$('studio-alt').disabled=!(graphicValid&&$('studio-approved').checked);
}
async function readJSON(file,max=2000000){if(!file)throw Error('Choose a JSON file.');if(file.size>max)throw Error('File is too large.');return JSON.parse(await file.text())}
$('watch-vendor').addEventListener('change',pickOptions);
$('watch-form').addEventListener('submit',event=>{event.preventDefault();const w={vendor:$('watch-vendor').value,product:$('watch-product').value};if(!w.vendor)return;if(state.watches.some(x=>x.vendor===w.vendor&&x.product===w.product)){announce('Already followed.');return}if(state.watches.length>=200){announce('Watchlist limit reached.');return}state.watches.push(w);page=1;save('Watchlist updated.');render()});
$('watch-tags').addEventListener('click',e=>{const b=e.target.closest('[data-remove]');if(b){state.watches.splice(Number(b.dataset.remove),1);save('Watch removed.');render()}});
document.addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.save){const id=b.dataset.save;if(state.saved.includes(id))state.saved=state.saved.filter(x=>x!==id);else state.saved.push(id);save('Saved CVEs updated.');render()}if(b.dataset.review){openReview(b.dataset.review);$('queue').scrollIntoView()}if(b.dataset.studio){loadStudio(b.dataset.studio);$('studio').scrollIntoView()}});
for(const id of ['match-search','match-mode'])$(id).addEventListener(id==='match-search'?'input':'change',()=>{page=1;render()});
$('watch-prev').addEventListener('click',()=>{page--;render()});$('watch-next').addEventListener('click',()=>{page++;render()});
$('load-review').addEventListener('click',()=>openReview($('review-cve').value.trim().toUpperCase()));
$('review-cve').addEventListener('input',()=>{reviewId='';$('review-form').hidden=true;$('review-context').textContent='Open the selected CVE to review it.'});
$('review-form').addEventListener('submit',event=>{event.preventDefault();if(!reviewId)return;const next=$('review-date').value;if(next&&!C.validDate(next)){announce('Enter a valid review date.');return}state.reviews[reviewId]={status:$('review-status').value,notes:$('review-notes').value,nextReview:next,updatedAt:new Date().toISOString()};save('Review saved.');render()});
$('review-studio').addEventListener('click',()=>{loadStudio(reviewId);$('studio').scrollIntoView()});
$('queue-filter').addEventListener('change',render);
$('digest').addEventListener('click',()=>{const list=records.filter(r=>C.matches(r,state.watches)).sort((a,b)=>b.dateAdded.localeCompare(a.dateAdded));download('1dotq-watchlist-digest.md','text/markdown','# 1dotq watchlist digest\n\nSource: bundled CISA KEV snapshot. Not an exposure assessment.\n\n'+list.map(r=>`## ${r.cveID} — ${r.vulnerabilityName}\n\nKEV added: ${r.dateAdded}\n\n${r.shortDescription}\n\nCISA action: ${r.requiredAction}\n\n`).join(''))});
$('export-reviews').addEventListener('click',()=>download('1dotq-private-reviews.json','application/json',JSON.stringify({exportedAt:new Date().toISOString(),reviews:state.reviews},null,2)));
$('change-file').addEventListener('change',async event=>{try{comparison=C.changeReport(await readJSON(event.target.files[0],10000000));renderChanges();announce('Comparison loaded locally.')}catch(e){announce(e.message)}finally{event.target.value=''}});
for(const id of ['change-filter','change-watched'])$(id).addEventListener('change',renderChanges);
$('studio-load').addEventListener('click',()=>loadStudio($('studio-cve').value.trim().toUpperCase()));
$('studio-reset').addEventListener('click',()=>{if(studioRecord)loadStudio(studioRecord.cveID)});
for(const id of ['studio-template','studio-format','studio-headline','studio-summary','studio-action'])$(id).addEventListener(id.includes('template')||id.includes('format')?'change':'input',invalidate);
$('studio-approved').addEventListener('change',drawGraphic);
$('studio-cve').addEventListener('input',()=>{studioRecord=null;invalidate()});
$('studio-png').addEventListener('click',()=>{if(!graphicValid||!$('studio-approved').checked)return;canvas.toBlob(blob=>{if(!blob){announce('PNG export failed.');return}download(studioRecord.cveID+'-'+$('studio-template').value+'-'+$('studio-format').value+'.png','image/png',blob);announce('PNG exported. Nothing was posted.')},'image/png')});
$('studio-caption').addEventListener('click',()=>{if(!graphicValid||!$('studio-approved').checked)return;download(studioRecord.cveID+'-caption-draft.txt','text/plain',`${$('studio-headline').value}\n${studioRecord.cveID}\n\n${$('studio-summary').value}\n\n${$('studio-action').value}\n\nSource: CISA KEV, added ${studioRecord.dateAdded}\nhttps://www.cisa.gov/known-exploited-vulnerabilities-catalog\n\nReview and adapt for your platform before posting.\n`)});
$('export-workspace').addEventListener('click',()=>download('1dotq-private-workspace.json','application/json',JSON.stringify({...state,exportedAt:new Date().toISOString()},null,2)));
$('import-workspace').addEventListener('change',async event=>{try{const incoming=C.validate(await readJSON(event.target.files[0]));state=C.merge(state,incoming);save('Workspace merged.');render()}catch(e){announce('Import rejected: '+e.message)}finally{event.target.value=''}});
$('reset-workspace').addEventListener('click',()=>{if(!confirm('Reset this browser’s watchlist, saved CVEs and review notes? Export a workspace copy first if you need them.'))return;try{localStorage.removeItem(KEY);storageOK=true}catch{}state=C.fresh();reviewId='';$('review-form').hidden=true;$('review-context').textContent='';save('Local workspace reset.');render()});
logo.onload=()=>{logoReady=true;drawGraphic();if(batchRecords.length)$('batch-generate').disabled=false};logo.onerror=()=>{$('studio-feedback').textContent='Brand image could not load. Export is disabled.'};logo.src='brand.png';
fetch('kev.json').then(r=>{if(!r.ok)throw Error('Catalog unavailable');return r.json()}).then(data=>{if(!Array.isArray(data.vulnerabilities)||data.count!==data.vulnerabilities.length||data.vulnerabilities.some(r=>!C.validId(r.cveID)))throw Error('Catalog validation failed');records=data.vulnerabilities;byId=new Map(records.map(r=>[r.cveID,r]));$('watch-vendor').innerHTML='<option value="">Choose vendor</option>'+[...new Set(records.map(r=>r.vendorProject))].sort().map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');$('cve-options').innerHTML=records.map(r=>`<option value="${r.cveID}">${esc(r.vendorProject+' '+r.product)}</option>`).join('');if(storageOK)announce('Workspace ready · CISA snapshot '+data.catalogVersion);render();const id=new URLSearchParams(location.search).get('id');if(byId.has(id)){openReview(id);loadStudio(id)}}).catch(e=>announce('Unable to load catalog: '+e.message));

$('review-notes').addEventListener('input',()=>{$('notes-length').textContent=$('review-notes').value.length+' / 4000 characters · Ctrl+Enter saves this review.'});
$('review-notes').addEventListener('keydown',event=>{if(event.ctrlKey&&event.key==='Enter'){event.preventDefault();$('review-form').requestSubmit()}});
$('copy-review-id').addEventListener('click',async()=>{if(!reviewId)return;try{await navigator.clipboard.writeText(reviewId);announce('CVE identifier copied.')}catch{announce('Copy this identifier: '+reviewId)}});
$('studio-alt').addEventListener('click',()=>{if(!graphicValid||!$('studio-approved').checked)return;download(studioRecord.cveID+'-alt-text.txt','text/plain','1dotq Threat Intel graphic. '+$('studio-headline').value+'. '+studioRecord.cveID+'. '+($('studio-template').value==='action'?$('studio-action').value:$('studio-summary').value)+' Known exploitation: listed in CISA KEV. Source: CISA KEV, added '+studioRecord.dateAdded+'.');announce('Alt text exported for the image.')});

function autoSummary(text){const t=text.trim();if(t.length<=220)return t;const prefix=t.slice(0,220);const ends=[...prefix.matchAll(/[.!?](?=\s|$)/g)];if(ends.length)return prefix.slice(0,ends[ends.length-1].index+1);return C.excerpt(t,220)}
async function lookupSeverity(id){
  const unavailable={score:null,label:'Unavailable'};
  try{
    const response=await fetch('https://cveawg.mitre.org/api/cve/'+encodeURIComponent(id),{signal:AbortSignal.timeout(10000)});
    if(!response.ok)return unavailable;const data=await response.json();if(data?.cveMetadata?.cveId!==id)return unavailable;
    const providers=[data?.containers?.cna,...(Array.isArray(data?.containers?.adp)?data.containers.adp:[])];
    for(const provider of providers){for(const version of ['4_0','3_1','3_0']){for(const metric of (Array.isArray(provider?.metrics)?provider.metrics:[])){const m=metric['cvssV'+version];const score=m?.baseScore;if(typeof score==='number'&&Number.isFinite(score)&&score>=0&&score<=10){const label=score===0?'NONE':score<4?'LOW':score<7?'MEDIUM':score<9?'HIGH':'CRITICAL';return {score,label,version:version.replace('_','.'),provider:provider?.providerMetadata?.shortName||'CVE record'};}}}}
    return unavailable;
  }catch{return unavailable}
}
let batchRecords=[];
const batchEditors=$('batch-editors');
function updateBatchButton(){
  $('batch-generate').disabled=!(logoReady&&batchRecords.length);$('batch-final').disabled=!(logoReady&&batchRecords.length&&$('batch-final-approval').checked);
}
function batchDraw(r){
  studioRecord=r; $('studio-cve').value=r.cveID; $('studio-headline').value=r.headline; $('studio-summary').value=r.summary; $('studio-action').value='Check the vendor advisory for affected versions and the appropriate remediation.'; $('studio-template').value='alert'; $('studio-format').value='portrait'; $('studio-approved').checked=false; drawGraphic(); return graphicValid;
}
function openBatchPreview(r){
  const ok=batchDraw(r); $('studio-source').innerHTML=`<p class="hint">Batch preview: ${esc(r.cveID)} · source added ${esc(r.dateAdded)}</p>`;
  if(ok){r.previewed=true; $('batch-status').textContent='Previewing '+r.cveID+'. Check the graphic below and its source before approving.'}else{r.previewed=false; $('batch-status').textContent='Text does not fit for '+r.cveID+'. Shorten the headline or summary.'}
  updateBatchButton(); $('graphic').scrollIntoView({behavior:'smooth',block:'center'});
}
$('batch-file').addEventListener('change',async e=>{
  batchRecords=[]; batchEditors.replaceChildren(); $('batch-final-approval').checked=false; updateBatchButton();
  try {
    const data=await readJSON(e.target.files[0],1000000);
    if(!Array.isArray(data)||!data.length||data.length>5)throw Error('Select a JSON array of 1 to 5 CISA records.');
    for(const r of data)if(!r||!C.validId(r.cveID)||!['vendorProject','product','shortDescription','dateAdded'].every(k=>typeof r[k]==='string'&&r[k].length>0&&r[k].length<5000)||!C.validDate(r.dateAdded))throw Error('A record is missing required CISA fields.');
    if(new Set(data.map(r=>r.cveID)).size!==data.length)throw Error('The file contains duplicate CVE IDs.');
    $('batch-status').textContent='Looking up CVSS scores from CVE records…';
    const scores=await Promise.all(data.map(r=>lookupSeverity(r.cveID)));
    batchRecords=data.map((r,i)=>({...r,severity:scores[i],headline:(r.vendorProject+' '+r.product).slice(0,70),summary:autoSummary(r.shortDescription),approved:false,previewed:false}));updateBatchButton();
    batchEditors.innerHTML=batchRecords.map((r,i)=>`<article class="bench-card"><h4>${esc(r.cveID)}</h4><p class="hint">${r.severity.score===null?'Severity unavailable':esc(r.severity.label+' '+r.severity.score.toFixed(1)+' · CVSS '+r.severity.version+' · '+r.severity.provider)}</p><label>Headline<input data-batch-headline="${i}" maxlength="70" value="${esc(r.headline)}"></label><label>Summary<textarea data-batch-summary="${i}" maxlength="220" rows="4">${esc(r.summary)}</textarea></label><p class="hint">Compare with <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">CISA KEV</a> and the vendor advisory. Rewrite any incomplete excerpt.</p><button type="button" data-batch-preview="${i}">Preview this slide</button><label class="approval"><input type="checkbox" data-batch-approve="${i}"> I checked the source, complete wording, and preview for ${esc(r.cveID)}.</label></article>`).join('');
    $('batch-status').textContent='Ready to generate drafts automatically. Optional: edit or preview below. Review all output before publishing.';
  }catch(err){$('batch-status').textContent='Import failed: '+err.message}
});
batchEditors.addEventListener('input',e=>{
  const field=e.target.dataset.batchHeadline!==undefined?'headline':e.target.dataset.batchSummary!==undefined?'summary':null;if(!field)return;
  const i=Number(field==='headline'?e.target.dataset.batchHeadline:e.target.dataset.batchSummary),r=batchRecords[i];$('batch-final-approval').checked=false;r[field]=e.target.value;r.approved=false;r.previewed=false;batchEditors.querySelector(`[data-batch-approve="${i}"]`).checked=false;updateBatchButton();
});
batchEditors.addEventListener('click',e=>{const b=e.target.closest('[data-batch-preview]');if(b)openBatchPreview(batchRecords[Number(b.dataset.batchPreview)])});
batchEditors.addEventListener('change',e=>{
  if(e.target.dataset.batchApprove===undefined)return;const r=batchRecords[Number(e.target.dataset.batchApprove)];
  if(e.target.checked&&(!r.previewed||!r.headline.trim()||!r.summary.trim()||/[.…]$/.test(r.summary.trim())&&r.summary.trim().endsWith('…'))){e.target.checked=false;$('batch-status').textContent='Preview the slide and replace any shortened ending before approving.'}
  r.approved=e.target.checked;updateBatchButton();
});
$('batch-final-approval').addEventListener('change',updateBatchButton);
async function exportBatch(finalExport){
  if(!logoReady||!batchRecords.length)return;
  $('batch-generate').disabled=true;
  try{
    for(const r of batchRecords)if(!batchDraw(r))throw Error('Text does not fit for '+r.cveID+'. Shorten it and preview again.');
    canvas.width=1080;canvas.height=1350;ctx.fillStyle='#0B1F3B';ctx.fillRect(0,0,1080,1350);ctx.fillStyle='#0057D6';ctx.fillRect(0,0,1080,14);ctx.drawImage(logo,54,38,240,240);ctx.fillStyle='#F6F8FB';ctx.font='700 22px Arial';ctx.fillText('1DOTQ / THREAT INTEL',570,114);ctx.font='700 20px Arial';if(!finalExport)ctx.fillText('DRAFT · REVIEW BEFORE PUBLISHING',570,150);ctx.fillStyle='#0057D6';ctx.font='700 27px Arial';ctx.fillText('WEEKLY SECURITY ROUNDUP',64,330);ctx.fillStyle='#F6F8FB';ctx.font='700 72px Arial';ctx.fillText('Patch priorities',64,430);ctx.font='400 32px Arial';ctx.fillText('Vulnerabilities to review this week',64,500);ctx.font='700 34px Arial';batchRecords.forEach((r,i)=>ctx.fillText(r.cveID,64,610+i*60));ctx.fillStyle='#0B1F3B';ctx.fillRect(0,1170,1080,180);ctx.fillStyle='#FFFFFF';ctx.font='700 27px Arial';ctx.fillText('Source: CISA Known Exploited Vulnerabilities',64,1232);ctx.font='400 22px Arial';ctx.fillText('Check vendor guidance for affected products.',64,1280);
    const cover=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));if(!cover)throw Error('Cover export failed.');download(finalExport?'01-weekly-cover.png':'01-weekly-cover-DRAFT.png','image/png',cover);
    for(let i=0;i<batchRecords.length;i++){const r=batchRecords[i];batchDraw(r);ctx.fillStyle='#F6F8FB';ctx.font='700 20px Arial';if(!finalExport)ctx.fillText('DRAFT · REVIEW BEFORE PUBLISHING',570,150);const blob=await new Promise(resolve=>canvas.toBlob(resolve,'image/png'));if(!blob)throw Error('Export failed for '+r.cveID);download(String(i+2).padStart(2,'0')+'-'+r.cveID+(finalExport?'.png':'-DRAFT.png'),'image/png',blob);await new Promise(resolve=>setTimeout(resolve,300))}
    const caption=(finalExport?'':'DRAFT — REVIEW FACTS BEFORE PUBLISHING\n\n')+'This week’s patch priorities\n\n'+batchRecords.map(r=>r.cveID+' — '+r.headline+'\n'+(r.severity.score===null?'Severity unavailable':r.severity.label+' '+r.severity.score.toFixed(1)+' (CVSS '+r.severity.version+', '+r.severity.provider+')')+'\n'+r.summary).join('\n\n')+'\n\nCheck the applicable vendor advisories and remediate affected systems.\n\nSource: CISA Known Exploited Vulnerabilities Catalog\nhttps://www.cisa.gov/known-exploited-vulnerabilities-catalog\n';download('weekly-caption.txt','text/plain',caption);
    $('batch-status').textContent='Generated the '+(finalExport?'final':'draft')+' cover, slides and caption. Allow multiple downloads if prompted. Nothing was posted.';
  }catch(err){$('batch-status').textContent='Export stopped: '+err.message+'. Some files may already have downloaded.'}finally{updateBatchButton()}
}
$('batch-generate').addEventListener('click',()=>exportBatch(false));
$('batch-final').addEventListener('click',()=>{if($('batch-final-approval').checked)exportBatch(true)});
