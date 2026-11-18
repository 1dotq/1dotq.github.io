'use strict';
const byId=id=>document.getElementById(id);
let records=[];
const date=v=>String(v||'').slice(0,10);
function draw(){
  const days=byId('window').value,group=byId('group').value,search=byId('search').value.trim().toLocaleLowerCase();
  const cutoff=days==='all'?'0000-00-00':new Date(Date.now()-Number(days)*86400000).toISOString().slice(0,10);
  const selected=records.filter(r=>date(r.dateAdded)>=cutoff&&(byId('ransomware').value!=='known'||String(r.knownRansomwareCampaignUse).toLowerCase()==='known'));
  const grouped=new Map();
  for(const r of selected){
    const name=group==='vendor'?r.vendorProject:r.vendorProject+' / '+r.product;
    const key=name.trim()||'Unspecified in CISA';
    const current=grouped.get(key)||{name:key,vendor:r.vendorProject,product:r.product,count:0,latest:'',ransomware:0};
    current.count++;current.latest=current.latest>date(r.dateAdded)?current.latest:date(r.dateAdded);
    if(String(r.knownRansomwareCampaignUse).toLowerCase()==='known')current.ransomware++;
    grouped.set(key,current);
  }
  const ranked=[...grouped.values()].sort((a,b)=>b.count-a.count||b.latest.localeCompare(a.latest)||a.name.localeCompare(b.name));
  const shown=ranked.filter(x=>x.name.toLocaleLowerCase().includes(search)).slice(0,Number(byId('limit').value)),max=ranked[0]?.count||1;
  byId('entry-total').textContent=selected.length.toLocaleString();byId('group-total').textContent=grouped.size.toLocaleString();
  byId('ransomware-total').textContent=selected.filter(r=>String(r.knownRansomwareCampaignUse).toLowerCase()==='known').length.toLocaleString();
  byId('result-status').textContent=`Showing ${shown.length} of ${ranked.length} ${group==='vendor'?'vendor':'vendor and product'} groups in this window.`;
  const list=byId('leaderboard');list.replaceChildren();
  if(!shown.length){const p=document.createElement('p');p.textContent='No matching KEV entries in this window.';list.append(p);return}
  for(const entry of shown){
    const row=document.createElement('div');row.className='rank-row';
    const rank=document.createElement('span');rank.className='rank-number';rank.textContent=String(ranked.indexOf(entry)+1).padStart(2,'0');
    const middle=document.createElement('div'),name=document.createElement('a'),meta=document.createElement('div'),bar=document.createElement('div'),fill=document.createElement('span');
    name.className='rank-name';name.textContent=entry.name;name.href='index.html?'+new URLSearchParams(group==='vendor'?{q:entry.vendor}:{q:entry.vendor,product:entry.product})+'#catalog';meta.className='rank-meta';meta.textContent=`Latest addition ${entry.latest} · ${entry.ransomware} marked for known ransomware use`;
    bar.className='rank-bar';fill.style.width=(entry.count/max*100).toFixed(1)+'%';bar.append(fill);middle.append(name,meta,bar);const explore=document.createElement('a');explore.className='rank-explore';explore.href='explore.html?'+new URLSearchParams(group==='vendor'?{vendor:entry.vendor}:{vendor:entry.vendor,product:entry.product});explore.textContent='Explore trend →';middle.append(explore);
    const count=document.createElement('div');count.className='rank-count';count.textContent=entry.count.toLocaleString();const small=document.createElement('small');small.textContent='KEV entries';count.append(small);
    row.append(rank,middle,count);list.append(row);
  }
  const url=new URL(location.href);url.search='';for(const id of ['window','group','ransomware','limit'])if(byId(id).selectedIndex>0)url.searchParams.set(id,byId(id).value);if(byId('search').value.trim())url.searchParams.set('q',byId('search').value.trim());history.replaceState(null,'',url);
}
function exportRankings(){const rows=[['rank','vendor_or_product','kev_entries','latest_added','known_ransomware_use']];for(const row of byId('leaderboard').querySelectorAll('.rank-row')){const rank=row.querySelector('.rank-number').textContent,name=row.querySelector('.rank-name').textContent,count=row.querySelector('.rank-count').firstChild.textContent,meta=row.querySelector('.rank-meta').textContent;const match=meta.match(/Latest addition ([\d-]+) · (\d+)/);rows.push([rank,name,count,match?.[1]||'',match?.[2]||''])}const csv=rows.map(row=>row.map(value=>'"'+String(value).replaceAll('"','""')+'"').join(',')).join('\r\n');const url=URL.createObjectURL(new Blob(['\ufeff'+csv],{type:'text/csv;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download='1dotq-kev-rankings.csv';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
async function main(){
  const response=await fetch('kev.json',{cache:'no-store'});if(!response.ok)throw Error('CISA catalog is unavailable.');
  const catalog=await response.json();if(!Array.isArray(catalog.vulnerabilities)||catalog.count!==catalog.vulnerabilities.length)throw Error('CISA catalog validation failed.');
  records=catalog.vulnerabilities;byId('stamp').textContent=`CISA catalog ${catalog.catalogVersion} · ${records.length.toLocaleString()} entries · collected ${date(catalog.collectedAt)} UTC`;
  const recent=records.slice().sort((a,b)=>date(b.dateAdded).localeCompare(date(a.dateAdded))||a.cveID.localeCompare(b.cveID)).slice(0,12);
  for(const r of recent){if(!/^CVE-\d{4}-\d{4,}$/.test(r.cveID))continue;const card=document.createElement('a');card.className='recent-card';card.href='cve.html?id='+encodeURIComponent(r.cveID);const id=document.createElement('b'),title=document.createElement('span'),when=document.createElement('small');id.textContent=r.cveID;title.textContent=r.vulnerabilityName;when.textContent=`CISA added ${date(r.dateAdded)} · ${r.vendorProject} / ${r.product}`;card.append(id,title,when);byId('recent-list').append(card)}
  const params=new URLSearchParams(location.search);for(const id of ['window','group','ransomware','limit']){const value=params.get(id);if(value&&[...byId(id).options].some(o=>o.value===value))byId(id).value=value}byId('search').value=(params.get('q')||'').slice(0,100);
  for(const key of ['window','group','search','ransomware','limit'])byId(key).addEventListener(key==='search'?'input':'change',draw);
  byId('download-rankings').addEventListener('click',exportRankings);byId('clear-rankings').addEventListener('click',()=>{for(const id of ['window','group','ransomware','limit'])byId(id).selectedIndex=id==='window'?1:0;byId('search').value='';draw();byId('search').focus()});draw();
}
main().catch(error=>{byId('stamp').textContent=error.message;byId('leaderboard').textContent='Rankings are temporarily unavailable.'});
