(() => {
  const $=id=>document.getElementById(id),make=(tag,text,cls)=>{const e=document.createElement(tag);e.textContent=text;if(cls)e.className=cls;return e;};
  let operations,signals,selected;
  const date=s=>s?new Date(s).toLocaleString():'Unknown';
  const open=x=>!['resolved','completed','postmortem'].includes(String(x.status).toLowerCase())&&!x.resolved_at;
  async function load(){
    $('live-stamp').textContent='Loading public snapshots…';
    try{
      const [a,b]=await Promise.all([fetch('public-operations.json?ts='+Date.now(),{cache:'no-store'}),fetch('public-feed.json?ts='+Date.now(),{cache:'no-store'})]);
      if(!a.ok||!b.ok)throw Error('public source HTTP '+a.status+'/'+b.status);
      operations=await a.json();signals=await b.json();
      $('live-stamp').textContent='Published '+date(operations.generated_at)+' · auto refresh every 5 minutes';
      const providers=[...new Set(operations.incidents.map(x=>x.provider))].sort();const picker=$('outage-provider'),old=picker.value;
      picker.replaceChildren();const all=make('option','All monitored providers');all.value='all';picker.append(all);
      for(const p of providers){const o=make('option',p);o.value=p;picker.append(o)}picker.value=providers.includes(old)?old:'all';
      render();
    }catch(e){$('live-stamp').textContent='Outage snapshot unavailable: '+e.message;$('outage-list').textContent='Check provider status pages directly.'}
  }
  function render(){if(!operations)return;const all=operations.incidents||[];
    $('outage-total').textContent=all.length;$('outage-open').textContent=all.filter(open).length;$('outage-alerts').textContent=(operations.alerts||[]).length;
    const provider=$('outage-provider').value,state=$('outage-state').value,q=$('outage-search').value.trim().toLowerCase();
    const rows=all.filter(x=>(provider==='all'||x.provider===provider)&&(state==='all'||(state==='open')===open(x))&&(!q||(x.provider+' '+x.category+' '+x.title+' '+x.summary).toLowerCase().includes(q)));
    const list=$('outage-list');list.replaceChildren();
    if(!rows.length)list.append(make('div','No provider incidents match these filters. The feeds are partial; check the original status pages.','live-empty'));
    for(const x of rows){const card=make('button','','outage-card');card.type='button';card.setAttribute('aria-pressed',String(x.id===selected));
      card.append(make('span',x.provider+' · '+x.category,'outage-pill'+(open(x)?' active':'')),make('strong',x.title),
        make('small',date(x.updated_at)+' · '+x.status));card.onclick=()=>show(x);list.append(card)}
    const coverage=$('outage-coverage');coverage.replaceChildren();
    const staticSources=[['Cloudflare','Cloud / DNS / CDN','https://www.cloudflarestatus.com/'],['GitHub','Developer infrastructure','https://www.githubstatus.com/'],['Google Cloud','Cloud','https://status.cloud.google.com/']];
    for(const [name,category,url] of staticSources){const article=document.createElement('article'),a=make('a',name+' ↗');a.href=url;a.target='_blank';a.rel='noopener noreferrer';article.append(a,make('small',category+' · sampled in public signal feed'));coverage.append(article)}
    for(const x of operations.sources||[]){const article=document.createElement('article'),a=make('a',x.source.toUpperCase()+' ↗');a.href=x.url;a.target='_blank';a.rel='noopener noreferrer';article.append(a,make('small',(x.status==='ok'?'Checked '+date(x.checked_at):'Collector error at '+date(x.checked_at))+(x.source==='ioda'?' · connectivity measurements':' · provider incident feed')));coverage.append(article)}
    const match=rows.find(x=>x.id===selected)||rows[0];if(match)show(match);else{$('outage-detail').textContent='No incident selected.';$('outage-nearby').replaceChildren()}
  }
  function show(x){selected=x.id;document.querySelectorAll('.outage-card').forEach((card,i)=>card.setAttribute('aria-pressed',String((operations.incidents||[]).find(y=>y.id===x.id)?.title===card.querySelector('strong')?.textContent)));
    const detail=$('outage-detail');detail.replaceChildren();detail.append(make('p',x.provider+' · '+x.category+' · '+x.status),make('h3',x.title));
    const timeline=document.createElement('div');for(const [label,time,body] of [['Reported',x.started_at,x.summary],['Updated',x.updated_at,x.status],['Resolved',x.resolved_at,'Provider marked this incident resolved']]){
      if(!time)continue;const row=make('div','','timeline-row');row.append(make('time',label+' · '+date(time)),make('p',body||''));timeline.append(row)}detail.append(timeline);
    const source=make('a','Open provider report ↗');source.href=x.url;source.target='_blank';source.rel='noopener noreferrer';detail.append(source);
    const nearby=$('outage-nearby');nearby.replaceChildren();const center=Date.parse(x.started_at),windowMs=12*3600000;
    const candidates=(signals?.items||[]).filter(y=>y.kind!=='outage'&&Number.isFinite(Date.parse(y.updated_at))&&Math.abs(Date.parse(y.updated_at)-center)<=windowMs).slice(0,5);
    if(!candidates.length){nearby.append(make('p','No sampled security signal falls within ±12 hours. This does not rule out an incident.'));return}
    for(const y of candidates){const row=make('div','','coincidence'),a=make('a',y.title);a.href=y.url;a.target='_blank';a.rel='noopener noreferrer';row.append(a,make('small',y.source+' · '+date(y.updated_at)));nearby.append(row)}
  }
  for(const id of ['outage-provider','outage-state','outage-search'])$(id).addEventListener(id==='outage-search'?'input':'change',render);
  $('outage-refresh').onclick=load;load();setInterval(load,300000);
})();
