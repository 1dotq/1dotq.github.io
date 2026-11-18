(() => {
  const $ = id => document.getElementById(id);
  let snapshot, selected;
  const when = value => new Date(value).toLocaleString();
  const node = (tag, text, cls) => { const x=document.createElement(tag); x.textContent=text; if(cls)x.className=cls; return x; };
  async function load() {
    $('live-stamp').textContent='Loading public snapshot…';
    try {
      const response=await fetch('public-operations.json?ts='+Date.now(),{cache:'no-store'});
      if(!response.ok)throw Error('HTTP '+response.status);
      snapshot=await response.json();
      $('live-stamp').textContent='Snapshot generated '+when(snapshot.generated_at)+' · auto refresh every 5 minutes';
      render();
    } catch(e) { $('live-stamp').textContent='Map data unavailable: '+e.message; $('map-list').textContent='Open the IODA source for current measurements.'; }
  }
  function render() {
    if(!snapshot)return;
    const hours=Number($('map-window').value), level=$('map-level').value, cutoff=Date.now()-hours*3600000;
    const alerts=(snapshot.alerts||[]).filter(x=>Date.parse(x.time)>=cutoff && (level==='all'||x.level===level));
    const groups=new Map();
    for(const x of alerts){if(!groups.has(x.country_code))groups.set(x.country_code,[]);groups.get(x.country_code).push(x);}
    $('map-country-count').textContent=groups.size;
    $('map-alert-count').textContent=alerts.length;
    $('map-critical-count').textContent=alerts.filter(x=>x.level==='critical').length;
    const points=$('map-points'),list=$('map-list');points.replaceChildren();list.replaceChildren();
    if(!groups.size){list.append(node('div','No located alerts match this window. This does not establish that networks are healthy.','live-empty'));$('map-detail').textContent='No location selected.';return;}
    const ordered=[...groups.entries()].sort((a,b)=>b[1].length-a[1].length);
    for(const [code,items] of ordered){
      const first=items[0],button=node('button',String(items.length),'map-point'+(items.some(x=>x.level==='critical')?' critical':''));
      button.type='button';button.style.left=(first.x/1080*100)+'%';button.style.top=(first.y/540*100)+'%';
      button.setAttribute('aria-label',first.country+': '+items.length+' connectivity alerts');button.title=first.country+' · '+items.length+' alerts';
      button.onclick=()=>select(code,items);points.append(button);
      const entry=node('button','','live-item');entry.type='button';entry.dataset.code=code;
      entry.append(node('strong',first.country+' · '+items.length+' alerts'),node('small','Latest '+when(first.time)+' · '+first.level));
      entry.onclick=()=>select(code,items);list.append(entry);
    }
    if(selected&&groups.has(selected))select(selected,groups.get(selected));else select(ordered[0][0],ordered[0][1]);
  }
  function select(code,items){
    selected=code;document.querySelectorAll('.live-item').forEach(x=>x.setAttribute('aria-pressed',String(x.dataset.code===code)));
    const detail=$('map-detail');detail.replaceChildren();
    detail.append(node('h3',items[0].country),node('p',items.length+' source measurements in the selected window. Country placement is approximate.'));
    const list=document.createElement('ul');
    for(const x of items.slice(0,12)){
      const li=node('li',x.name+' · '+x.level+' · '+x.datasource+' · '+when(x.time));list.append(li);
    }
    detail.append(list);
    const a=node('a','Open IODA country measurements ↗');a.href=items[0].url;a.target='_blank';a.rel='noopener noreferrer';detail.append(a);
  }
  $('map-window').onchange=render;$('map-level').onchange=render;$('map-refresh').onclick=load;
  load();setInterval(load,300000);
})();
