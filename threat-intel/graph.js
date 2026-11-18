(() => {
  const $=id=>document.getElementById(id),NS='http://www.w3.org/2000/svg';
  let graph,lookup,adj,focus,actor,limit=18;
  const el=(tag,text,cls)=>{const x=document.createElement(tag);x.textContent=text;if(cls)x.className=cls;return x;};
  const svg=(tag,attrs)=>{const x=document.createElementNS(NS,tag);for(const [k,v] of Object.entries(attrs))x.setAttribute(k,v);return x;};
  function neighbors(id){return (adj.get(id)||[]).sort((a,b)=>{
    const order={vulnerability:0,sector:1,incident:2,campaign:3,malware:4,tool:5,technique:6,actor:7};return order[lookup.get(a.id)?.type]-order[lookup.get(b.id)?.type];
  });}
  function show(id){
    if(!lookup.has(id))return;focus=id;const center=lookup.get(id),items=neighbors(id),visible=items.slice(0,limit),canvas=$('graph-canvas');
    canvas.replaceChildren();
    const cx=450,cy=300,radius=Math.min(230,Math.max(140,visible.length*12));
    visible.forEach((edge,i)=>{
      const angle=-Math.PI/2+i*2*Math.PI/Math.max(visible.length,1),x=cx+Math.cos(angle)*radius,y=cy+Math.sin(angle)*radius;
      canvas.append(svg('line',{x1:cx,y1:cy,x2:x,y2:y}));
    });
    const draw=(node,x,y,isCenter)=>{
      const group=svg('g',{class:'graph-node '+node.type,tabindex:'0',role:'button','aria-label':'Expand '+node.name+' relationships'});
      group.append(svg('circle',{cx:x,cy:y,r:isCenter?30:21}));
      const label=svg('text',{x,y:y+(isCenter?52:39)});
      const short=node.name.length>22?node.name.slice(0,20)+'…':node.name;label.textContent=short;group.append(label);
      group.onclick=()=>{limit=18;show(node.id)};
      group.onkeydown=e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();group.click()}};
      canvas.append(group);
    };
    visible.forEach((edge,i)=>{const angle=-Math.PI/2+i*2*Math.PI/Math.max(visible.length,1);draw(lookup.get(edge.id),cx+Math.cos(angle)*radius,cy+Math.sin(angle)*radius,false)});
    draw(center,cx,cy,true);
    $('graph-more').disabled=items.length<=limit;$('graph-more').textContent=items.length>limit?'Show more relationships ('+(items.length-limit)+' remaining)':'All direct relationships shown';
    $('graph-count').textContent=items.length+' direct documented relationships';
    const detail=$('graph-detail');detail.replaceChildren();detail.append(el('p',center.type.toUpperCase()+(center.external_id?' · '+center.external_id:'')),el('h3',center.name));
    if(center.aliases?.length)detail.append(el('p','Also known as: '+center.aliases.join(', ')));
    if(center.description)detail.append(el('p',center.description.replace(/\[(\d+)\]/g,'')));
    const link=el('a','Open MITRE ATT&CK record ↗');link.href=center.url;link.target='_blank';link.rel='noopener noreferrer';detail.append(link);
    const groups=new Map();for(const edge of items){const n=lookup.get(edge.id);if(!groups.has(n.type))groups.set(n.type,[]);groups.get(n.type).push({node:n,edge});}
    const rel=$('graph-relationships');rel.replaceChildren();
    for(const [type,entries] of groups){const section=el('section','','graph-group');section.append(el('h3',type[0].toUpperCase()+type.slice(1)+' · '+entries.length));
      const ul=document.createElement('ul');for(const {node:n,edge} of entries.slice(0,12)){const li=document.createElement('li'),button=el('button',n.name,'live-button');button.type='button';button.onclick=()=>{limit=18;show(n.id)};li.append(button);
        if(edge.evidence==='CISA joint advisory'){const citation=el('a','CISA evidence ↗');citation.href=edge.url;citation.target='_blank';citation.rel='noopener noreferrer';li.append(citation)}ul.append(li)}
      section.append(ul);rel.append(section);
    }
    if(center.type==='actor' && !['vulnerability','sector','incident'].some(type=>groups.has(type))){
      const gap=el('div','','graph-group');gap.append(el('h3','CVEs, sectors, related incidents'),el('p','No direct, verified links are published for this actor. Shared techniques and time overlap are not evidence of attribution.'));rel.append(gap);
    }
  }
  function find(){const q=$('actor-search').value.trim().toLowerCase();if(!q)return;const candidates=[...lookup.values()].filter(n=>n.type==='actor');
    const match=candidates.find(n=>n.name.toLowerCase()===q||n.external_id?.toLowerCase()===q)||candidates.find(n=>n.name.toLowerCase().includes(q)||n.aliases?.some(a=>a.toLowerCase().includes(q)));
    if(match){actor=match.id;limit=18;show(match.id)}else $('graph-count').textContent='No matching actor in this ATT&CK snapshot.';
  }
  async function load(){
    try{const response=await fetch('threat-graph.json',{cache:'no-cache'});if(!response.ok)throw Error('HTTP '+response.status);graph=await response.json();
      lookup=new Map(graph.nodes.map(n=>[n.id,n]));adj=new Map();
      for(const edge of graph.edges){if(!lookup.has(edge.source)||!lookup.has(edge.target))continue;
        for(const [a,b] of [[edge.source,edge.target],[edge.target,edge.source]]){if(!adj.has(a))adj.set(a,[]);adj.get(a).push({id:b,type:edge.type,url:edge.url})}}
      const actors=graph.nodes.filter(n=>n.type==='actor').sort((a,b)=>a.name.localeCompare(b.name));
      const options=$('actor-options');for(const n of actors){const o=document.createElement('option');o.value=n.name;options.append(o)}
      $('live-stamp').textContent=actors.length+' documented actors · ATT&CK export '+new Date(graph.generated_at).toLocaleString();
      actor=actors.find(n=>adj.get(n.id)?.length)?.id;show(actor);
    }catch(e){$('live-stamp').textContent='Threat graph unavailable: '+e.message;$('graph-detail').textContent='Open MITRE ATT&CK for the original records.'}
  }
  $('actor-find').onclick=find;$('actor-search').onkeydown=e=>{if(e.key==='Enter')find()};
  $('graph-more').onclick=()=>{limit+=18;show(focus)};$('graph-back').onclick=()=>{limit=18;show(actor)};
  load();
})();
