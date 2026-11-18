'use strict';
window.PublicCore=Object.freeze({
  id:value=>/^CVE-\d{4}-\d{4,}$/.test(String(value||'')),
  https:value=>{try{const u=new URL(value);return u.protocol==='https:'&&!u.username&&!u.password?u.href:null}catch{return null}},
  day:value=>/^\d{4}-\d{2}-\d{2}$/.test(String(value||'').slice(0,10))?String(value).slice(0,10):'',
  time:value=>{const d=new Date(value);return Number.isNaN(d.getTime())?'Unavailable':d.toLocaleString(undefined,{dateStyle:'medium',timeStyle:'short'})},
  el:(tag,text,cls)=>{const n=document.createElement(tag);n.textContent=String(text??'');if(cls)n.className=cls;return n},
  async load(path,check){const r=await fetch(path,{cache:'no-store'});if(!r.ok)throw Error(path+' unavailable (HTTP '+r.status+')');const data=await r.json();if(!check(data))throw Error(path+' failed validation');return data},
  catalog:data=>Array.isArray(data?.vulnerabilities)&&data.count===data.vulnerabilities.length&&data.vulnerabilities.every(r=>/^CVE-\d{4}-\d{4,}$/.test(r.cveID||'')),
  feed:data=>Array.isArray(data?.items)&&Array.isArray(data?.sources),
  details:data=>data&&typeof data.records==='object'&&!Array.isArray(data.records),
  csv:rows=>rows.map(row=>row.map(value=>{let s=String(value??'');if(/^[\t\r\n ]*[=+@\-]/.test(s))s="'"+s;return '"'+s.replaceAll('"','""')+'"'}).join(',')).join('\r\n'),
  download:(name,type,content)=>{const url=URL.createObjectURL(new Blob([content],{type})),a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)},
  daysAgo:days=>new Date(Date.now()-days*86400000).toISOString().slice(0,10),
  link:(url,label)=>{const a=document.createElement('a');a.href=url;a.textContent=label;if(/^https:\/\//.test(url)){a.target='_blank';a.rel='noopener noreferrer'}return a},
  stale:(value,hours=48)=>{const ms=Date.parse(value);return !Number.isFinite(ms)||Date.now()-ms>hours*3600000}
});
