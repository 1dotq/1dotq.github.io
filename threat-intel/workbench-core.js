(function(root){
  'use strict';
  const validId=id=>typeof id==='string'&&/^CVE-\d{4}-\d{4,}$/.test(id);
  const statuses=['unreviewed','investigating','reviewed','deferred'];
  const fresh=()=>({version:1,watches:[],saved:[],reviews:{}});
  const text=(value,max)=>typeof value==='string'?value.slice(0,max):'';
  function validDate(value){return typeof value==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(value)&&!Number.isNaN(Date.parse(value))&&new Date(value+'T00:00:00Z').toISOString().slice(0,10)===value}
  function validate(input){
    if(!input||input.version!==1||!Array.isArray(input.watches)||!Array.isArray(input.saved)||!input.reviews||typeof input.reviews!=='object'||Array.isArray(input.reviews))throw Error('Not a version 1 workspace export.');
    if(input.watches.length>200||input.saved.length>5000||Object.keys(input.reviews).length>5000)throw Error('Workspace exceeds supported limits.');
    const out=fresh(),seen=new Set();
    for(const w of input.watches){
      if(!w||typeof w.vendor!=='string'||!w.vendor.trim()||typeof w.product!=='string')throw Error('Invalid watch rule.');
      const rule={vendor:text(w.vendor,200),product:text(w.product,200)},key=JSON.stringify(rule);
      if(!seen.has(key)){out.watches.push(rule);seen.add(key)}
    }
    for(const id of input.saved){if(!validId(id))throw Error('Invalid saved CVE.');if(!out.saved.includes(id))out.saved.push(id)}
    for(const [id,r] of Object.entries(input.reviews)){
      if(!validId(id)||!r||!statuses.includes(r.status)||typeof r.notes!=='string'||!Number.isFinite(Date.parse(r.updatedAt))||(r.nextReview&&!validDate(r.nextReview)))throw Error('Invalid review entry.');
      out.reviews[id]={status:r.status,notes:text(r.notes,4000),nextReview:r.nextReview||'',updatedAt:new Date(r.updatedAt).toISOString()};
    }
    return out;
  }
  function merge(a,b){
    const left=validate(a),right=validate(b);
    for(const w of right.watches)if(!left.watches.some(x=>x.vendor===w.vendor&&x.product===w.product))left.watches.push(w);
    left.saved=[...new Set([...left.saved,...right.saved])];
    for(const [id,r] of Object.entries(right.reviews))if(!left.reviews[id]||Date.parse(r.updatedAt)>Date.parse(left.reviews[id].updatedAt))left.reviews[id]=r;
    return validate(left);
  }
  const matches=(r,rules)=>rules.some(w=>r.vendorProject===w.vendor&&(!w.product||r.product===w.product));
  const due=(review,today)=>Boolean(review.nextReview&&review.nextReview<=today);
  function excerpt(value,max){
    const s=text(value,10000).trim();if(s.length<=max)return s;
    const head=s.slice(0,max-1),space=head.lastIndexOf(' ');
    return head.slice(0,space>max/2?space:head.length).trimEnd()+'…';
  }
  function changeReport(data){
    if(!data||!Array.isArray(data.added)||!Array.isArray(data.removed)||!data.changed||typeof data.changed!=='object'||Array.isArray(data.changed))throw Error('Not a catalog comparison report.');
    const events=[];
    for(const kind of ['added','removed'])for(const id of data[kind]){if(!validId(id))throw Error('Invalid comparison CVE.');events.push({kind,id,fields:[]})}
    for(const [id,fields] of Object.entries(data.changed)){if(!validId(id)||!Array.isArray(fields)||fields.some(f=>typeof f!=='string'))throw Error('Invalid changed fields.');events.push({kind:'changed',id,fields:fields.map(f=>text(f,100))})}
    if(events.length>20000)throw Error('Comparison is too large.');
    return {oldVersion:text(data.old_version,80),newVersion:text(data.new_version,80),events,details:data.details&&typeof data.details==='object'?data.details:{}};
  }
  const api={validId,validDate,fresh,validate,merge,matches,due,excerpt,changeReport,statuses};
  root.WorkbenchCore=api;if(typeof module!=='undefined')module.exports=api;
})(typeof globalThis!=='undefined'?globalThis:this);
