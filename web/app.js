'use strict';
const $ = id => document.getElementById(id);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let state = {findings:[],stats:{},metadata:{},audit:[]}, token='', selected=null, uploadMode='findings', busy=false;
const msg = (text, kind='') => { $('notice').textContent=text; $('notice').className='notice '+kind; };
async function api(path, data) {
  const options = data === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json','X-VulnPilot-Token':token},body:JSON.stringify(data)};
  const response=await fetch(path,options), result=await response.json();
  if(!response.ok) throw Error(result.error || 'Request failed');
  return result;
}
function banner(){
  const source=state.metadata.intelligence?.source || '';
  if(source.toLowerCase().includes('synthetic')) msg('DEMONSTRATION WORKSPACE — fictional CVEs and synthetic intelligence. These are not actual security findings.','demo');
  else if(!state.findings.length) msg('Your workspace is ready. Load the demo to explore, or import a normalized findings CSV.');
  else msg(`${state.stats.provisional} findings have incomplete intelligence. Verify source dates and asset applicability before acting.`);
}
function render(){
  for(const key of ['total','active','urgent','overdue']) $(key).textContent=state.stats[key] || 0;
  const active=state.findings.filter(r=>['Open','In progress'].includes(r.status));
  $('distribution').innerHTML=['P1','P2','P3','P4'].map(p=>{const n=active.filter(r=>r.priority===p).length;return `<div class="bar"><span class="badge ${p}">${p}</span><meter aria-label="${p} active findings" min="0" max="${Math.max(1,active.length)}" value="${n}"></meter><b>${n}</b></div>`;}).join('');
  const meta=state.metadata.intelligence;
  $('coverage').textContent=`${state.findings.length-(state.stats.provisional||0)} / ${state.findings.length} complete`;
  const dates=state.findings.map(r=>r.intel_date).filter(Boolean).sort();
  const oldest=dates[0], stale=oldest && (Date.now()-Date.parse(oldest)>7*86400000);
  $('intel-description').textContent=meta ? `${meta.source} · Retrieved ${meta.retrieved_at?.slice(0,16).replace('T',' ')} UTC.${oldest?' Oldest EPSS/snapshot date: '+oldest+'.':''}${stale?' Caution: evidence is over seven days old.':''}` : 'No intelligence snapshot loaded. Missing evidence is shown as unknown.';
  $('audit').innerHTML=state.audit.length?state.audit.slice(0,10).map(a=>`<div class="audit-row"><time>${esc(a.at.slice(0,16).replace('T',' '))} UTC</time><strong>${esc(a.action)}</strong><p>${esc(a.detail)}</p></div>`).join(''):'<p class="muted">Imports, intelligence refreshes and workflow updates will appear here.</p>';
  renderRows(); banner();
}
function renderRows(){
  const query=$('search').value.toLowerCase(), priority=$('priority').value, status=$('status').value;
  const rows=state.findings.filter(r=>(!priority||r.priority===priority)&&(!status||r.status===status)&&[r.asset,r.cve,r.owner,r.title].some(v=>v.toLowerCase().includes(query)));
  $('count').textContent=`${rows.length} of ${state.findings.length} findings`;
  $('rows').innerHTML=rows.length?rows.map(r=>`<tr><td><span class="badge ${esc(r.priority)}">${esc(r.priority)}</span><small>${esc(r.score)} / 100${r.provisional?' · provisional':''}</small></td><td><div class="asset">${esc(r.asset)}</div><small>${esc(r.cve)}</small></td><td><div class="evidence">${r.kev===true?'<span class="kev">KEV listed</span>':r.kev===false?'<span>KEV not listed</span>':'<span class="unknown">KEV unknown</span>'}</div><small>EPSS ${r.epss===null?'unknown':(r.epss*100).toFixed(1)+'%'}</small></td><td>${esc(r.owner)}</td><td>${esc(r.status)}</td><td class="${r.overdue?'danger':''}">${esc(r.target_date)}<small>${r.overdue?'Past internal target':'Internal target'}</small></td><td><button class="review" data-id="${r.id}">Review ↗</button></td></tr>`).join(''):'<tr><td colspan="7" class="empty">No findings match. Import a CSV or load the demo to get started.</td></tr>';
}
async function refresh(){ state=await api('/api/state'); render(); }
async function run(action){
  if(busy)return;
  busy=true;
  document.querySelectorAll('button').forEach(b=>b.disabled=true);
  try{await action();await refresh();}catch(e){msg(e.message,'error');}
  finally{busy=false;document.querySelectorAll('button').forEach(b=>b.disabled=false);}
}
function openUpload(mode){
  uploadMode=mode; $('file').value=''; $('file').accept=mode==='findings'?'.csv':'.json';
  $('upload-title').textContent=mode==='findings'?'Import scanner findings':'Import intelligence snapshot';
  $('upload-help').textContent=mode==='findings'?'Required CSV columns: asset, cve, title, cvss, criticality, internet_exposed, owner. Criticality is 1–5; exposure is true/false. Re-import updates facts and preserves workflow.':'Upload the normalized JSON format in samples/demo_intelligence.json. Source, date and CVE records are required. This replaces the current intelligence snapshot.';
  $('upload-dialog').showModal();
}
$('demo').addEventListener('click',()=>run(async()=>{await api('/api/demo',{});}));
$('refresh').addEventListener('click',()=>run(async()=>{}));
$('import').addEventListener('click',()=>openUpload('findings'));
$('snapshot').addEventListener('click',()=>openUpload('snapshot'));
$('sync').addEventListener('click',()=>$('sync-dialog').showModal());
$('confirm-sync').addEventListener('click',()=>run(async()=>{$('sync-dialog').close();msg('Fetching official intelligence… Feed failures will preserve the previous snapshot.');await api('/api/sync',{});}));
document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>b.closest('dialog').close()));
for(const id of ['search','priority','status']) $(id).addEventListener('input',renderRows);
$('upload-form').addEventListener('submit',e=>{e.preventDefault();const file=$('file').files[0];if(!file)return;if(file.size>2000000){msg('File limit is 2 MB.','error');return;}run(async()=>{const raw=await file.text();await api(uploadMode==='findings'?'/api/import':'/api/snapshot',uploadMode==='findings'?{csv:raw}:{snapshot:raw});$('upload-dialog').close();});});
$('rows').addEventListener('click',e=>{
  const button=e.target.closest('[data-id]');if(!button)return;
  selected=state.findings.find(r=>r.id===Number(button.dataset.id));const r=selected;
  $('finding-detail').innerHTML=`<span class="badge ${esc(r.priority)}">${esc(r.priority)} · ${esc(r.score)}/100</span><h3>${esc(r.asset)}</h3><p>${esc(r.cve)} — ${esc(r.title)}</p><div class="detail-grid"><div><small>BUSINESS OWNER</small>${esc(r.owner)}</div><div><small>EXPOSURE / CRITICALITY</small>${r.internet_exposed?'Internet exposed':'Internal'} · ${r.criticality}/5</div><div><small>INTELLIGENCE SOURCE</small>${esc(r.intel_source)}</div><div><small>INTERNAL TARGET</small>${esc(r.target_date)}</div></div><h4>Why this priority?</h4><ul class="reasons">${r.reasons.map(reason=>`<li>${esc(reason)}</li>`).join('')}</ul><p class="muted">Policy ${esc(r.policy_version)}. The 0–100 score is a transparent heuristic, not an exploitation probability. Validate scanner applicability and consult the vendor's remediation guidance.</p>`;
  $('edit-status').value=r.status;$('notes').value=r.notes;$('finding-dialog').showModal();
});
$('finding-form').addEventListener('submit',e=>{e.preventDefault();run(async()=>{await api('/api/update',{id:selected.id,status:$('edit-status').value,notes:$('notes').value});$('finding-dialog').close();});});
(async()=>{try{token=(await api('/api/session')).token;await refresh();}catch(e){msg('Could not load workspace: '+e.message,'error');}})();
