(function(){
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
const $ = s => document.querySelector(s);
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

/* ---------- Samples ---------- */
const SAMPLES = [
  {name:'تحديث بنكي مزيّف', msg:'البنك: عميلنا العزيز، تم تعليق حسابك مؤقتًا لأسباب أمنية. يرجى تحديث بياناتك خلال 24 ساعة عبر الرابط وإلا سيتم إيقاف الحساب نهائيًا.', url:'http://secure-bank-verify.top/login/update?id=88213'},
  {name:'جائزة وهمية', msg:'مبروك! ربحت جائزة قيمتها 5000 ريال ضمن حملة العملاء المميزين. اضغط الآن لاستلام هديتك، العرض ينتهي اليوم فقط.', url:'https://bit.ly/3xPr1ze'},
  {name:'شحنة معلّقة', msg:'شركة الشحن: شحنتك معلّقة بسبب رسوم جمركية 12 ريال. أكد عنوانك وادفع الرسوم فورًا لتجنب إعادة الشحنة.', url:'https://track-parce1-sa.xyz/pay?ref=SA9921'},
  {name:'رسالة سليمة', msg:'مرحبًا، هذا رابط محضر اجتماع الأمس للمراجعة قبل لقاء الأحد.', url:'https://docs.example.org/meeting-notes'}
];
const sampWrap = $('#samples');
SAMPLES.forEach((s,i)=>{
  const b=document.createElement('button'); b.type='button'; b.className='chip'; b.textContent=s.name; b.id='sample-'+i;
  b.setAttribute('aria-pressed', i===0?'true':'false');
  b.onclick=()=>{ $('#msg').value=s.msg; $('#url').value=s.url; [...sampWrap.children].forEach(c=>c.setAttribute('aria-pressed','false')); b.setAttribute('aria-pressed','true'); run(true); };
  sampWrap.appendChild(b);
});

/* ---------- Analysis engine (in-page heuristics) ---------- */
const TACTICS = {
  urg:{label:'الإلحاح', col:'--warn', words:['عاجل','فورا','فورًا','فوراً','خلال 24','خلال ساعة','الآن','آخر فرصة','ينتهي','اليوم فقط','قبل فوات','urgent','immediately','now','expires','asap','24 hours']},
  auth:{label:'انتحال السلطة', col:'--violet', words:['البنك','بنك','الإدارة','الشرطة','وزارة','الدعم الفني','فريق الأمان','رسمي','شركة الشحن','الجمارك','بريد','حكومي','bank','support','security team','admin','official']},
  fear:{label:'التخويف', col:'--threat', words:['تعليق','إيقاف','ايقاف','حظر','مخالفة','غرامة','اختراق','إغلاق','اغلاق','معلّقة','معلقة','إعادة الشحنة','لأسباب أمنية','suspended','locked','blocked','fine','hacked','closed']},
  rew:{label:'الإغراء', col:'--safe', words:['مبروك','ربحت','فزت','جائزة','مجاني','مجانا','استرداد','هدية','هديتك','خصم','مكافأة','winner','prize','free','refund','gift','reward']},
  act:{label:'طلب إجراء', col:'--cyan', words:['اضغط','ادخل','أدخل','حدّث','تحديث','أكد','أكّد','تأكيد','أرسل الرمز','رمز التحقق','ادفع','سدد','استلام','click','verify','confirm','update','otp','login','pay']}
};
function analyzeMsg(msg){
  const m=msg.toLowerCase(); const res={}; let total=0;
  for(const k in TACTICS){ let hits=0; TACTICS[k].words.forEach(w=>{ if(m.includes(w.toLowerCase())) hits++; }); const v=Math.min(1,hits*0.45); res[k]=v; total+=v; }
  const score=Math.min(100,Math.round(total/3*100));
  return {res,score};
}
function analyzeUrl(raw){
  const out={score:0,find:[],twin:[],rules:{},host:''};
  let u=raw.trim(); if(!u) return out;
  if(!/^[a-z]+:\/\//i.test(u)) u='http://'+u;
  let p; try{p=new URL(u);}catch(e){out.score=20;out.rules.bad=20;out.find.push(['صيغة رابط غير سليمة أو مشوّهة','--warn']);return out;}
  const host=p.hostname.toLowerCase(), full=u.toLowerCase(); out.host=host;
  const add=(s,t,c,id)=>{out.score+=s;out.find.push([t,c||'--threat']);if(id)out.rules[id]=s};
  if(p.protocol==='http:') add(10,'اتصال غير مشفّر (HTTP)','--warn','http');
  if(/^\d+\.\d+\.\d+\.\d+$/.test(host)) add(25,'الرابط يستخدم عنوان IP بدل اسم نطاق',0,'ip');
  if(host.includes('xn--')) add(25,'نطاق بأحرف مُقنّعة تشبه أحرفًا مألوفة (Punycode)',0,'puny');
  if(/\.(top|xyz|click|tk|zip|live|shop|icu|buzz|rest|cfd|sbs|gq|ml)$/.test(host)) add(15,'امتداد نطاق شائع في حملات الاحتيال',0,'tld');
  if(raw.includes('@')) add(20,'وجود رمز @ لإخفاء الوجهة الحقيقية',0,'at');
  if(host.split('.').length>=4) add(10,'عدد كبير من النطاقات الفرعية','--warn','sub');
  if((host.match(/-/g)||[]).length>=2) add(8,'نطاق مركّب بشرطات يقلّد جهة موثوقة','--warn','hyph');
  const short=['bit.ly','tinyurl.com','t.co','cutt.ly','is.gd','rb.gy','shorturl.at','tiny.cc'];
  const isShort=short.includes(host);
  if(isShort) add(14,'رابط مختصر يخفي الوجهة النهائية','--warn','short');
  if(/[a-z][01][a-z]/.test(host.replace(/\d{2,}/g,''))) add(14,'تشابه بصري مع اسم معروف (استبدال حرف برقم)',0,'look');
  const kws=['login','verify','secure','update','account','bank','wallet','gift','prize','otp','confirm','signin','pay','claim','reward'];
  const kh=kws.filter(k=>full.includes(k)); if(kh.length) add(Math.min(18,kh.length*6),'كلمات حساسة في الرابط: '+kh.slice(0,3).join('، '),'--warn','kw');
  if(u.length>90) add(5,'رابط طويل بشكل غير معتاد','--warn','long');
  // twin behaviors
  out.twin.push(['c','TWIN-7A31 spawned · mobile UA · geo=Riyadh(fake)']);
  if(isShort){ out.twin.push(['w','301 → promo-gift-sa.click']); out.twin.push(['w','302 → reward-claim.xyz/pay']); }
  out.twin.push(['', 'GET '+host+p.pathname]);
  if(/login|verify|account|signin|update|secure/.test(full)) out.twin.push(['t','FORM detected: username + password fields']);
  if(/otp|pay|claim|reward|gift|prize/.test(full)||isShort) out.twin.push(['t','FORM detected: card number + OTP field']);
  if(/apk|exe|download|\.zip/.test(full)) out.twin.push(['t','auto-download attempt: payload.apk']);
  if(out.score>=40) out.twin.push(['t','script: fingerprint + keystroke capture']);
  if(out.score<20) out.twin.push(['g','page rendered · no credential forms · no payload']);
  out.score=Math.min(100,out.score);
  return out;
}
function hashHex(s){let h=2166136261;for(let i=0;i<s.length;i++){h^=s.charCodeAt(i);h=Math.imul(h,16777619)}return (h>>>0).toString(16).toUpperCase().padStart(8,'0')}

/* ---------- Run ---------- */
const stages=[...document.querySelectorAll('.stage')];
const logEl=$('#log'), consoleEl=$('#console');
let runId=0;
const wait=ms=>new Promise(r=>setTimeout(r,ms));
function logLine(cls,txt){const d=document.createElement('div'); if(cls) d.className=cls; d.textContent='› '+txt; logEl.appendChild(d); logEl.scrollTop=logEl.scrollHeight;}
async function fill(st,ms,id){ st.classList.add('on'); const bar=st.querySelector('i'); const steps=12; for(let i=1;i<=steps;i++){ if(id!==runId) return; bar.style.setProperty('--p',(i/steps*100)+'%'); await wait(ms/steps);} st.classList.remove('on'); st.classList.add('done'); }

async function run(animate){
  const id=++runId;
  const msg=$('#msg').value, url=$('#url').value;
  const U=analyzeUrl(url), I=analyzeMsg(msg);
  let risk=Math.round(Math.min(100, U.score*0.62 + I.score*0.48));
  if(!url.trim()&&!msg.trim()) risk=0;
  const tier = risk>=60?'bad':risk>=30?'mid':'ok';
  stages.forEach(s=>{s.classList.remove('on','done'); s.querySelector('i').style.setProperty('--p','0%');});
  logEl.innerHTML=''; setResult(null);
  const fast = !animate || reduce;
  if(!fast) consoleEl.classList.add('scanning');
  // stage 1
  for(const [c,t] of U.twin){ if(id!==runId) return; logLine(c,t); if(!fast) await wait(260); }
  if(fast) stages[0].querySelector('i').style.setProperty('--p','100%'), stages[0].classList.add('done'); else await fill(stages[0],500,id);
  if(id!==runId) return;
  // stage 2
  const top=Object.entries(I.res).filter(([k,v])=>v>0).sort((a,b)=>b[1]-a[1]);
  logLine('c','intent model: '+(top.length? top.map(([k,v])=>k+'='+v.toFixed(2)).join(' ') : 'no manipulation cues'));
  if(fast) stages[1].querySelector('i').style.setProperty('--p','100%'), stages[1].classList.add('done'); else await fill(stages[1],900,id);
  if(id!==runId) return;
  // stage 3
  const serumId='SRM-'+hashHex(url+msg);
  if(tier==='bad') logLine('t','verdict=BLOCK · serum '+serumId+' broadcast to mesh');
  else if(tier==='mid') logLine('w','verdict=WARN · pattern queued for mesh review');
  else logLine('g','verdict=ALLOW · no serum required');
  if(fast) stages[2].querySelector('i').style.setProperty('--p','100%'), stages[2].classList.add('done'); else await fill(stages[2],600,id);
  consoleEl.classList.remove('scanning');
  setResult({risk,tier,U,I,top,serumId});
  if(tier==='bad' && animate && window.__meshInfect) window.__meshInfect(null, serumId);
}
function setResult(r){
  const g=$('#gauge'), pill=$('#pill'), title=$('#vtitle'), f=$('#findings'), serum=$('#serum');
  if(!r){ g.style.setProperty('--off',327); $('#score').textContent='…'; pill.textContent='جارٍ الفحص'; pill.style.setProperty('--v-col','var(--muted)'); pill.style.setProperty('--v-soft','var(--panel-2)'); title.textContent='التوأم يقتحم الرابط'; f.innerHTML=''; serum.hidden=true; return; }
  const map={bad:['--threat','--threat-soft','خطر · محظور','فخ احتيالي مؤكد'],mid:['--warn','--warn-soft','مشبوه','تعامل بحذر شديد'],ok:['--safe','--safe-soft','آمن نسبيًا','لم يُرصد سلوك عدائي']}[r.tier];
  g.style.setProperty('--v-col','var('+map[0]+')'); g.style.setProperty('--off', 327 - 327*r.risk/100);
  pill.style.setProperty('--v-col','var('+map[0]+')'); pill.style.setProperty('--v-soft','var('+map[1]+')'); pill.textContent=map[2]; title.textContent=map[3];
  // count up
  const el=$('#score'); const t0=performance.now(); const dur=reduce?0:900;
  (function tick(t){ const k=dur?Math.min(1,(t-t0)/dur):1; el.textContent=Math.round(r.risk*k); if(k<1) requestAnimationFrame(tick); })(t0);
  f.innerHTML='';
  const items=[...r.U.find];
  r.top.slice(0,3).forEach(([k,v])=>items.push(['أسلوب استدراج: '+TACTICS[k].label+' ('+Math.round(v*100)+'%)', TACTICS[k].col]));
  if(!items.length) items.push(['لا توجد مؤشرات خطر في الرابط أو الرسالة','--safe']);
  items.slice(0,6).forEach(([t,c])=>{ const li=document.createElement('li'); li.style.setProperty('--c','var('+c+')'); li.textContent=t; f.appendChild(li); });
  if(r.tier==='bad'){ serum.hidden=false; serum.innerHTML='<span>مصل رقمي مُولَّد:</span><span class="mono">'+r.serumId+'</span><span>· وُزّع على شبكة المناعة</span>'; }
  else serum.hidden=true;
}
$('#run').addEventListener('click',()=>run(true));
$('#msg').value=SAMPLES[0].msg; $('#url').value=SAMPLES[0].url;
run(false);

/* ---------- Twin hops loop ---------- */
const hops=[...document.querySelectorAll('#hops .hop')];
let hi=0;
function hopTick(){ hops.forEach((h,i)=>h.classList.toggle('lit', i<=hi)); hi=(hi+1)%(hops.length+2); }
if(reduce) hops.forEach(h=>h.classList.add('lit')); else { hops.forEach(h=>h.classList.add('lit')); setTimeout(()=>{hi=0; setInterval(hopTick,1100);},2500); }

/* ---------- Immune mesh ---------- */
const cv=$('#meshCanvas'), ctx=cv.getContext('2d');
let W=0,H=0,nodes=[],edges=[],adj=[],dpr=1, waves=[];
let threats=0, immunized=0;
function build(){
  const r=cv.getBoundingClientRect(); dpr=Math.min(2,devicePixelRatio||1); W=r.width; H=r.height; cv.width=W*dpr; cv.height=H*dpr; ctx.setTransform(dpr,0,0,dpr,0,0);
  const n=Math.max(28,Math.min(70,Math.round(W*H/5200)));
  let seed=7; const rnd=()=>{seed=(seed*16807)%2147483647;return seed/2147483647};
  nodes=[]; for(let i=0;i<n;i++) nodes.push({x:18+rnd()*(W-36), y:18+rnd()*(H-36), ox:0, oy:0, ph:rnd()*6.28, st:0, t:0});
  nodes.forEach(nd=>{nd.ox=nd.x;nd.oy=nd.y});
  edges=[]; adj=nodes.map(()=>[]);
  nodes.forEach((a,i)=>{ const d=nodes.map((b,j)=>[j,Math.hypot(a.x-b.x,a.y-b.y)]).filter(([j])=>j!==i).sort((x,y)=>x[1]-y[1]).slice(0,3);
    d.forEach(([j])=>{ if(!adj[i].includes(j)){adj[i].push(j);adj[j].push(i);edges.push([i,j]);} }); });
}
function infect(idx, serumId){
  if(idx==null) idx=Math.floor(Math.random()*nodes.length);
  threats++; $('#mThreats').textContent=threats;
  const now=performance.now();
  // BFS distances
  const dist=new Array(nodes.length).fill(-1); dist[idx]=0; const q=[idx];
  while(q.length){const c=q.shift(); adj[c].forEach(j=>{if(dist[j]<0){dist[j]=dist[c]+1;q.push(j)}})}
  const maxd=Math.max(...dist);
  nodes.forEach((nd,i)=>{ nd.st = i===idx ? 2 : 0; nd.t = now + (i===idx?0:600+dist[i]*140); });
  waves.push({x:nodes[idx].x,y:nodes[idx].y,t:now});
  const ms= 600+maxd*140; const n=nodes.length;
  setTimeout(()=>{ immunized+=n-1; $('#mImm').textContent=immunized.toLocaleString('en'); $('#mMs').textContent=Math.round(ms*0.52)+' ms';
    addFeed(serumId||('SRM-'+hashHex(String(now))), n-1); }, reduce?0:ms);
}
window.__meshInfect=infect;
const feed=$('#feed');
const KINDS=['تصيّد بنكي','جائزة وهمية','شحنة مزيّفة','انتحال جهة رسمية','سرقة رمز تحقق'];
function addFeed(id,n){
  const li=document.createElement('li'); const d=new Date();
  li.innerHTML='<span class="mono">'+id+'</span><span>'+KINDS[Math.floor(Math.random()*KINDS.length)]+' · حُصّنت '+n+' عقدة</span><time>'+d.toTimeString().slice(0,8)+'</time>';
  feed.prepend(li); while(feed.children.length>5) feed.lastChild.remove();
}
function draw(){
  const now=performance.now();
  const cCy=css('--cyan'), cSt=css('--steel-2'), cTh=css('--threat'), cLine=css('--line');
  ctx.clearRect(0,0,W,H);
  nodes.forEach(nd=>{ if(!reduce){ nd.x=nd.ox+Math.sin(now/1600+nd.ph)*3; nd.y=nd.oy+Math.cos(now/1900+nd.ph)*3; }
    if(nd.st===0 && nd.t && now>=nd.t) nd.st=1; if(nd.st===2 && now-nd.t>2400){nd.st=1;} });
  edges.forEach(([i,j])=>{ const a=nodes[i],b=nodes[j]; const lit=(a.st===1&&now-a.t<900)||(b.st===1&&now-b.t<900);
    ctx.strokeStyle= lit?cCy:cLine; ctx.globalAlpha= lit?0.9:0.9; ctx.lineWidth= lit?1.6:1; ctx.beginPath(); ctx.moveTo(a.x,a.y); ctx.lineTo(b.x,b.y); ctx.stroke(); });
  ctx.globalAlpha=1;
  waves=waves.filter(w=>now-w.t<1800);
  waves.forEach(w=>{ const k=(now-w.t)/1800; ctx.strokeStyle=cCy; ctx.globalAlpha=(1-k)*0.6; ctx.lineWidth=2; ctx.beginPath(); ctx.arc(w.x,w.y,k*Math.max(W,H)*0.7,0,6.283); ctx.stroke(); });
  ctx.globalAlpha=1;
  nodes.forEach(nd=>{
    let col=cSt, r=3.2;
    if(nd.st===2){ col=cTh; r=6+Math.sin(now/120)*1.5; ctx.fillStyle=cTh; ctx.globalAlpha=.18; ctx.beginPath(); ctx.arc(nd.x,nd.y,r*2.6,0,6.283); ctx.fill(); ctx.globalAlpha=1; }
    else if(nd.st===1){ col=cCy; const age=now-nd.t; r= age<500? 3.2+ (1-age/500)*4 : 3.6;
      ctx.strokeStyle=cCy; ctx.globalAlpha=.55; ctx.lineWidth=1.2; ctx.beginPath(); ctx.arc(nd.x,nd.y,r+3.5,0,6.283); ctx.stroke(); ctx.globalAlpha=1; }
    ctx.fillStyle=col; ctx.beginPath(); ctx.arc(nd.x,nd.y,r,0,6.283); ctx.fill();
  });
  if(!reduce) requestAnimationFrame(draw);
}
cv.addEventListener('click',e=>{ const r=cv.getBoundingClientRect(); const x=e.clientX-r.left, y=e.clientY-r.top; let best=0,bd=1e9; nodes.forEach((n,i)=>{const d=Math.hypot(n.x-x,n.y-y); if(d<bd){bd=d;best=i}}); infect(best); if(reduce) draw(performance.now()); });
build();
let rT; addEventListener('resize',()=>{clearTimeout(rT); rT=setTimeout(()=>{build(); if(reduce) draw(performance.now());},150)});
// seed feed so it's populated at rest
['SRM-4E91C0A2','SRM-B07D13F5','SRM-91AA6C2E'].forEach(id=>addFeed(id, nodes.length-1));
threats=3; immunized=(nodes.length-1)*3; $('#mThreats').textContent=threats; $('#mImm').textContent=immunized; $('#mMs').textContent='612 ms';
nodes.forEach(n=>{n.st=1; n.t=1});
requestAnimationFrame(draw);
if(!reduce){ setTimeout(()=>infect(null),1800); setInterval(()=>infect(null),7000); }

/* =================== Interactive explainers =================== */
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
const TCLS={urg:'k-urg',auth:'k-auth',fear:'k-fear',rew:'k-rew',act:'k-act'};
function markText(text){
  const spans=[]; const low=text.toLowerCase();
  for(const k in TACTICS){ TACTICS[k].words.forEach(w=>{ const lw=w.toLowerCase(); let i=low.indexOf(lw); while(i>=0){ spans.push([i,i+lw.length,k]); i=low.indexOf(lw,i+lw.length);} }); }
  spans.sort((a,b)=>a[0]-b[0]||(b[1]-b[0])-(a[1]-a[0]));
  let out='',pos=0; spans.forEach(([s,e,k])=>{ if(s<pos) return; out+=esc(text.slice(pos,s))+'<mark class="'+TCLS[k]+'">'+esc(text.slice(s,e))+'</mark>'; pos=e; });
  return out+esc(text.slice(pos));
}

/* ---------- intent playground ---------- */
const IP_SAMPLES=[
  ['تخويف وإلحاح','تم تعليق حسابك لأسباب أمنية. يرجى تحديث بياناتك خلال 24 ساعة وإلا سيتم إيقاف الحساب.'],
  ['إغراء','مبروك! ربحت جائزة قيمتها 5000 ريال. اضغط الآن لاستلام هديتك، العرض ينتهي اليوم فقط.'],
  ['رسالة عادية','مرحبًا، أرسلت لك ملخص اجتماع الأمس. نلتقي يوم الأحد إن شاء الله.']
];
const ipText=$('#ipText'), ipWrap=$('#ipSamples');
IP_SAMPLES.forEach(([n,t],i)=>{ const b=document.createElement('button'); b.type='button'; b.className='chip'; b.textContent=n; b.id='ip-s'+i;
  b.onclick=()=>{ ipText.value=t; [...ipWrap.children].forEach(c=>c.setAttribute('aria-pressed','false')); b.setAttribute('aria-pressed','true'); updIntent(); }; ipWrap.appendChild(b); });
function updIntent(){
  const t=ipText.value; const I=analyzeMsg(t);
  $('#ipPreview').innerHTML= t.trim()? markText(t) : '<span class="note">اكتب رسالة لتظهر هنا مع تلوين عبارات الضغط النفسي.</span>';
  const bars=$('#ipBars'); bars.innerHTML='';
  for(const k in TACTICS){ const v=I.res[k]; const d=document.createElement('div'); d.className='tac';
    d.innerHTML='<span>'+TACTICS[k].label+'</span><div class="tb"><i style="--w:'+Math.round(v*100)+'%;--c:var('+TACTICS[k].col+');animation:none;transition:width .4s"></i></div><span class="v">'+v.toFixed(2)+'</span>'; bars.appendChild(d); }
  const sc=$('#ipScore'); sc.textContent=I.score;
  const col=I.score>=60?'--threat':I.score>=30?'--warn':'--safe'; sc.style.setProperty('--v','var('+col+')');
  $('#ipVerdict').textContent= I.score>=60?'نية استدراج عالية: الرسالة تعتمد على الضغط النفسي بوضوح.' : I.score>=30?'مؤشرات ضغط متوسطة: تعامل معها بحذر.' : 'لا توجد مؤشرات ضغط نفسي واضحة.';
}
ipText.addEventListener('input',updIntent);
ipText.value=IP_SAMPLES[0][1]; ipWrap.children[0].setAttribute('aria-pressed','true'); updIntent();

/* ---------- mesh spread (layer by layer) ---------- */
const BN=[[60,50],[160,30],[270,45],[370,60],[90,150],[200,120],[320,140],[150,210],[290,210]];
const BE=[[0,1],[1,2],[2,3],[0,4],[1,5],[2,5],[3,6],[4,5],[5,6],[4,7],[5,7],[6,8],[7,8],[5,8]];
const BADJ=BN.map(()=>[]); BE.forEach(([a,b])=>{BADJ[a].push(b);BADJ[b].push(a)});
const svg=$('#bfsSvg'); const NS='http://www.w3.org/2000/svg';
const lineEls=BE.map(([a,b])=>{const l=document.createElementNS(NS,'line'); l.setAttribute('x1',BN[a][0]);l.setAttribute('y1',BN[a][1]);l.setAttribute('x2',BN[b][0]);l.setAttribute('y2',BN[b][1]); svg.appendChild(l); return l;});
const gEls=BN.map(([x,y],i)=>{const g=document.createElementNS(NS,'g'); g.innerHTML='<circle cx="'+x+'" cy="'+y+'" r="13"></circle><text x="'+x+'" y="'+y+'">'+(i+1)+'</text><text class="d" x="'+x+'" y="'+(y+25)+'"></text>'; g.addEventListener('click',()=>bReset(i)); svg.appendChild(g); return g;});
let B; let bTimer=null;
function bReset(origin){
  clearInterval(bTimer); bTimer=null; origin = origin==null?(B?B.origin:4):origin;
  B={origin,queue:[origin],depth:{[origin]:0},done:[],cur:null,from:{}};
  bDraw('الجهاز رقم '+(origin+1)+' اكتشف التهديد. هو أول جهاز في الطابور، وسيبدأ منه انتشار المصل.');
}
function bStep(){
  if(!B.queue.length){ bDraw('اكتمل التحصين: كل الأجهزة استلمت المصل.'); return false; }
  const n=B.queue.shift(); B.cur=n; B.done.push(n); const added=[];
  BADJ[n].forEach(p=>{ if(B.depth[p]===undefined){ B.depth[p]=B.depth[n]+1; B.from[p]=n; B.queue.push(p); added.push(p+1);} });
  bDraw('الجهاز '+(n+1)+' ثبّت المصل وحظر التهديد محليًا'+(added.length?'، ثم أرسله إلى جيرانه: '+added.join('، ')+'.':'. كل جيرانه وصلهم المصل مسبقًا.'));
  return true;
}
function bDraw(msg){
  gEls.forEach((g,i)=>{ g.setAttribute('class', i===B.origin?'origin': i===B.cur?'cur': B.done.includes(i)?'done': B.queue.includes(i)?'q':'');
    g.querySelector('.d').textContent= B.depth[i]!==undefined?'طبقة '+B.depth[i]:''; });
  lineEls.forEach((l,k)=>{ const [a,b]=BE[k]; l.classList.toggle('on', B.from[a]===b||B.from[b]===a); });
  const q=$('#bfsQueue'); q.innerHTML= B.queue.length? B.queue.map(i=>'<span>'+(i+1)+'</span>').join('') : '<em>الطابور فارغ</em>';
  const maxd=Math.max(...Object.values(B.depth)); const hop=+$('#hopMs').value;
  $('#bfsDone').textContent=B.done.length+'/'+BN.length; $('#bfsDepth').textContent=maxd; $('#bfsTime').textContent=(maxd*hop)+' ms';
  if(msg) $('#bfsExplain').textContent=msg;
}
$('#bfsStep').onclick=()=>{clearInterval(bTimer);bTimer=null;bStep();};
$('#bfsReset').onclick=()=>bReset();
$('#bfsRun').onclick=()=>{ clearInterval(bTimer); if(!B.queue.length) bReset(); bTimer=setInterval(()=>{ if(!bStep()){clearInterval(bTimer);bTimer=null;} }, reduce?0:Math.max(250,+$('#hopMs').value*4)); };
$('#hopMs').addEventListener('input',()=>{ $('#hopVal').textContent=$('#hopMs').value+' ms'; bDraw(); });
bReset(4);

/* ---------- team ---------- */
const TEAM=[['رفيف عايش العلوني','مديرة التقنية'],['أسيل مازن أبو النصر','مديرة التسويق'],['أسيل خالد الشلالي','مديرة المشروع']];
const grid=$('#teamGrid');
TEAM.forEach(([n,role])=>{ const p=n.split(/\s+/); const ini=p[0][0]+' '+p[p.length-1].replace(/^ال/,'')[0];
  const card=document.createElement('div'); card.className='member rimmed';
  card.innerHTML='<div class="bevel"><div class="avatar">'+esc(ini)+'</div><div class="nm">'+esc(n)+'</div><div class="rl">'+esc(role)+'</div></div>';
  grid.appendChild(card); });

})();
