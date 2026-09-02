const PROP = PropertiesService.getScriptProperties();
const ITER = 10000;

function doPost(e) {
  try {
    const q = JSON.parse(e.postData.contents);
    if (q.gatewayKey !== PROP.getProperty('GAS_SHARED_SECRET')) throw Error('Unauthorized gateway');
    const p = q.path, m = q.method, b = q.payload || {};
    if (p === '/v1/auth/login') return out_(login_(b));
    const u = session_((q.authorization || '').replace('Bearer ', ''));
    if (p === '/v1/dashboard') return out_(dashboard_(u));
    if (p === '/v1/people' && m === 'GET') return out_(people_(u));
    if (p === '/v1/people' && m === 'POST') return out_(savePerson_(u, b));
    if (p === '/v1/claims' && m === 'GET') return out_({items: claims_(u)});
    if (p === '/v1/claims' && m === 'POST') return out_(createClaim_(u, b));
    if (/^\/v1\/claims\/[^/]+$/.test(p) && m === 'GET') return out_(claimDetail_(u, p.split('/')[3]));
    if (/^\/v1\/claims\/[^/]+\/approve$/.test(p) && m === 'POST') return out_(approve_(u, p.split('/')[3], b));
    if (/^\/v1\/prints\/form1\/[^/]+$/.test(p) && m === 'POST') return out_(printForm1_(u, p.split('/')[4]));
    if (/^\/v1\/prints\/form11\/[^/]+$/.test(p) && m === 'POST') return out_(printForm11_(u, p.split('/')[4]));
    if (p === '/v1/monthly' && m === 'GET') return out_({items: monthly_(u)});
    if (p === '/v1/monthly' && m === 'POST') return out_(createMonthly_(u, b));
    throw Error('Not found');
  } catch (x) {
    return out_({error: true, message: x.message});
  }
}

function login_(b) {
  const r = rows_('ผู้ใช้').find(x => String(x.username) === String(b.username) && x.สถานะ !== 'ระงับ');
  const valid = r && (r.password_salt ? safe_(r.password_hash, derive_(b.password, r.password_salt)) : safe_(r.password_hash, legacy_(b.password)));
  if (!valid) throw Error('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
  const t = Utilities.getUuid();
  CacheService.getScriptCache().put('session:' + t, JSON.stringify({id: r.user_id, role: r.role, name: r['ชื่อ-สกุล']}), 1800);
  audit_(r.username, 'LOGIN', 'USER', r.user_id);
  return {token: t, expiresIn: 1800, role: r.role, name: r['ชื่อ-สกุล']};
}

function session_(t) {
  const v = CacheService.getScriptCache().get('session:' + t);
  if (!v) throw Error('Session หมดอายุ กรุณาเข้าสู่ระบบใหม่');
  return JSON.parse(v);
}

function require_(u, roles) {
  if (!roles.includes(u.role)) throw Error('ไม่มีสิทธิ์ใช้งาน');
}

function dashboard_(u) {
  require_(u, ['ADMIN', 'OFFICER', 'APPROVER']);
  const c = claims_(u);
  return {user: u, counts: {claims: c.length, draft: c.filter(x => x.status === 'ร่าง').length, pending: c.filter(x => x.status === 'รออนุมัติ').length, approved: c.filter(x => x.status === 'อนุมัติ').length}, items: c};
}

function people_(u) {
  require_(u, ['ADMIN', 'OFFICER', 'APPROVER']);
  return {items: rows_('บุคลากร').filter(x => x.สถานะ !== 'ยกเลิก').map(x => ({id: x.person_id, name: [x['คำนำหน้า'], x['ชื่อ'], x['นามสกุล']].filter(Boolean).join(' '), position: x.ตำแหน่ง, level: x.ระดับ, unit: x['หน่วยบริการปัจจุบัน']}))};
}

function savePerson_(u, b) {
  require_(u, ['ADMIN', 'OFFICER']);
  if (!b.firstName || !b.lastName || !b.position) throw Error('กรอกชื่อ นามสกุล และตำแหน่ง');
  const id = 'P' + Utilities.getUuid().slice(0, 6).toUpperCase();
  sheet_('บุคลากร').appendRow([id,b.title||'',b.firstName,b.lastName,b.position,b.level||'',b.startDate||'',b.office||'',b.unit||'',b.village||'',b.subdistrict||'',b.district||'',b.province||'',b.address||'',b.addressVillage||'',b.road||'',b.addressSubdistrict||'',b.addressDistrict||'',b.addressProvince||'',b.postcode||'',b.areaGroup||'',b.licenseType||'',b.licenseNo||'','ใช้งาน']);
  if (b.unit && b.historyStart) {
    const hid = 'H' + Utilities.getUuid().slice(0, 7).toUpperCase();
    const d = duration_(b.historyStart, b.historyEnd || new Date());
    sheet_('ประวัติการปฏิบัติงาน').appendRow([hid,id,1,b.unit,b.historyProvince||b.province||'',b.historyLevel||b.areaGroup||'',b.historyStart,b.historyEnd||'',d.years,d.months,d.days,b.historyEnd?'':'ปัจจุบัน']);
  }
  audit_(u.name, 'CREATE', 'PERSON', id);
  return {ok: true, id: id};
}

function claims_(u) {
  require_(u, ['ADMIN', 'OFFICER', 'APPROVER']);
  return rows_('คำขอเบิก').map(x => ({claimId:x.claim_id,personId:x.person_id,fiscalYear:x['ปีงบประมาณ'],month:x['เดือน'],type:x['ประเภทค่าตอบแทน'],amount:Number(x['จำนวนเงิน']||0),status:x.สถานะ,createdAt:x['สร้างเมื่อ']}));
}

function createClaim_(u, b) {
  require_(u, ['ADMIN', 'OFFICER']);
  if (!b.personId || !b.fiscalYear || !b.month || !b.type || !b.rate || !b.months) throw Error('ข้อมูลคำขอไม่ครบ');
  const id = 'C' + b.fiscalYear + '-' + Utilities.getUuid().slice(0,5).toUpperCase();
  const total = Number(b.rate) * Number(b.months);
  sheet_('คำขอเบิก').appendRow([id,b.personId,b.fiscalYear,b.month,new Date(),b.type,b.rateId||'',b.startDate||'',b.endDate||'',Number(b.months),Number(b.rate),total,'ร่าง','','','','','','','','','','',b.note||'',new Date()]);
  audit_(u.name, 'CREATE', 'CLAIM', id);
  return {ok:true, claimId:id};
}

function claimDetail_(u, id) {
  require_(u, ['ADMIN', 'OFFICER', 'APPROVER']);
  const x = rows_('คำขอเบิก').find(r => String(r.claim_id) === String(id));
  if (!x) throw Error('ไม่พบคำขอ');
  const p = rows_('บุคลากร').find(r => String(r.person_id) === String(x.person_id)) || {};
  const history = rows_('ประวัติการปฏิบัติงาน').filter(r => String(r.person_id) === String(x.person_id));
  return {claim:x, person:p, history:history};
}

function approve_(u, id, b) {
  require_(u, ['ADMIN', 'APPROVER']);
  const sh=sheet_('คำขอเบิก'), a=sh.getDataRange().getValues(), r=a.findIndex(x=>String(x[0])===String(id));
  if (r<1) throw Error('ไม่พบคำขอ');
  const status=b.approved?'อนุมัติ':'ไม่อนุมัติ';
  sh.getRange(r+1,13).setValue(status); sh.getRange(r+1,22).setValue(status); sh.getRange(r+1,23).setValue(b.note||'');
  audit_(u.name,status,'CLAIM',id);
  return {ok:true};
}

function monthly_(u) {
  require_(u, ['ADMIN','OFFICER','APPROVER']);
  return rows_('ฉ11รายเดือน').map(x=>({id:x.monthly_id,personId:x.person_id,fiscalYear:x['ปีงบประมาณ'],month:x['เดือน'],monthNo:x.month_no,amount:Number(x['จำนวนเงิน']||0),status:x.สถานะ}));
}

function createMonthly_(u,b) {
  require_(u,['ADMIN','OFFICER']);
  if(!b.personId||!b.fiscalYear||!b.month||!b.rate) throw Error('ข้อมูล ฉ.11 ไม่ครบ');
  const id='M'+b.fiscalYear+'-'+String(b.monthNo||'00').padStart(2,'0')+'-'+b.personId+'-'+Utilities.getUuid().slice(0,4).toUpperCase();
  const start=b.startDate||'', end=b.endDate||'';
  sheet_('ฉ11รายเดือน').appendRow([id,b.personId,b.fiscalYear,b.month,Number(b.monthNo||0),start,end,b.rateId||'',Number(b.rate),Number(b.amount||b.rate),'ร่าง',b.note||'']);
  audit_(u.name,'CREATE','MONTHLY',id);
  return {ok:true,id:id};
}

function printForm1_(u,id) {
  require_(u,['ADMIN','OFFICER','APPROVER']);
  const c=rows_('คำขอเบิก').find(x=>String(x.claim_id)===String(id));
  if(!c) throw Error('ไม่พบคำขอ');
  const p=rows_('บุคลากร').find(x=>String(x.person_id)===String(c.person_id));
  if(!p) throw Error('ไม่พบข้อมูลบุคลากร');
  const pdf=makeSlidesPdf_(PROP.getProperty('PRINT_FORM1_SLIDES_ID'),form1Values_(c,p),'แบบคำขอ_'+safeName_(id)+'.pdf');
  audit_(u.name,'PRINT_PDF','CLAIM',id);
  return pdf;
}

function printForm11_(u,id) {
  require_(u,['ADMIN','OFFICER','APPROVER']);
  const m=rows_('ฉ11รายเดือน').find(x=>String(x.monthly_id)===String(id));
  if(!m) throw Error('ไม่พบรายการ ฉ.11');
  const p=rows_('บุคลากร').find(x=>String(x.person_id)===String(m.person_id));
  if(!p) throw Error('ไม่พบข้อมูลบุคลากร');
  const h=rows_('ประวัติการปฏิบัติงาน').filter(x=>String(x.person_id)===String(m.person_id)).slice(0,6);
  const pdf=makeSlidesPdf_(PROP.getProperty('PRINT_FORM11_SLIDES_ID'),form11Values_(m,p,h),'ฉ11_'+safeName_(id)+'.pdf');
  audit_(u.name,'PRINT_PDF','MONTHLY',id);
  return pdf;
}

function form1Values_(c,p) {
  const name=[p['คำนำหน้า'],p['ชื่อ'],p['นามสกุล']].filter(Boolean).join(' ');
  const serviceDuration=duration_(p['วันที่เริ่มรับราชการ'],c['วันที่ยื่น']||new Date());
  const claimDuration=duration_(c['วันที่เริ่มสิทธิ'],c['วันที่สิ้นสุดสิทธิ']);
  const filed=thaiParts_(c['วันที่ยื่น']||new Date());
  const values={
    '«1»':v_(p['หน่วยบริการปัจจุบัน']),'«2»':filed.day,'«3»':filed.month,'«4»':filed.year,
    '«5»':name,'«6»':v_(p.ตำแหน่ง),'«7»':v_(p.ระดับ),'«8»':String(serviceDuration.years),'«9»':v_(p['สำนัก/กอง']),
    '«10»':v_(p['หน่วยบริการปัจจุบัน']),'«11»':v_(p['หมู่ที่']),'«12»':v_(p.ตำบล),'«13»':v_(p.อำเภอ),'«14»':v_(p.จังหวัด),
    '«15»':thaiDate_(c['วันที่เริ่มสิทธิ']),'«16»':thaiDate_(c['วันที่สิ้นสุดสิทธิ']),'«17»':durationText_(claimDuration),
    '«18»':v_(p['บ้านเลขที่']),'«19»':v_(p.ถนน),'«20»':v_(p['ตำบล(ที่อยู่)']),'«21»':v_(p['อำเภอ(ที่อยู่)']),'«22»':v_(p['จังหวัด(ที่อยู่)']),'«23»':v_(p['รหัสไปรษณีย์']),
    '«24»':v_(p['เลขใบอนุญาต']),'«25»':'-',
    '«45»':thaiDate_(c['วันที่เริ่มสิทธิ']),'«46»':thaiDate_(c['วันที่สิ้นสุดสิทธิ']),'«47»':durationText_(claimDuration),
    '«48»':money_(c['อัตราต่อเดือน']),'«49»':money_(c['จำนวนเงิน']),'«50»':bahtText_(Number(c['จำนวนเงิน']||0)),
    '«5»':name,'«6»':v_(p.ตำแหน่ง)
  };
  const licenses=['ใบอนุญาตประกอบโรคศิลปะ','ใบอนุญาตประกอบวิชาชีพเวชกรรม','ใบอนุญาตประกอบวิชาชีพทันตกรรม','ใบอนุญาตประกอบวิชาชีพเภสัชกรรม','ใบอนุญาตประกอบวิชาชีพการพยาบาลและการผดุงครรภ์','ใบอนุญาตผู้ประกอบวิชาชีพการแพทย์แผนไทย/ประยุกต์','เทคนิคการแพทย์','กายภาพบำบัด'];
  const lt=String(p['ประเภทใบอนุญาต']||'');
  for(let i=1;i<=10;i++) values['«'+(25+i)+'»']='';
  const licenseIndex=licenses.findIndex(x=>lt.indexOf(x)>=0);
  if(!lt) values['«35»']='✓'; else if(licenseIndex>=0) values['«'+(26+licenseIndex)+'»']='✓'; else values['«34»']='✓';
  const cats=['ค่าตอบแทนในการปฏิบัติงานของเจ้าหน้าที่','คลินิกพิเศษนอกเวลาราชการ','เวรหรือผลัดบ่ายหรือผลัดดึก','ชันสูตรพลิกศพ','แพทย์สาขาส่งเสริมพิเศษ','เงินเพิ่มพิเศษสำหรับแพทย์','สร้างเสริมสุขภาพและเวชปฏิบัติครอบครัว','เบี้ยเลี้ยงเหมาจ่าย'];
  const type=String(c['ประเภทค่าตอบแทน']||''),catIndex=cats.findIndex(x=>type.indexOf(x)>=0);
  for(let i=1;i<=9;i++) values['«'+(35+i)+'»']='';
  values['«'+(36+(catIndex>=0?catIndex:8))+'»']='✓';
  const aps=approverMap_();
  values['«51»']=aps.supervisor.name; values['«52»']=aps.supervisor.position;
  values['«53»']=aps.head.name; values['«54»']=aps.head.position;
  values['«55»']=aps.check.name; values['«56»']=aps.pay.name;
  values['«57»']=aps.approver.name; values['«58»']=aps.approver.position;
  return values;
}

function form11Values_(m,p,h) {
  const name=[p['คำนำหน้า'],p['ชื่อ'],p['นามสกุล']].filter(Boolean).join(' ');
  const end=m['วันที่สิ้นเดือน']||new Date();
  const first=h.length?h.map(x=>date_(x['วันที่เริ่ม'])).filter(Boolean).sort((a,b)=>a-b)[0]:date_(p['วันที่เริ่มรับราชการ']);
  const total=duration_(first,end);
  const values={'«1»':v_(p['หน่วยบริการปัจจุบัน']),'«2»':v_(m['เดือน']),'«3»':v_(m['ปีงบประมาณ']),'«4»':v_(p['ชื่อ']),'«5»':v_(p['นามสกุล']),'«6»':v_(p.ตำแหน่ง),'«7»':v_(p['หน่วยบริการปัจจุบัน']),'«8»':v_(p.จังหวัด),'«9»':v_(p['กลุ่มพื้นที่']),'«10»':String(total.years),'«11»':String(total.months)};
  for(let i=0;i<6;i++){
    const x=h[i]||{},d=duration_(x['วันที่เริ่ม'],x['วันที่สิ้นสุด']||end),base=12+i*6;
    values['«'+base+'»']=x['หน่วยบริการ']||''; values['«'+(base+1)+'»']=x.จังหวัด||''; values['«'+(base+2)+'»']=x['ระดับพื้นที่']||'';
    values['«'+(base+3)+'»']=x['วันที่เริ่ม']?thaiDate_(x['วันที่เริ่ม']):''; values['«'+(base+4)+'»']=x['วันที่สิ้นสุด']?thaiDate_(x['วันที่สิ้นสุด']):''; values['«'+(base+5)+'»']=x['วันที่เริ่ม']?durationText_(d):'';
  }
  values['«48»']=String(total.years); values['«49»']=String(total.months); values['«50»']=String(total.days); values['«51»']=name;
  return values;
}

function makeSlidesPdf_(templateId,values,fileName) {
  if(!templateId) throw Error('ยังไม่ได้ตั้งค่าแม่แบบพิมพ์ กรุณารัน setupOriginalPrintTemplatesOnce');
  let temp;
  try {
    temp=DriveApp.getFileById(templateId).makeCopy('_TEMP_PRINT_'+Utilities.getUuid());
    const deck=SlidesApp.openById(temp.getId());
    Object.keys(values).forEach(k=>deck.replaceAllText(k,String(values[k]===undefined?'':values[k])));
    deck.saveAndClose();
    const url='https://docs.google.com/presentation/d/'+temp.getId()+'/export/pdf';
    const res=UrlFetchApp.fetch(url,{headers:{Authorization:'Bearer '+ScriptApp.getOAuthToken()},muteHttpExceptions:true});
    if(res.getResponseCode()!==200) throw Error('สร้าง PDF ไม่สำเร็จ HTTP '+res.getResponseCode());
    return {fileName:fileName,mimeType:'application/pdf',dataBase64:Utilities.base64Encode(res.getBlob().getBytes())};
  } finally { if(temp) temp.setTrashed(true); }
}

function setupOriginalPrintTemplatesOnce() {
  if(typeof Drive==='undefined'||!Drive.Files) throw Error('กรุณาเปิด Advanced Google Service: Drive API ก่อน');
  const sources={form1:'1iMx0JeKsletEOlOZYxe4WpYvM0neGm3S',form11:'1ASY2oevEAhY2MuMJvdo7rUwycFKkxpnu'};
  const create=(id,name)=>Drive.Files.create({name:name,mimeType:'application/vnd.google-apps.presentation'},DriveApp.getFileById(id).getBlob());
  const f1=create(sources.form1,'Print_แบบ1_แม่แบบต้นฉบับ_PDF');
  const f11=create(sources.form11,'Print_ฉ11_แม่แบบต้นฉบับ_PDF');
  PROP.setProperties({PRINT_FORM1_SLIDES_ID:f1.id,PRINT_FORM11_SLIDES_ID:f11.id});
  return {form1:f1.id,form11:f11.id};
}

function approverMap_(){
  const a=rows_('ผู้อนุมัติ').filter(x=>x.สถานะ!=='ยกเลิก');
  const find=(terms)=>{const x=a.find(r=>terms.some(t=>String(r.บทบาท||'').indexOf(t)>=0))||{};return {name:x['ชื่อ-นามสกุล']||'',position:x.ตำแหน่ง||''}};
  return {supervisor:find(['ผู้บังคับบัญชาชั้นต้น']),head:find(['หัวหน้าหน่วย']),check:find(['พิจารณาตรวจ']),pay:find(['พิจารณาจ่าย']),approver:find(['ผู้อนุมัติ','ผู้บริหารท้องถิ่น'])};
}

function bahtText_(n){
  n=Math.round(Number(n||0)*100)/100; const parts=n.toFixed(2).split('.');
  const main=readThaiNumber_(parts[0])+'บาท'; const sat=Number(parts[1]);
  return main+(sat?readThaiNumber_(String(sat))+'สตางค์':'ถ้วน');
}
function readThaiNumber_(s){
  s=String(s).replace(/^0+/,'')||'0'; if(s==='0')return 'ศูนย์';
  if(s.length>6){const cut=s.length-6;return readThaiNumber_(s.slice(0,cut))+'ล้าน'+readThaiNumber_(s.slice(cut));}
  const num=['ศูนย์','หนึ่ง','สอง','สาม','สี่','ห้า','หก','เจ็ด','แปด','เก้า'],unit=['','สิบ','ร้อย','พัน','หมื่น','แสน'];let out='';
  for(let i=0;i<s.length;i++){const d=Number(s[i]),pos=s.length-i-1;if(!d)continue;if(pos===1&&d===1)out+='สิบ';else if(pos===1&&d===2)out+='ยี่สิบ';else if(pos===0&&d===1&&s.length>1)out+='เอ็ด';else out+=num[d]+unit[pos];}return out;
}

function rows_(n){const a=sheet_(n).getDataRange().getValues(),h=a.shift();return a.map(r=>Object.fromEntries(h.map((x,i)=>[x,r[i]])))}
function sheet_(n){const x=SpreadsheetApp.openById(PROP.getProperty('SPREADSHEET_ID')).getSheetByName(n);if(!x)throw Error('ไม่พบชีต '+n);return x}
function setPassword(username,password){if(String(password).length<12)throw Error('รหัสผ่านต้องอย่างน้อย 12 ตัวอักษร');const sh=sheet_('ผู้ใช้'),a=sh.getDataRange().getValues(),r=a.findIndex(x=>String(x[1])===String(username));if(r<1)throw Error('ไม่พบผู้ใช้');sh.getRange(1,8).setValue('password_salt');const salt=Utilities.getUuid();sh.getRange(r+1,3).setValue(derive_(password,salt));sh.getRange(r+1,8).setValue(salt);audit_(username,'RESET_PASSWORD','USER',a[r][0])}
function derive_(password,salt){let value=salt+'|'+password;for(let i=0;i<ITER;i++)value=Utilities.base64Encode(Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,value,Utilities.Charset.UTF_8));return value}
function legacy_(v){return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,v,Utilities.Charset.UTF_8).map(x=>('0'+(x&255).toString(16)).slice(-2)).join('')}
function safe_(a,b){if(!a||!b||a.length!==b.length)return false;let n=0;for(let i=0;i<a.length;i++)n|=a.charCodeAt(i)^b.charCodeAt(i);return n===0}
function audit_(u,a,e,id){sheet_('AuditLog').appendRow([new Date(),u,a,e,id,''])}
function out_(x){return ContentService.createTextOutput(JSON.stringify(x)).setMimeType(ContentService.MimeType.JSON)}
function v_(x){return x===null||x===undefined||x===''?'-':String(x)}
function money_(x){return Number(x||0).toLocaleString('th-TH',{minimumFractionDigits:0,maximumFractionDigits:2})}
function safeName_(x){return String(x).replace(/[^A-Za-z0-9ก-๙_-]/g,'_')}
function mark_(actual,label){return String(actual||'').toLowerCase().indexOf(String(label).toLowerCase())>=0?'☒':'☐'}
function thaiNum_(n){return String(n).replace(/[0-9]/g,d=>'๐๑๒๓๔๕๖๗๘๙'[Number(d)])}
function date_(x){if(!x)return null;const d=x instanceof Date?x:new Date(x);return isNaN(d.getTime())?null:d}
function thaiDate_(x){const d=date_(x);if(!d)return '-';const m=['มกราคม','กุมภาพันธ์','มีนาคม','เมษายน','พฤษภาคม','มิถุนายน','กรกฎาคม','สิงหาคม','กันยายน','ตุลาคม','พฤศจิกายน','ธันวาคม'];return d.getDate()+' '+m[d.getMonth()]+' '+(d.getFullYear()+543)}
function duration_(a,b){const s=date_(a),e=date_(b);if(!s||!e||e<s)return {years:0,months:0,days:0};let y=e.getFullYear()-s.getFullYear(),m=e.getMonth()-s.getMonth(),d=e.getDate()-s.getDate();if(d<0){m--;d+=new Date(e.getFullYear(),e.getMonth(),0).getDate()}if(m<0){y--;m+=12}return {years:Math.max(0,y),months:Math.max(0,m),days:Math.max(0,d)}}

function resetAdminPasswordFromPropertyOnce(){
  const password=PROP.getProperty('TEMP_ADMIN_PASSWORD');
  if(!password) throw Error('กรุณาตั้ง Script Property ชื่อ TEMP_ADMIN_PASSWORD ก่อน');
  setPassword('admin',password);
  PROP.deleteProperty('TEMP_ADMIN_PASSWORD');
}
