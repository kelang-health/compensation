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
  const lock=LockService.getScriptLock(); lock.waitLock(30000);
  try {
    const c=rows_('คำขอเบิก').find(x=>String(x.claim_id)===String(id));
    if(!c) throw Error('ไม่พบคำขอ');
    const p=rows_('บุคลากร').find(x=>String(x.person_id)===String(c.person_id));
    if(!p) throw Error('ไม่พบข้อมูลบุคลากร');
    fillForm1_(sheet_('Print_แบบ1'),c,p);
    SpreadsheetApp.flush();
    const pdf=exportPdf_(sheet_('Print_แบบ1'),58,'แบบคำขอ_'+safeName_(id)+'.pdf');
    audit_(u.name,'PRINT_PDF','CLAIM',id);
    return pdf;
  } finally { lock.releaseLock(); }
}

function printForm11_(u,id) {
  require_(u,['ADMIN','OFFICER','APPROVER']);
  const lock=LockService.getScriptLock(); lock.waitLock(30000);
  try {
    const m=rows_('ฉ11รายเดือน').find(x=>String(x.monthly_id)===String(id));
    if(!m) throw Error('ไม่พบรายการ ฉ.11');
    const p=rows_('บุคลากร').find(x=>String(x.person_id)===String(m.person_id));
    if(!p) throw Error('ไม่พบข้อมูลบุคลากร');
    const h=rows_('ประวัติการปฏิบัติงาน').filter(x=>String(x.person_id)===String(m.person_id)).slice(0,6);
    fillForm11_(sheet_('Print_ฉ11'),m,p,h);
    SpreadsheetApp.flush();
    const pdf=exportPdf_(sheet_('Print_ฉ11'),27,'ฉ11_'+safeName_(id)+'.pdf');
    audit_(u.name,'PRINT_PDF','MONTHLY',id);
    return pdf;
  } finally { lock.releaseLock(); }
}

function fillForm1_(sh,c,p) {
  const name=[p['คำนำหน้า'],p['ชื่อ'],p['นามสกุล']].filter(Boolean).join(' ');
  const serviceDuration=duration_(c['วันที่เริ่มสิทธิ']||p['วันที่เริ่มรับราชการ'],c['วันที่สิ้นสุดสิทธิ']||new Date());
  sh.getRange('J4').setValue(p['หน่วยบริการปัจจุบัน']||'');
  sh.getRange('J5').setValue(thaiDate_(c['วันที่ยื่น']||new Date()));
  sh.getRange('A8').setValue('ข้าพเจ้า '+name+'  ตำแหน่ง '+v_(p.ตำแหน่ง));
  sh.getRange('A9').setValue('ระดับ '+v_(p.ระดับ)+'  อายุราชการ '+serviceDuration.years+' ปี  สังกัดสำนัก/กอง '+v_(p['สำนัก/กอง']));
  sh.getRange('A10').setValue('ปัจจุบันปฏิบัติงานในหน่วยบริการสาธารณสุข '+v_(p['หน่วยบริการปัจจุบัน']));
  sh.getRange('A11').setValue('หมู่ที่ '+v_(p['หมู่ที่'])+' ตำบล '+v_(p.ตำบล)+' อำเภอ '+v_(p.อำเภอ)+' จังหวัด '+v_(p.จังหวัด));
  sh.getRange('A12').setValue('ตั้งแต่วันที่ '+thaiDate_(c['วันที่เริ่มสิทธิ'])+' ถึงวันที่ '+thaiDate_(c['วันที่สิ้นสุดสิทธิ'])+' รวมระยะเวลา '+serviceDuration.years+' ปี '+serviceDuration.months+' เดือน '+serviceDuration.days+' วัน');
  sh.getRange('A13').setValue('ที่อยู่ปัจจุบัน บ้านเลขที่ '+v_(p['บ้านเลขที่'])+' หมู่ '+v_(p['หมู่ที่(ที่อยู่)'])+' ถนน '+v_(p.ถนน)+' ตำบล '+v_(p['ตำบล(ที่อยู่)'])+' อำเภอ '+v_(p['อำเภอ(ที่อยู่)'])+' จังหวัด '+v_(p['จังหวัด(ที่อยู่)'])+' '+v_(p['รหัสไปรษณีย์']));
  const licenses=['ใบอนุญาตประกอบโรคศิลปะ','ใบอนุญาตประกอบวิชาชีพเวชกรรม','ใบอนุญาตประกอบวิชาชีพทันตกรรม','ใบอนุญาตประกอบวิชาชีพเภสัชกรรม','ใบอนุญาตประกอบวิชาชีพการพยาบาลและการผดุงครรภ์','ใบอนุญาตผู้ประกอบวิชาชีพการแพทย์แผนไทย/ประยุกต์','เทคนิคการแพทย์','กายภาพบำบัด'];
  const lt=String(p['ประเภทใบอนุญาต']||'');
  sh.getRange('A15').setValue(mark_(lt,licenses[0])+' '+licenses[0]+'     '+mark_(lt,licenses[1])+' '+licenses[1]+'     '+mark_(lt,licenses[2])+' '+licenses[2]);
  sh.getRange('A16').setValue(mark_(lt,licenses[3])+' '+licenses[3]+'     '+mark_(lt,licenses[4])+' '+licenses[4]);
  sh.getRange('A17').setValue(mark_(lt,'แพทย์แผนไทย')+' '+licenses[5]+'     '+mark_(lt,licenses[6])+' '+licenses[6]+'     '+mark_(lt,licenses[7])+' '+licenses[7]);
  sh.getRange('A18').setValue((lt&&!licenses.some(x=>lt.indexOf(x)>=0)?'☒':'☐')+' ใบอนุญาตอื่น ๆ ระบุ '+v_(lt)+'     '+(!lt?'☒':'☐')+' ไม่มีใบอนุญาตประกอบวิชาชีพ');
  sh.getRange('A19').setValue('เลขที่ใบอนุญาต '+v_(p['เลขใบอนุญาต']));
  const cats=['ค่าตอบแทนในการปฏิบัติงานของเจ้าหน้าที่','ค่าตอบแทนการปฏิบัติงานในคลินิกพิเศษนอกเวลาราชการ','ค่าตอบแทนในการปฏิบัติงานเวรหรือผลัดบ่ายหรือผลัดดึกของพยาบาล','ค่าตอบแทนในการปฏิบัติงานชันสูตรพลิกศพ','ค่าตอบแทนพิเศษสำหรับแพทย์สาขาส่งเสริมพิเศษ','ค่าตอบแทนเงินเพิ่มพิเศษสำหรับแพทย์ ทันตแพทย์ และเภสัชกร ที่ปฏิบัติงานโดยไม่ทำเวชปฏิบัติส่วนตัว','ค่าตอบแทนในการปฏิบัติงานด้านการสร้างเสริมสุขภาพและเวชปฏิบัติครอบครัว','ค่าเบี้ยเลี้ยงเหมาจ่ายสำหรับเจ้าหน้าที่ที่ปฏิบัติงานในหน่วยบริการสาธารณสุข','ค่าตอบแทนอื่น ๆ'];
  cats.forEach((x,i)=>sh.getRange(22+i,1).setValue(mark_(String(c['ประเภทค่าตอบแทน']||''),x)+' ('+thaiNum_(i+1)+') '+x+(i===8?' ระบุ '+v_(c['ประเภทค่าตอบแทน']):'')));
  sh.getRange('A31').setValue('ระยะเวลาที่ขอรับ ตั้งแต่ '+thaiDate_(c['วันที่เริ่มสิทธิ'])+' ถึง '+thaiDate_(c['วันที่สิ้นสุดสิทธิ'])+' จำนวน '+v_(c['จำนวนเดือน'])+' เดือน');
  sh.getRange('A32').setValue('อัตราเดือนละ '+money_(c['อัตราต่อเดือน'])+' บาท × '+v_(c['จำนวนเดือน'])+' เดือน รวมเป็นเงิน '+money_(c['จำนวนเงิน'])+' บาท');
  sh.getRange('A33').setFormula('="จำนวนเงินตัวอักษร "&BAHTTEXT('+Number(c['จำนวนเงิน']||0)+')');
  sh.getRange('G39').setValue('('+name+')'); sh.getRange('G40').setValue('ตำแหน่ง '+v_(p.ตำแหน่ง));
}

function fillForm11_(sh,m,p,h) {
  const name=[p['คำนำหน้า'],p['ชื่อ'],p['นามสกุล']].filter(Boolean).join(' ');
  const end=m['วันที่สิ้นเดือน']||new Date();
  const first=h.length?h.map(x=>date_(x['วันที่เริ่ม'])).filter(Boolean).sort((a,b)=>a-b)[0]:date_(p['วันที่เริ่มรับราชการ']);
  const total=duration_(first,end);
  sh.getRange('A4').setValue('หน่วยบริการ '+v_(p['หน่วยบริการปัจจุบัน']));
  sh.getRange('A5').setValue('ประจำเดือน '+v_(m['เดือน'])+' พ.ศ. '+v_(m['ปีงบประมาณ']));
  sh.getRange('A7').setValue('ชื่อ '+v_(p['ชื่อ'])+'  นามสกุล '+v_(p['นามสกุล'])+'  ตำแหน่ง '+v_(p.ตำแหน่ง));
  sh.getRange('A8').setValue('ปัจจุบันปฏิบัติงานที่ '+v_(p['หน่วยบริการปัจจุบัน'])+'  จังหวัด '+v_(p.จังหวัด));
  sh.getRange('A9').setValue('ระดับ/กลุ่มพื้นที่ '+v_(p['กลุ่มพื้นที่'])+'  ระยะเวลาปฏิบัติงาน ณ หน่วยบริการ '+total.years+' ปี '+total.months+' เดือน');
  for(let i=0;i<6;i++){
    const r=13+i, x=h[i]||{};
    sh.getRange(r,2).setValue(v_(x['หน่วยบริการ'])); sh.getRange(r,6).setValue(v_(x.จังหวัด)); sh.getRange(r,8).setValue(v_(x['ระดับพื้นที่']));
    sh.getRange(r,9).setValue(thaiDate_(x['วันที่เริ่ม'])); sh.getRange(r,11).setValue(thaiDate_(x['วันที่สิ้นสุด']));
  }
  sh.getRange('A20').setValue('รวม '+total.years+' ปี '+total.months+' เดือน '+total.days+' วัน');
  sh.getRange('G25').setValue('('+name+')'); sh.getRange('G26').setValue('ตำแหน่ง '+v_(p.ตำแหน่ง)); sh.getRange('G27').setValue('วันที่ '+thaiDate_(new Date()));
}

function exportPdf_(sh,lastRow,fileName) {
  const ss=sh.getParent();
  const url='https://docs.google.com/spreadsheets/d/'+ss.getId()+'/export?format=pdf&gid='+sh.getSheetId()+'&size=A4&portrait=true&fitw=true&sheetnames=false&printtitle=false&pagenumbers=false&gridlines=false&fzr=false&top_margin=0.30&bottom_margin=0.30&left_margin=0.35&right_margin=0.35&r1=0&c1=0&r2='+lastRow+'&c2=11';
  const res=UrlFetchApp.fetch(url,{headers:{Authorization:'Bearer '+ScriptApp.getOAuthToken()},muteHttpExceptions:true});
  if(res.getResponseCode()!==200) throw Error('สร้าง PDF ไม่สำเร็จ HTTP '+res.getResponseCode());
  return {fileName:fileName,mimeType:'application/pdf',dataBase64:Utilities.base64Encode(res.getBlob().getBytes())};
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
