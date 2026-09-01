const PROP=PropertiesService.getScriptProperties();
function doGet(e){return route_(e)}
function doPost(e){return route_(e)}
function route_(e){try{
  if(String(e.parameter.key||'')!==PROP.getProperty('GAS_SHARED_SECRET')) throw Error('Unauthorized gateway');
  const path=e.parameter.path||'/v1/claims';
  if(path==='/v1/auth/login') return out_(login_(JSON.parse(e.postData.contents)));
  const user=session_(e.parameter.token||'');
  if(path==='/v1/claims') return out_({items:claims_(user)});
  throw Error('Not found');
}catch(err){return out_({message:err.message,error:true})}}
function login_(b){const r=sheet_('ผู้ใช้').getDataRange().getValues().slice(1).find(x=>String(x[1])===String(b.username)&&String(x[2])===hash_(b.password)&&x[5]!=='ระงับ');if(!r)throw Error('ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');const token=Utilities.getUuid();CacheService.getScriptCache().put('session:'+token,JSON.stringify({id:r[0],role:r[4],name:r[3]}),1800);audit_(r[1],'LOGIN','USER',r[0]);return {token:token,expiresIn:1800,role:r[4]}}
function session_(token){const x=CacheService.getScriptCache().get('session:'+token);if(!x)throw Error('Session หมดอายุ');return JSON.parse(x)}
function claims_(user){const a=sheet_('คำขอเบิก').getDataRange().getValues();return a.slice(1).map(r=>({claimId:r[0],fiscalYear:r[1],month:r[2],amount:r[6],status:r[7]}))}
function sheet_(n){return SpreadsheetApp.openById(PROP.getProperty('SPREADSHEET_ID')).getSheetByName(n)}
function hash_(v){return Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256,v,Utilities.Charset.UTF_8).map(x=>('0'+(x&255).toString(16)).slice(-2)).join('')}
function audit_(u,a,e,id){sheet_('AuditLog').appendRow([new Date(),u,a,e,id,''])}
function out_(x){return ContentService.createTextOutput(JSON.stringify(x)).setMimeType(ContentService.MimeType.JSON)}