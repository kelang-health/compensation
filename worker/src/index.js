export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    if (!env.ALLOWED_ORIGIN.split(',').includes(origin)) return new Response('Forbidden', {status:403});
    if (req.method === 'OPTIONS') return new Response(null, {headers: cors(origin)});
    const target = new URL(req.url);
    const headers = new Headers({'X-Gateway-Key': env.GAS_SHARED_SECRET, 'Content-Type': req.headers.get('Content-Type') || 'application/json'});
    const authorization = req.headers.get('Authorization');
    if (authorization) headers.set('Authorization', authorization);
    const res = await fetch(env.GAS_API_URL + target.pathname, {method:req.method, headers, body:['GET','HEAD'].includes(req.method) ? undefined : req.body});
    return new Response(res.body, {status:res.status, headers:{...cors(origin),'Content-Type':'application/json','Cache-Control':'no-store'}});
  }
};
function cors(origin) { return {'Access-Control-Allow-Origin':origin,'Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Allow-Methods':'GET, POST, OPTIONS','Vary':'Origin'}; }