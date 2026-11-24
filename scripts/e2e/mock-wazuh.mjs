// Mock of the Wazuh manager API and indexer with synthetic data (invented host names,
// public CVE IDs). Used by the end-to-end test and for UI screenshots.
import http from 'node:http';
const agents = [['001','web-01'],['002','db-primary'],['003','build-runner'],['004','mail-gw'],['005','nas-01'],['006','dns-01']];
const catalog = [
  ['CVE-2024-3094','Critical',10.0,'xz-utils','5.6.0','Malicious code in the xz upstream tarballs allows unauthorised remote access via liblzma.'],
  ['CVE-2024-6387','High',8.1,'openssh-server','1:9.6p1-3','Race condition in the sshd SIGALRM handler can lead to unauthenticated remote code execution.'],
  ['CVE-2023-4863','High',8.8,'libwebp7','1.2.4-0.2','Heap buffer overflow in libwebp allows an attacker to perform an out-of-bounds write via a crafted file.'],
  ['CVE-2024-2961','High',7.3,'libc6','2.36-9','The iconv() function in glibc may overflow the output buffer when converting to ISO-2022-CN-EXT.'],
  ['CVE-2023-44487','High',7.5,'nghttp2','1.52.0-1','HTTP/2 rapid reset allows denial of service through request cancellation.'],
  ['CVE-2024-45490','Critical',9.8,'libexpat1','2.5.0-1','An issue in libexpat allows a negative length for XML_ParseBuffer.'],
  ['CVE-2023-5678','Medium',5.3,'openssl','3.0.11-1','Generating excessively long X9.42 DH keys may be slow.'],
  ['CVE-2024-0727','Medium',5.5,'openssl','3.0.11-1','Processing a maliciously formatted PKCS12 file may lead OpenSSL to crash.'],
  ['CVE-2023-50495','Medium',6.5,'libncursesw6','6.4-4','NCurse has a segmentation fault via _nc_wrap_entry().'],
  ['CVE-2024-28085','Medium',6.1,'util-linux','2.38.1-5','wall in util-linux does not filter escape sequences from command-line arguments.'],
  ['CVE-2023-29383','Low',3.3,'passwd','1:4.13+dfsg1-1','In shadow-utils, chfn does not filter control characters.'],
  ['CVE-2022-27943','Low',5.5,'gcc-12-base','12.2.0-14','libiberty has a stack exhaustion in demangle_const.'],
  ['CVE-2023-31484','High',8.1,'perl-base','5.36.0-7','CPAN.pm does not verify TLS certificates when downloading distributions.'],
  ['CVE-2023-45853','Critical',9.8,'zlib1g','1:1.2.13','MiniZip in zlib has an integer overflow in zipOpenNewFileInZip4_64.'],
];
// deterministic spread: agent i gets catalog entries where (j*7+i*3)%5 != 0, more for some
const docs = [];
agents.forEach(([id,name], i) => catalog.forEach((c, j) => {
  if ((j*7 + i*3) % (i === 0 ? 9 : i === 3 ? 2 : 4) === 1 || (i===1 && j<9) || (i===2 && j%2===0)) {
    docs.push({ agent:{id,name}, package:{name:c[3],version:c[4],type:'deb'}, vulnerability:{id:c[0],severity:c[1],score:{base:c[2]},description:c[5],detected_at:new Date(Date.UTC(2026,10,1+((i*5+j)%19),8+(j%9))).toISOString(),reference:'https://nvd.nist.gov/vuln/detail/'+c[0]} });
  }
}));
// Vulnerability detector alerts (status Active / Solved) over the last 90 days, for the trend.
// Each agent gets its own direction: some improve, some get worse, one is steady.
const DAY = 86400000;
const today = Math.floor(Date.now() / DAY) * DAY;
const vulnAlerts = [];
const drift = [[2, 5], [6, 2], [3, 3], [7, 1], [0, 0], [1, 4]]; // [new, resolved] per 10 days
agents.forEach(([id, name], i) => {
  for (let d = 0; d < 90; d++) {
    const [n, r] = drift[i];
    const k = (d * 7 + i * 13) % 10;
    if (k < n) vulnAlerts.push({ ts: today - d * DAY + 3600000 * (k + 1), id, name, cve: 'CVE-A' + d, status: 'Active', severity: catalog[(d + i) % catalog.length][1] });
    if (k >= 10 - r) vulnAlerts.push({ ts: today - d * DAY + 3600000 * (k + 2), id, name, cve: 'CVE-S' + d, status: 'Solved', severity: catalog[(d + i + 3) % catalog.length][1] });
    if (d % 9 === 0) for (const status of ['Active', 'Solved']) vulnAlerts.push({ ts: today - d * DAY + 3600000, id, name, cve: 'CVE-U' + d, status, severity: 'High' }); // package upgrade
  }
});
function trendAggs(q) {
  const from = Date.parse(q.query.bool.filter[0].range.timestamp.gte);
  const ev = vulnAlerts.filter((a) => a.ts >= from).sort((x, y) => y.ts - x.ts);
  const { size, after } = q.aggs.findings.composite;
  const start = after?.n ?? 0;
  const page = ev.slice(start, start + size);
  const findings = { buckets: page.map((a) => ({ key: { slot: Math.floor(a.ts / 600000) * 600000, agent: a.id, cve: a.cve, package: 'pkg', status: a.status, severity: a.severity }, doc_count: 1 })), ...(page.length ? { after_key: { n: start + page.length } } : {}) };
  const ids = [...new Set(ev.map((a) => a.id))];
  return { hits: { total: { value: 0, relation: 'eq' }, hits: [] }, aggregations: { findings, by_agent: { buckets: ids.map((id) => ({ key: id, doc_count: 1, name: { buckets: [{ key: ev.find((a) => a.id === id).name }] } })) } } };
}
// Attacks for the attack trend page (documentation address ranges).
const ATTACK_BASE = { smtp: 22, imap: 16, ssh: 1, 'other_login:pam': 2 };
const SERVICES = { hits: { total: { value: 9, relation: 'eq' }, hits: [] }, aggregations: { services: { buckets: { other_login: { rules: { buckets: [{ key: '5503', doc_count: 9, newest: { hits: { hits: [{ _source: { rule: { groups: ['pam', 'syslog', 'authentication_failed'] } } }] } } }] } } } } } };
function attackAggs(q) {
  const cur = q.aggs.current.aggs.categories;
  const h = cur.aggs.by_time.date_histogram;
  const step = parseInt(h.fixed_interval) * 3600000;
  const out = {}, prev = {};
  Object.keys(cur.filters.filters).forEach((id, c) => {
    const base = (ATTACK_BASE[id] ?? 0) * step / 3600000;
    const buckets = [];
    for (let t = h.extended_bounds.min, i = 0; t <= h.extended_bounds.max; t += step, i++) {
      const n = Math.floor((t < Date.now() - 45 * DAY ? 0 : base) * (0.5 + ((i * 7 + c * 5) % 11) / 8) + (id === 'ssh' && i === 9 ? 25 : 0));
      buckets.push({ key: t, doc_count: n, ips: { value: Math.ceil(n * 0.8) }, brute: { doc_count: id === 'smtp' && n && i % 13 === 4 ? 3 : 0 } });
    }
    const n = buckets.reduce((s, b) => s + b.doc_count, 0);
    out[id] = { doc_count: n, ips: { value: Math.ceil(n * 0.6) }, brute: { doc_count: buckets.reduce((s, b) => s + b.brute.doc_count, 0) }, by_time: { buckets } };
    prev[id] = { doc_count: Math.floor(n * (0.7 + c * 0.2)), ips: { value: Math.floor(n * 0.5) } };
  });
  const total = Object.values(out).reduce((s, b) => s + b.doc_count, 0);
  return { hits: { total: { value: total, relation: 'eq' }, hits: [] }, aggregations: { current: { doc_count: total, ips: { value: Math.ceil(total * 0.5) }, categories: { buckets: out } }, previous: { categories: { buckets: prev } } } };
}
const PLACES = [['Japan', 35.7, 139.7], ['Brazil', -23.5, -46.6], ['United States', 37.8, -122.4], ['South Africa', -33.9, 18.4], ['India', 19.1, 72.9], ['Australia', -33.9, 151.2], ['Germany', 52.5, 13.4], ['New Zealand', -41.3, 174.8]];
function mapHits(q) {
  const from = Date.parse(q.query.bool.filter[0].range.timestamp.gte);
  const hits = [];
  for (let t = Math.ceil(from / 60000) * 60000; t < Date.now(); t += 60000) {
    const n = t / 60000;
    const [country_name, lat, lon] = PLACES[[0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 4, 5, 6, 7, 0, 0, 1, 2, 0][(n * 5) % 24]];
    const groups = [['dovecot', 'authentication_failed'], ['poste', 'authentication_failed'], ['sshd', 'invalid_login'], ['pam', 'syslog', 'authentication_failed'], ['syslog', 'vsftpd', 'authentication_failed']][n % 5];
    hits.push({ _id: 'm' + n, _index: 'i', _source: { timestamp: new Date(t).toISOString(), agent: { name: 'mail-gw' }, rule: { groups }, data: { srcip: '203.0.113.' + (n % 250) }, ...(n % 20 ? { GeoLocation: { country_name, location: { lat, lon } } } : {}) } });
  }
  return { hits: { total: { value: hits.length, relation: 'eq' }, hits: hits.reverse().slice(0, q.size) } };
}
function attackTop(q) {
  const b = (...xs) => ({ buckets: xs.map(([key, doc_count]) => ({ key, doc_count })) });
  const to = Date.parse(q.query.bool.filter[0].range.timestamp.lt);
  return { hits: { total: { value: 42, relation: 'eq' }, hits: [1, 2, 3].map((i) => ({ _id: 'a' + i, _index: 'i', _source: { timestamp: new Date(to - i * 60000).toISOString(), agent: { id: '004', name: 'mail-gw' }, rule: { id: '9705', level: 5, description: 'Dovecot Invalid User Login Attempt.' }, data: { srcip: '203.0.113.' + i, dstuser: 'info@example.com' }, GeoLocation: { country_name: 'Exampleland' } } })) },
    aggregations: { ips: { value: 31 }, by_ip: b(['203.0.113.1', 6], ['198.51.100.7', 4]), by_country: b(['Exampleland', 30]), by_dstuser: b(['info@example.com', 25]), by_srcuser: b(['root', 9]), by_agent: b(['mail-gw', 42]), by_rule: b(['Dovecot Invalid User Login Attempt.', 42]) } };
}
const get = (o, path) => path.split('.').reduce((a,k)=>a?.[k], o);
const match = (d, f) => f.every(c => c.term ? Object.entries(c.term).every(([k,v])=>String(get(d,k))===String(v)) : c.terms ? Object.entries(c.terms).every(([k,v])=>v.includes(get(d,k))) : true);
const terms = (ds, field, size) => { const m = new Map(); ds.forEach(d=>{const k=get(d,field); m.set(k,(m.get(k)||0)+1)}); return [...m].sort((a,b)=>b[1]-a[1]).slice(0,size).map(([key,doc_count])=>({key,doc_count})); };
const srv = http.createServer((req, res) => { let body=''; req.on('data',c=>body+=c); req.on('end',()=>{
  const u = new URL(req.url,'http://x'); const send=(s,o,t)=>{res.writeHead(s,{'content-type':t?'text/plain':'application/json'});res.end(t?o:JSON.stringify(o))};
  if (u.pathname==='/security/user/authenticate') return send(200,'JWT123',true);
  if (u.pathname.startsWith('/wazuh-states-vulnerabilities')) {
    const q = JSON.parse(body); const f = q.query?.bool?.filter ?? []; const ds = docs.filter(d=>match(d,f));
    const aggs = {};
    if (q.aggs?.findings) return send(200, { hits: { total: { value: 0, relation: 'eq' }, hits: [] }, aggregations: { findings: { buckets: docs.map((d) => ({ key: { agent: d.agent.id, cve: d.vulnerability.id, package: d.package.name, severity: d.vulnerability.severity }, doc_count: 1 })) } } });
    if (q.aggs?.by_severity) aggs.by_severity = {buckets: terms(ds,'vulnerability.severity',10)};
    if (q.aggs?.by_cve) aggs.by_cve = {buckets: terms(ds,'vulnerability.id',q.aggs.by_cve.terms.size)};
    if (q.aggs?.by_agent) aggs.by_agent = {buckets: terms(ds,'agent.id',q.aggs.by_agent.terms.size).map(b=>{const sub=ds.filter(d=>d.agent.id===b.key);return {...b,name:{buckets:terms(sub,'agent.name',1)},by_severity:{buckets:terms(sub,'vulnerability.severity',10)}}})};
    if (q.aggs?.all) { const base=q.aggs.all.aggs.agent.filter.bool.filter; aggs.all={agent:{by_severity:{buckets:terms(docs.filter(d=>match(d,base)),'vulnerability.severity',10)}}}; }
    const sorted = [...ds].sort((a,b)=>b.vulnerability.score.base-a.vulnerability.score.base);
    return send(200,{hits:{total:{value:ds.length,relation:'eq'},hits:sorted.slice(0,q.size||0).map((d,i)=>({_id:'v'+i,_index:'i',_source:d}))},aggregations:aggs});
  }
  if (u.pathname.endsWith('/_search') && body && JSON.parse(body).aggs?.by_agent?.aggs?.categories) return send(200, { hits: { total: { value: 0, relation: 'eq' }, hits: [] }, aggregations: { by_agent: { sum_other_doc_count: 0, buckets: [
    { key: '001', doc_count: 40, categories: { buckets: { web: { doc_count: 40, public: { doc_count: 38, ips: { value: 12 }, first: { value: Date.now() - 7200000 }, last: { value: Date.now() - 600000 }, rules: { buckets: [{ key: 'SQL injection attempt.', doc_count: 38 }] }, rule_cves: { buckets: [] }, latest: { hits: { hits: [{ _id: 'a1' }] } } } } } } }] } } });
  const ports = u.pathname.match(/^\/syscollector\/(\d+)\/ports$/);
  if (ports) return send(200, { data: { affected_items: ports[1] === '001' ? [{ local: { ip: '0.0.0.0', port: 443 }, protocol: 'tcp', state: 'listening', process: 'nginx' }] : [], total_affected_items: ports[1] === '001' ? 1 : 0 } });
  if (u.pathname.endsWith('/_search') && body && JSON.parse(body).aggs?.services) return send(200, SERVICES);
  if (u.pathname.endsWith('/_search') && body && JSON.parse(body).aggs?.current) return send(200, attackAggs(JSON.parse(body)));
  if (u.pathname.endsWith('/_search') && body && JSON.parse(body).aggs?.by_ip) return send(200, attackTop(JSON.parse(body)));
  if (u.pathname.endsWith('/_search') && body && JSON.parse(body)._source?.includes('GeoLocation.location')) return send(200, mapHits(JSON.parse(body)));
  if (u.pathname.endsWith('/_search') && body && JSON.parse(body).aggs?.oldest) return send(200, { hits: { total: { value: 1, relation: 'eq' }, hits: [] }, aggregations: { oldest: { value: Date.now() - 45 * DAY } } });
  if (u.pathname.endsWith('/_search') && body && JSON.parse(body).aggs?.findings) return send(200, trendAggs(JSON.parse(body)));
  if (u.pathname.endsWith('/_search')) return send(200,{hits:{total:{value:0,relation:'eq'},hits:[]},aggregations:{by_level:{buckets:[]}}});
  if (u.pathname==='/' && req.headers.authorization?.startsWith('Basic')) return send(200,{version:{distribution:'opensearch',number:'2.19.1'}});
  if (u.pathname==='/') return send(200,{data:{api_version:'4.12.0'}});
  if (u.pathname==='/agents') return send(200,{data:{affected_items:agents.map(([id,name])=>({id,name,status:'active'})),total_affected_items:agents.length}});
  send(404,{title:'nf'});
});});
srv.listen(Number(process.env.MOCK_WAZUH_PORT ?? 19200), '127.0.0.1');
