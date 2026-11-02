import { createHash } from 'node:crypto';
function ascii(s: string) {
  return JSON.stringify(s).replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4,'0'));
}
function compare(a: string, b: string) {
  const x = Array.from(a), y = Array.from(b);
  for (let i=0; i<Math.min(x.length,y.length); i++) {
    const diff=x[i].codePointAt(0)! - y[i].codePointAt(0)!;
    if (diff) return diff;
  }
  return x.length-y.length;
}
export function canonical(value: unknown): string {
  if (typeof value === 'string') return ascii(value);
  if (Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  if (value && typeof value === 'object') {
    return '{'+Object.entries(value).sort(([a],[b])=>compare(a,b)).map(([k,v])=>ascii(k)+':'+canonical(v)).join(',')+'}';
  }
  if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('Non-finite number');
  if (typeof value === 'number' && value !== 0 && Math.abs(value)<0.0001)
    return value.toExponential().replace(/e([+-])(\d)$/, 'e$10$2');
  return JSON.stringify(value);
}
const hash=(x:unknown)=>createHash('sha256').update(canonical(x)).digest('hex');
export function requestKey(environment:string,account_ref:string,operation:string,payload:object,run_label?:string) {
  if (!account_ref?.trim() || /^(tca_|sk-|bearer )/i.test(account_ref) || /^(?=.*\d)(?=.*[a-z])[a-z\d]{40,}$/i.test(account_ref))
    throw new Error('Configure a non-secret REACHDOG_ACCOUNT_LABEL');
  return 'rdt1-'+operation+'-'+hash({environment,account_ref,operation,payload_hash:hash(payload),api_revision:'b03e832',options:run_label===undefined?{}:{run_label}});
}
