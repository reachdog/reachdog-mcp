import { ToolError } from './errors.ts';
import { ApiError } from './client.ts';
import type { Spend } from './state.ts';
export function amount(x:unknown):number {
  if(typeof x!=='number'||!Number.isFinite(x)||x<0) throw new Error('Invalid billing amount');
  return x;
}
export class Budget implements Spend {
  private entries=new Map<string,number>();
  private busy=new Set<string>();
  constructor(readonly limit?:number){if(limit!==undefined)amount(limit);}
  async runPaidPost<T>(id:string, estimate:number, post:()=>Promise<T>) {
    if (this.busy.has(id)) throw new ToolError('Operation already in progress');
    const prior=this.entries.get(id);
    const reserve=Math.max(prior??0,amount(estimate));
    const total=Array.from(this.entries.values()).reduce((a,b)=>a+b,0);
    if(this.limit!==undefined && total-(prior??0)+reserve>this.limit) throw new ToolError('Session budget exceeded');
    this.busy.add(id); this.entries.set(id,reserve);
    try {return await post();}
    catch(e){
      if(prior===undefined && e instanceof ApiError && !e.ambiguous && [400,401,402,403,422,429].includes(e.status))
        this.entries.delete(id);
      throw e;
    } finally {this.busy.delete(id);}
  }
  async settle(id:string,x:unknown){if(this.entries.has(id))this.entries.set(id,amount(x));}
  async refused(id:string){this.entries.delete(id);}
}
