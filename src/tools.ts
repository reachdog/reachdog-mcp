import { Ajv } from 'ajv';
import { Budget,amount } from './budget.ts';
import { canonical,requestKey } from './identity.ts';
import { ReachDogClient } from './client.ts';
import params from './parameters.json' with {type:'json'};
import schemas from './schemas.json' with {type:'json'};
import type { CatalogStatus,CatalogRequest,ContentRequest,TitleRequest,ResearchRequest } from './api-types.ts';

const obj=(properties:object,required:string[]=[])=>({type:'object' as const,properties,required,additionalProperties:false});
const string={type:'string',minLength:1}, confirm={type:'boolean'}, label={type:'string'};
const single={
 enrich_title:['title_match','TitleRequest','MATCH','title'],
 research_market:['market_research','ResearchRequest','RESEARCH','research'],
 generate_content:['content_generation','ContentRequest','CONTENT','content']
} as const;
const controls={confirm,run_label:label};
const tools=[
 {name:'get_usage',description:'Read account usage and current unit price.',inputSchema:obj({})},
 {name:'list_parameters',description:'List available API parameters, grouped by endpoint.',inputSchema:obj({})},
 {name:'estimate_cost',description:'Estimate one title, research or content request in Reach Dog tokens.',inputSchema:obj({parameters:{type:'array',items:string,minItems:1,uniqueItems:true}},['parameters'])},
 ...Object.entries(single).map(([name,[,schema]])=>({name,description:'Preview by default. Set confirm to request approval for this exact body.',inputSchema:obj({body:schemas[schema],...controls},['body'])})),
 {name:'enrich_catalog',description:'Submit a catalog for a quote with body. Accept a previously displayed quote with batch_id, acceptance and confirm=true.',inputSchema:obj({body:schemas.CatalogRequest,batch_id:string,acceptance:string,...controls})},
 ...['get_catalog_status','retry_payment'].map(name=>({name,description:name==='retry_payment'?'Request approval to retry a refused payment for the original accepted quote.':'Read current catalog status and settled results.',inputSchema:obj({batch_id:string,...(name==='retry_payment'?{confirm}:{})},['batch_id'])}))
];
export {tools};
const ajv=new Ajv({strict:false});
const validators=new Map(tools.map(t=>[t.name,ajv.compile(t.inputSchema)]));
type Input={body?:any;parameters?:string[];confirm?:boolean;run_label?:string;batch_id?:string;acceptance?:string};
type Approval=(message:string)=>Promise<'accepted'|'declined'|'unsupported'>;
export class Session {
  private catalogBusy = new Set<string>();
  private async onBatch<T>(id:string, run:()=>Promise<T>) {
    if(this.catalogBusy.has(id)) throw new Error('Batch operation in progress; resume with get_catalog_status');
    this.catalogBusy.add(id);
    try {return await run();} finally {this.catalogBusy.delete(id);}
  }
  private quotes=new Map<string,string>();
  private accepted=new Map<string,string>();
  constructor(private client:ReachDogClient,private host:string,private account:string,private budget:Budget,
    private approve:Approval,private waitMs=120000){}
  private async mode(confirm:boolean|undefined,details:object){
    if (!confirm) return 'preview';
    const action=await this.approve(JSON.stringify(details));
    if(action==='accepted')return 'approved by user';
    if(action==='unsupported' && this.budget.limit!==undefined)return 'within pre-approved session cap';
    return action==='declined'?'declined':'preview';
  }
  async call(name:string,a:Input={}){
    const check=validators.get(name);
    if(!check||!check(a))throw new Error('Invalid '+name+' input: '+ajv.errorsText(check?.errors));
    if(name==='list_parameters')return params;
    if(name==='get_usage')return (await this.client.usage()).body;
    if(name==='get_catalog_status')return this.onBatch(a.batch_id!,()=>this.status(a.batch_id!));
    if(name==='enrich_catalog'||name==='retry_payment')return a.batch_id ? this.onBatch(a.batch_id,()=>this.catalog(name,a)) : this.catalog(name,a);
    const op=single[name as keyof typeof single];
    const requested=a.parameters??a.body.parameters;
    const names=requested.map((x:string|number)=>typeof x==='number'?params.REGISTER[String(x) as keyof typeof params.REGISTER]:x);
    const allowed:string[]=op?params[op[2]]:[...params.MATCH,...params.RESEARCH,...params.CONTENT];
    if(new Set(names).size!==names.length||names.some((p:string)=>!allowed.includes(p))) throw new Error('Invalid parameter selection');
    if(op?.[2]==='CONTENT')for(const [p,channels] of Object.entries(params.CHANNELS))
      if(names.includes(p)&&!channels.some(c=>a.body.channels.includes(c)))throw new Error('Incompatible channels for '+p);
    const price=(await this.client.usage()).body.parameter_price;
    if(typeof price!=='number'||!Number.isFinite(price)||price<0)throw new Error('no price available for this account');
    const estimate={estimated_tokens:amount(names.length*price),basis:'estimate, not a locked quote'};
    if(!op)return estimate;
    const key=requestKey(this.host,this.account,op[0],a.body,a.run_label);
    const approval=await this.mode(a.confirm,{operation:name,body:a.body,...estimate});
    if(approval==='preview'||approval==='declined')return {...estimate,approval};
    return this.budget.runPaidPost(key,estimate.estimated_tokens,async()=>{
      const response=await this.client[op[3]](a.body as TitleRequest & ResearchRequest & ContentRequest,key);
      const state=response.headers.get('x-charge-state'), value=response.headers.get('x-charged-tokens');
      const charged=state==='settled'&&value!==null&&/^\d+$/.test(value)?Number(value):null;
      if(charged!==null)this.budget.settle(key,charged);
      return {approval,charge_state:state,charged_tokens:charged,result:response.body};
    });
  }
  private display(s:CatalogStatus){
    const {quote,acceptance}=s.billing;
    if(typeof acceptance!=='string'||!quote)throw new Error('Missing quote binding');
    this.quotes.set(s.id,canonical({quote,acceptance}));
    return {batch_id:s.id,status:s.status,quote,acceptance,expires_at:s.expires_at,approval:'preview'};
  }
  private async catalog(name:string,a:Input){
    if(a.body){
      if(name!=='enrich_catalog'||a.confirm||a.batch_id||a.acceptance)throw new Error('Submit body alone to preview a quote');
      if(a.body.parameters.some((p:string)=>!params.CATALOG.includes(p)))throw new Error('Unsupported catalog output');
      const key=requestKey(this.host,this.account,'catalog',a.body,a.run_label);
      const s=(await this.client.submit(a.body as CatalogRequest,key)).body;
      return s.status==='awaiting_acceptance'?this.display(s):this.onBatch(s.id,()=>this.status(s.id));
    }
    if(!a.batch_id)throw new Error('Missing batch_id');
    const s=(await this.client.status(a.batch_id)).body;
    const {quote,acceptance}=s.billing;
    const binding=canonical({quote,acceptance});
    const retry=name==='retry_payment';
    if(retry){
      if(!this.retryable(s)||this.accepted.get(s.id)!==binding)throw new Error('Original accepted quote required for payment retry');
    }else{
      if(s.status!=='awaiting_acceptance')return this.status(s.id);
      if(a.acceptance!==acceptance||this.quotes.get(s.id)!==binding)return this.display(s);
    }
    const cost=amount((quote as {amount?:number})?.amount);
    const approval=await this.mode(a.confirm,{operation:name,batch_id:s.id,quote});
    if(approval==='preview'||approval==='declined')return {...this.display(s),approval};
    await this.budget.runPaidPost(s.id,cost,async()=>{
      this.accepted.set(s.id,binding);
      await (retry?this.client.retryPayment(s.id,String(acceptance)):this.client.accept(s.id,String(acceptance)));
    });
    return {approval,quote,...await this.status(s.id)};
  }
  private retryable(s:CatalogStatus){return s.billing.state==='refused' && ['insufficient_credits','wallet_frozen'].includes(String(s.error?.code));}
  private async status(id:string){
    const deadline=Date.now()+this.waitMs;
    for(;;){
      const s=(await this.client.status(id,deadline)).body;
      if(s.billing.state==='refused'){this.budget.refused(id);return {batch_id:id,status:s.status,error:s.error,recovery:this.retryable(s)?'retry_payment':null};}
      if(s.status==='completed'&&s.result_available&&s.billing.state==='settled'){
        this.budget.settle(id,(s.billing.receipt as {deducted?:number})?.deducted??(s.billing.quote as {amount:number}).amount);
        return {batch_id:id,status:s.status,result:await this.client.results(id)};
      }
      if(['failed','cancelled','awaiting_acceptance','completed'].includes(s.status)||Date.now()+5000>=deadline)
        return {batch_id:id,status:s.status,billing:s.billing,error:s.error,result_available:s.result_available};
      await new Promise(r=>setTimeout(r,5000));
    }
  }
}
