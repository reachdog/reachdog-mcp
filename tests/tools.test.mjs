import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { Session } from '../dist/tools.js';
import { Budget } from '../dist/budget.js';
import { requestKey } from '../dist/identity.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { createServer } from 'node:http';

const title={title:'Tea',parameters:['brand']};
function setup({cap,mode='unsupported',price=2}={}) {
 let status={id:'job',status:'awaiting_acceptance',expires_at:'later',billing:{acceptance:'a',quote:{amount:4}}};
 const calls=[];
 const api={usage:async()=>({body:{parameter_price:price}}),title:async(body,key)=>{
   calls.push(key);return {body:{brand:'Tea'},headers:new Headers({'x-charge-state':'settled','x-charged-tokens':'2'})};},
 submit:async()=>({body:status}),status:async()=>({body:status}),
 accept:async()=>{calls.push('accept');status.status='running';},retryPayment:async()=>{calls.push('retry');status.status='running';},
 results:async()=>{calls.push('results');return {};}};
 const session=new Session(api,'api.test','test',new Budget(cap),async()=>mode,20);
 return {session,api,calls,status};
}
const quote={body:{workflow:'catalog_local_v1',records:[{title:'Tea',client_product_id:'1'}],parameters:['catalog_groups']}};
const accept={batch_id:'job',acceptance:'a',confirm:true};
test('preview, decline, and absent approval never pay',async()=>{
 for(const args of [{cap:2},{mode:'declined',cap:2},{}]){
  const {session,calls}=setup(args);
  await session.call('enrich_title',{body:title,confirm:!('cap'in args)||args.mode==='declined'});
  assert.equal(calls.length,0);
 }
 const {session,calls}=setup({price:null,cap:3});
 await assert.rejects(session.call('enrich_title',{body:title,confirm:true}),/no price available/);
 assert.deepEqual(calls,[]);
});
test('concurrent requests fit only one reservation',async()=>{
 const {session,calls}=setup({cap:2});
 const results=await Promise.allSettled(['a','b'].map(run_label=>session.call('enrich_title',{body:title,confirm:true,run_label})));
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);assert.equal(calls.length,1);
});
test('lost reply retains allowance and same key can recover',async()=>{
 const {session,api,calls}=setup({cap:2});const send=api.title;let key;
 api.title=async(_,id)=>{key=id;throw Error('lost');};
 await assert.rejects(session.call('enrich_title',{body:title,confirm:true}),/lost/);
 api.title=send;
 await assert.rejects(session.call('enrich_title',{body:title,confirm:true,run_label:'new'}),/budget/);
 await session.call('enrich_title',{body:title,confirm:true});assert.equal(key,calls[0]);
});
test('unknown and changed quotes require re-display, timeout resumes the same job',async()=>{
 const {session,status,calls}=setup({cap:5});
 await session.call('enrich_catalog',accept);
 await session.call('enrich_catalog',quote);
 status.billing.quote.amount=5;
 await session.call('enrich_catalog',accept);assert.deepEqual(calls,[]);
 assert.equal((await session.call('enrich_catalog',accept)).batch_id,'job');
 await session.call('enrich_catalog',accept);assert.deepEqual(calls,['accept']);
 Object.assign(status,{status:'completed',result_available:true});status.billing.state='settled';status.billing.receipt={deducted:5};
 await session.call('get_catalog_status',{batch_id:'job'});assert.deepEqual(calls,['accept','results']);
});
test('refused payments retry only after a recoverable refusal',async()=>{
 const {session,status,calls}=setup({cap:4});
 await session.call('enrich_catalog',quote);await session.call('enrich_catalog',accept);
 Object.assign(status,{status:'failed',error:{code:'wallet_frozen'}});status.billing.state='refused';
 assert.equal((await session.call('get_catalog_status',{batch_id:'job'})).recovery,'retry_payment');
 status.error.code='final_failure';
 await assert.rejects(session.call('retry_payment',{batch_id:'job',confirm:true}),/Original accepted/);
 status.error.code='insufficient_credits';
 await session.call('retry_payment',{batch_id:'job',confirm:true});assert.deepEqual(calls,['accept','retry']);
});
test('identity matches pinned Python fixtures',()=>{
 for(const {payload,key} of JSON.parse(readFileSync(new URL('parity.json',import.meta.url))))
  assert.equal(requestKey('api.test','test','title_match',payload),key);
});
test('a real stdio client lists tools and previews with a mock HTTP API',async()=>{
 const api=createServer((req,res)=>{assert.equal(req.url,'/v1/usage');res.end('{"parameter_price":2}');});
 await new Promise(r=>api.listen(0,'127.0.0.1',r));
 const client=new Client({name:'test',version:'1'});
 try{
  const transport=new StdioClientTransport({command:process.execPath,args:['dist/server.js'],env:{REACHDOG_API_URL:'http://127.0.0.1:'+api.address().port,REACHDOG_API_KEY:'test',REACHDOG_ACCOUNT_LABEL:'offline'}});
  await client.connect(transport);
  assert.equal((await client.listTools()).tools.length,9);
  const result=await client.callTool({name:'enrich_title',arguments:{body:title}});
  assert.equal(JSON.parse(result.content[0].text).estimated_tokens,2);
 }finally{await client.close();await new Promise(r=>api.close(r));}
});
