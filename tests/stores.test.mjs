import test from 'node:test';
import assert from 'node:assert/strict';
import { Session } from '../dist/tools.js';
import { Budget } from '../dist/budget.js';
import { MemoryQuoteStore } from '../dist/state.js';

test('MemoryQuoteStore round-trips quotes and accepted bindings',async()=>{
 const s=new MemoryQuoteStore();
 assert.equal(await s.getQuote('j'),undefined);
 assert.equal(await s.getAccepted('j'),undefined);
 await s.setQuote('j','q1');await s.setAccepted('j','a1');
 assert.equal(await s.getQuote('j'),'q1');
 assert.equal(await s.getAccepted('j'),'a1');
 await s.setQuote('j','q2');
 assert.equal(await s.getQuote('j'),'q2');
});
test('Budget settle and refused are async and keep the budget text',async()=>{
 const b=new Budget(2);
 await b.runPaidPost('a',2,async()=>{});
 assert.ok(b.settle('a',1) instanceof Promise);
 assert.ok(b.refused('zz') instanceof Promise);
 await b.settle('a',1);
 await assert.rejects(b.runPaidPost('b',2,async()=>{}),/Session budget exceeded/);
});
function setup(quotes){
 const status={id:'job',status:'awaiting_acceptance',expires_at:'later',billing:{acceptance:'a',quote:{amount:4}}};
 const calls=[];
 const api={usage:async()=>({body:{parameter_price:2}}),submit:async()=>({body:status}),status:async()=>({body:status}),
  accept:async()=>{calls.push('accept');status.status='running';},results:async()=>({})};
 return {session:new Session(api,'api.test','test',new Budget(5),async()=>'unsupported',20,quotes),calls};
}
const quote={body:{workflow:'catalog_local_v1',records:[{title:'Tea',client_product_id:'1'}],parameters:['catalog_groups']}};
const accept={batch_id:'job',acceptance:'a',confirm:true};
test('default and injected stores gate acceptance on a displayed quote',async()=>{
 for(const store of [undefined,new MemoryQuoteStore()]){
  const {session,calls}=setup(store);
  await session.call('enrich_catalog',accept);assert.deepEqual(calls,[]);
  await session.call('enrich_catalog',quote);
  await session.call('enrich_catalog',accept);assert.deepEqual(calls,['accept']);
  if(store)assert.ok(await store.getAccepted('job'));
 }
});
