#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema,ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { Budget } from './budget.ts';
import { ReachDogClient,ApiError } from './client.ts';
import { requestKey } from './identity.ts';
import { Session,tools } from './tools.ts';
const env=process.env;
const url=new URL(env.REACHDOG_API_URL??'');
const account=env.REACHDOG_ACCOUNT_LABEL??'';
requestKey(url.host,account,'catalog',{});
const cap=env.REACHDOG_MAX_TOKENS_PER_SESSION;
if(cap!==undefined&&!/^\d+$/.test(cap))throw new Error('Invalid session cap');
const server=new Server({name:'reachdog',version:'0.1.0'},{capabilities:{tools:{}}});
const session=new Session(new ReachDogClient(url.href,env.REACHDOG_API_KEY??''),url.host,account,new Budget(cap===undefined?undefined:Number(cap)),async message=>{
  const capability=server.getClientCapabilities()?.elicitation;
  if(!capability||('url' in capability && !('form' in capability)))return 'unsupported';
  const result=await server.elicitInput({message:'Approve Reach Dog spending? '+message,requestedSchema:{type:'object',properties:{}}});
  return result.action==='accept'?'accepted':'declined';
});
server.setRequestHandler(ListToolsRequestSchema,()=>({tools}));
server.setRequestHandler(CallToolRequestSchema,async ({params})=>{
  try {
    const value=await session.call(params.name,params.arguments);
    return {isError:!!(value && 'error' in value && value.error),content:[{type:'text',text:JSON.stringify(value)}]};
  }catch(e){
    const message=e instanceof ApiError?JSON.stringify({status:e.status,error:e.body}):e instanceof Error && !(e instanceof TypeError)?e.message:'Tool invocation failed';
    return {isError:true,content:[{type:'text',text:message}]};
  }
});
await server.connect(new StdioServerTransport());
