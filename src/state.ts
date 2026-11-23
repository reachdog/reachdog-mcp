export interface QuoteStore {
  getQuote(id:string):Promise<string|undefined>;
  setQuote(id:string,binding:string):Promise<void>;
  getAccepted(id:string):Promise<string|undefined>;
  setAccepted(id:string,binding:string):Promise<void>;
}
export class MemoryQuoteStore implements QuoteStore {
  private quotes=new Map<string,string>();
  private accepted=new Map<string,string>();
  async getQuote(id:string){return this.quotes.get(id);}
  async setQuote(id:string,binding:string){this.quotes.set(id,binding);}
  async getAccepted(id:string){return this.accepted.get(id);}
  async setAccepted(id:string,binding:string){this.accepted.set(id,binding);}
}
export interface Spend {
  readonly limit?:number;
  runPaidPost<T>(id:string,estimate:number,post:()=>Promise<T>):Promise<T>;
  settle(id:string,x:unknown):Promise<void>;
  refused(id:string):Promise<void>;
}
