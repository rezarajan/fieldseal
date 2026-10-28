"""Runs axe-core (WCAG 2.0/2.1/2.2 A and AA) on pages in headless Chromium; walks the survey's
steps and tabs so hidden panels are checked too. Usage: axe_run.py WIDTHxHEIGHT url..."""
import asyncio, json, subprocess, sys, tempfile, urllib.request, socket, os, collections
import websockets
AXE=open(os.path.join(os.path.dirname(__file__),'vendor','axe-4.10.2.min.js')).read()  # pinned axe-core 4.10.2 (MPL-2.0), sha256 b511cd9d...7b75e3
TAGS=["wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22a","wcag22aa"]
def port():
    s=socket.socket(); s.bind(("127.0.0.1",0)); p=s.getsockname()[1]; s.close(); return p
class B:
    async def start(self,w,h):
        p=port(); self.proc=subprocess.Popen(["chromium","--headless=new","--no-sandbox","--disable-gpu",f"--remote-debugging-port={p}",f"--user-data-dir={tempfile.mkdtemp()}",f"--window-size={w},{h}","about:blank"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                t=[x for x in json.load(urllib.request.urlopen(f"http://127.0.0.1:{p}/json")) if x["type"]=="page"]
                if t: break
            except Exception: pass
            await asyncio.sleep(0.3)
        self.ws=await websockets.connect(t[0]["webSocketDebuggerUrl"],max_size=None); self.n=0
        await self.send("Page.enable")
    async def send(self,m,**pa):
        self.n+=1; i=self.n; await self.ws.send(json.dumps({"id":i,"method":m,"params":pa}))
        while True:
            r=json.loads(await self.ws.recv())
            if r.get("id")==i: return r
    async def ev(self,expr):
        r=await self.send("Runtime.evaluate",expression=expr,awaitPromise=True,returnByValue=True)
        return r.get("result",{}).get("result",{}).get("value")
    async def axe(self):
        await self.ev(AXE+";1")
        return await self.ev("axe.run(document,{runOnly:{type:'tag',values:%s},resultTypes:['violations']}).then(r=>r.violations.map(v=>({id:v.id,impact:v.impact,help:v.help,nodes:v.nodes.slice(0,3).map(n=>n.target.join(' ')+' :: '+(n.failureSummary||'').split('\\n').slice(0,2).join(' ')),count:v.nodes.length})))"%json.dumps(TAGS))
async def main():
    w,h=map(int,sys.argv[1].split('x')); b=B(); await b.start(w,h)
    agg=collections.OrderedDict()
    for url in sys.argv[2:]:
        await b.send("Page.navigate",url=url); await asyncio.sleep(1.5)
        states=[]
        for step in range(12):
            tabs=await b.ev("document.querySelectorAll('[role=tab]').length") or 0
            for t in range(max(1,tabs)):
                if tabs: await b.ev(f"(document.querySelectorAll('[role=tab]')[{t}]||{{click(){{}}}}).click()"); await asyncio.sleep(0.2)
                v=await b.axe() or []
                for x in v:
                    k=x['id']; agg.setdefault(k,{'impact':x['impact'],'help':x['help'],'where':[], 'count':0})
                    agg[k]['count']+=x['count']; agg[k]['where'].extend([f"{url.split('/')[-1]} s{step} t{t}: "+n for n in x['nodes']])
            moved=await b.ev("(()=>{const n=[...document.querySelectorAll('button,a')].find(e=>/^\\s*Next/.test(e.textContent)&&!e.disabled&&e.offsetParent);if(n){n.click();return true}return false})()")
            await asyncio.sleep(0.5)
            if not moved: break
    for k,v in agg.items():
        print(f"[{v['impact']}] {k}: {v['help']} ({v['count']} nodes)")
        for wh in v['where'][:4]: print("    ",wh[:230])
    print("TOTAL rules violated:",len(agg))
    b.proc.kill()
    return 1 if agg else 0
if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
