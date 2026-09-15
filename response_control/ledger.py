"""Bounded transactional HMAC simulation journal; not a production authorization DB.
Existing SQLiteDataRepository is explicitly a read model, not an authorization
source. This small isolated journal cannot be substituted for that repository.
Keys come from the trusted caller, never from intents; whole-file administrator
rollback is outside the HMAC boundary. Process sessions invalidate old tickets.
"""
import copy,hashlib,hmac,json,sqlite3,threading
from pathlib import Path
from .contracts import canonical,require,number
TERMINAL={'VERIFIED','DENIED','EXPIRED','CANCELLED','FAILED','REVIEW_REQUIRED','DEGRADED_SAFE'}
PATH=('PROPOSED','ADMITTED','POLICY_EVALUATED','SAFETY_EVALUATED','AUTHORIZED_FOR_SIMULATION','SIMULATING','SIMULATED','VERIFYING','VERIFIED')
def transition_allowed(old,new):
    return old not in TERMINAL and (new in TERMINAL-{'VERIFIED'} or (old in PATH[:-1] and PATH[PATH.index(old)+1]==new))
class SimulationLedger:
    MAX_RECORDS=64;MAX_BYTES=1024*1024
    def __init__(self,path,key,*,create=False):
        self.path=Path(path);require(type(key) is bytes and len(key)==32,'JOURNAL_KEY_REQUIRED');self._key=key;self.lock=threading.RLock()
        require(self.path.is_absolute() and self.path.parent.is_dir() and not self.path.is_symlink(),'JOURNAL_PATH')
        for p in self.path.parents:require(not p.is_symlink() and not p.is_junction(),'JOURNAL_REPARSE')
        marker=self.path.with_suffix('.initialized');self.marker=marker
        if create:
            require(not self.path.exists() and not marker.exists(),'JOURNAL_ALREADY_INITIALIZED')
            with marker.open('xb') as f:f.write(b'simulation-journal-v1\n')
        else:
            require(self.path.is_file() and marker.is_file(),'JOURNAL_MISSING_REVIEW_REQUIRED')
            require(self.path.stat().st_size<=4*1024*1024,'JOURNAL_FILE_BOUND')
        self.db=sqlite3.connect(str(self.path),isolation_level=None,check_same_thread=False,timeout=1)
        self.db.execute('PRAGMA trusted_schema=OFF');self.db.execute('PRAGMA synchronous=FULL');self.db.execute('PRAGMA journal_mode=DELETE');self.db.execute('PRAGMA max_page_count=1024')
        self.revision=None
        if create:
            self.db.execute('CREATE TABLE journal (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL, mac TEXT NOT NULL)')
            initial=dict(schema='cd.simulation-journal.v1',revision=0,last_time=0,records={},rejections=[],rejection_count=0)
            raw=canonical(initial);self.db.execute('INSERT INTO journal VALUES (1,?,?)',(raw,self._mac(raw)))
        try:self.data=self.read()
        except Exception:self.db.close();raise
    def _mac(self,raw):return hmac.new(self._key,raw,hashlib.sha256).hexdigest()
    def read(self):
        require(self.path.is_file() and not self.path.is_symlink() and self.marker.is_file() and not self.marker.is_symlink() and self.marker.read_bytes()==b'simulation-journal-v1\n','JOURNAL_MISSING_OR_MARKER_INVALID')
        row=self.db.execute('SELECT payload,mac FROM journal WHERE id=1').fetchone();require(row is not None,'JOURNAL_MISSING')
        raw,mac=row;require(type(raw) is bytes and len(raw)<=self.MAX_BYTES and type(mac) is str and hmac.compare_digest(mac,self._mac(raw)),'JOURNAL_INTEGRITY')
        data=json.loads(raw);require(set(data)=={'schema','revision','last_time','records','rejections','rejection_count'} and data['schema']=='cd.simulation-journal.v1','JOURNAL_SCHEMA')
        require(type(data['rejections']) is list and len(data['rejections'])<=64 and type(data['rejection_count']) is int and 0<=data['rejection_count']<=1000000 and len(data['rejections'])==min(data['rejection_count'],64),'JOURNAL_REJECTION_BOUND')
        require(type(data['revision']) is int and data['revision']>=0 and (self.revision is None or self.revision==data['revision']),'JOURNAL_STALE')
        require(number(data['last_time'])>=0,'JOURNAL_TIME')
        require(type(data['records']) is dict and len(data['records'])<=self.MAX_RECORDS,'JOURNAL_BOUND')
        for identity,record in data['records'].items():
            require(type(record) is dict and type(record.get('history')) is list and 1<=len(record['history'])<=20,'AUDIT_BOUND')
            require(record['intent']['intent_id']==identity and type(record['consumed']) is bool,'JOURNAL_IDENTITY')
            history=record['history'];require(history[0]['state']=='PROPOSED' and history[-1]['state']==record['state'],'JOURNAL_HISTORY')
            for previous,current in zip(history,history[1:]):
                require(transition_allowed(previous['state'],current['state']) and number(previous['at'])<=number(current['at']),'JOURNAL_TRANSITION')
            require(number(history[-1]['at'])<=data['last_time'],'JOURNAL_TIME')
            require(record['consumed']==any(h['state']=='SIMULATING' for h in history),'JOURNAL_CONSUMPTION')
        self.revision=data['revision'];return data
    def commit(self,data):
        with self.lock:
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.read();new=copy.deepcopy(data);new['revision']=self.revision+1
                require(len(new['records'])<=self.MAX_RECORDS and all(len(r['history'])<=20 for r in new['records'].values()),'JOURNAL_BOUND')
                raw=canonical(new);require(len(raw)<=self.MAX_BYTES,'JOURNAL_FULL')
                self.db.execute('UPDATE journal SET payload=?,mac=? WHERE id=1',(raw,self._mac(raw)));self.db.execute('COMMIT')
                self.revision=new['revision'];self.data=new
            except Exception:
                self.db.execute('ROLLBACK');raise
    def close(self):self.db.close()
