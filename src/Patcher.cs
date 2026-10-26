using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Windows.Forms;
using System.Drawing;
using System.Threading;

namespace ArslanKR {
class Op { public long Dst; public bool Copy; public long Src; public int Len; public byte[] Data; }
class Patch {
    public string Version; public long SrcSize; public byte[] SrcHash; public byte[] SrcIdxHash;
    public long DstSize; public byte[] DstHash; public byte[] Idx; public List<Op> Ops=new List<Op>();
    public static Patch Load(){
        Stream s=null;
        var asm=System.Reflection.Assembly.GetExecutingAssembly();
        foreach(var n in asm.GetManifestResourceNames()) if(n.EndsWith("arslan_kr.patch")) s=asm.GetManifestResourceStream(n);
        if(s==null){
            string p=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"arslan_kr.patch");
            if(!File.Exists(p)) throw new Exception("패치 데이터(arslan_kr.patch)를 찾을 수 없습니다.");
            s=File.OpenRead(p);
        }
        using(var ds=new DeflateStream(s,CompressionMode.Decompress))
        using(var r=new BinaryReader(ds)){
            var P=new Patch();
            if(Encoding.ASCII.GetString(r.ReadBytes(8))!="ARSKRP02") throw new Exception("패치 데이터 형식 오류");
            P.Version=Encoding.UTF8.GetString(r.ReadBytes(r.ReadInt32()));
            P.SrcSize=r.ReadInt64(); P.SrcHash=r.ReadBytes(32); P.SrcIdxHash=r.ReadBytes(32);
            P.DstSize=r.ReadInt64(); P.DstHash=r.ReadBytes(32);
            P.Idx=r.ReadBytes(r.ReadInt32());
            int n=r.ReadInt32();
            for(int i=0;i<n;i++){
                var o=new Op(); byte t=r.ReadByte(); o.Dst=r.ReadInt64();
                if(t==0){ o.Copy=true; o.Src=r.ReadInt64(); o.Len=r.ReadInt32(); }
                else { o.Len=r.ReadInt32(); o.Data=r.ReadBytes(o.Len); }
                P.Ops.Add(o);
            }
            return P;
        }
    }
}
// random-access view over a file region set (plain file, or ISO extents)
abstract class Region { public abstract long Length{get;} public abstract void Read(long pos,byte[] buf,int off,int n); public abstract void Write(long pos,byte[] buf,int off,int n); }
class FileRegion:Region{
    FileStream f; public FileRegion(FileStream f){this.f=f;}
    public override long Length{get{return f.Length;}}
    public override void Read(long pos,byte[] b,int o,int n){ f.Position=pos; int d=0; while(d<n){int k=f.Read(b,o+d,n-d); if(k<=0) throw new EndOfStreamException(); d+=k;} }
    public override void Write(long pos,byte[] b,int o,int n){ f.Position=pos; f.Write(b,o,n); }
}
class ExtRegion:Region{
    FileStream f; List<long[]> ext; long len;
    public ExtRegion(FileStream f,List<long[]> ext){ this.f=f; this.ext=ext; foreach(var e in ext) len+=e[1]; }
    public override long Length{get{return len;}}
    void Map(long pos,int n,Action<long,int,int> act){ long base0=0; int done=0;
        foreach(var e in ext){ long s=e[0], l=e[1];
            if(pos+done<base0+l && done<n){ long within=pos+done-base0; if(within<0) within=0;
                int k=(int)Math.Min(l-within,n-done); act(s+within,done,k); done+=k; }
            base0+=l; if(done>=n) break; }
        if(done<n) throw new Exception("ISO 범위를 벗어났습니다"); }
    public override void Read(long pos,byte[] b,int o,int n){ Map(pos,n,(fp,d,k)=>{ f.Position=fp; int x=0; while(x<k){int r=f.Read(b,o+d+x,k-x); if(r<=0) throw new EndOfStreamException(); x+=r;} }); }
    public override void Write(long pos,byte[] b,int o,int n){ Map(pos,n,(fp,d,k)=>{ f.Position=fp; f.Write(b,o+d,k); }); }
}
static class Iso {
    public class Rec { public long DirSector; public int Off; public int Len; public long Lba; public long Size; public byte Flags; public string Name; }
    static uint LE32(byte[] b,int o){ return BitConverter.ToUInt32(b,o); }
    public static List<Rec> ReadDir(FileStream f,long lba,long size){
        var list=new List<Rec>(); var buf=new byte[size]; f.Position=lba*2048; f.Read(buf,0,(int)size);
        int p=0;
        while(p<size){
            int len=buf[p];
            if(len==0){ p=((p/2048)+1)*2048; continue; }
            var r=new Rec{DirSector=lba+p/2048,Off=p%2048,Len=len,Lba=LE32(buf,p+2),Size=LE32(buf,p+10),Flags=buf[p+25]};
            int nl=buf[p+32]; r.Name=Encoding.ASCII.GetString(buf,p+33,nl);
            list.Add(r); p+=len;
        }
        return list;
    }
    public static List<Rec> Find(FileStream f,string[] path){
        var pvd=new byte[2048]; f.Position=16*2048; f.Read(pvd,0,2048);
        if(pvd[0]!=1||Encoding.ASCII.GetString(pvd,1,5)!="CD001") throw new Exception("ISO9660 이미지가 아닙니다.");
        long lba=LE32(pvd,156+2), size=LE32(pvd,156+10);
        for(int i=0;i<path.Length;i++){
            var recs=ReadDir(f,lba,size); bool last=i==path.Length-1;
            var hits=new List<Rec>();
            foreach(var r in recs){ string nm=r.Name; int sc=nm.IndexOf(';'); if(sc>=0) nm=nm.Substring(0,sc);
                if(nm.Equals(path[i],StringComparison.OrdinalIgnoreCase)) hits.Add(r); }
            if(hits.Count==0) throw new Exception("ISO 안에서 "+string.Join("/",path)+" 를 찾을 수 없습니다.");
            if(last) return hits;
            lba=hits[0].Lba; size=hits[0].Size;
        }
        return null;
    }
}
static class Engine {
    public static Action<string> Log=Console.WriteLine;
    public static Action<int> Prog=delegate{};
    public static volatile bool Cancel=false;
    static void CC(){ if(Cancel) throw new OperationCanceledException("사용자가 취소했습니다."); }
    static byte[] HashRegion(Region r,long len){
        using(var sha=SHA256.Create()){ var buf=new byte[1<<22]; long done=0;
            while(done<len){ int n=(int)Math.Min(buf.Length,len-done); r.Read(done,buf,0,n); sha.TransformBlock(buf,0,n,null,0); done+=n; Prog((int)(done*100/Math.Max(1,len))); CC(); }
            sha.TransformFinalBlock(buf,0,0); return sha.Hash; }
    }
    static bool Eq(byte[] a,byte[] b){ if(a.Length!=b.Length) return false; for(int i=0;i<a.Length;i++) if(a[i]!=b[i]) return false; return true; }
    public static string FindUsr(string root){
        foreach(var c in new[]{ Path.Combine(root,"PS3_GAME","USRDIR"), root, Path.Combine(root,"USRDIR") })
            if(File.Exists(Path.Combine(c,"LINKDATA.BIN"))&&File.Exists(Path.Combine(c,"LINKDATA.IDX"))) return c;
        return null;
    }
    // build new BIN from source region into dst stream
    static void Build(Patch P,Region src,Stream dst){
        var buf=new byte[1<<22]; int k=0; long total=0; foreach(var o in P.Ops) total+=o.Len; long done=0;
        dst.SetLength(P.DstSize);
        foreach(var o in P.Ops){
            dst.Position=o.Dst;
            if(o.Copy){ long left=o.Len, sp=o.Src; while(left>0){ int n=(int)Math.Min(buf.Length,left); src.Read(sp,buf,0,n); dst.Write(buf,0,n); sp+=n; left-=n; done+=n; } }
            else { dst.Write(o.Data,0,o.Data.Length); done+=o.Len; }
            if((++k&15)==0){ Prog((int)(done*100/Math.Max(1,total))); CC(); }
        }
        dst.Flush();
    }
    static bool CheckSrc(Patch P,Region r,string what){
        Log(what+" 검사 중 (약 1GB)...");
        if(r.Length!=P.SrcSize) return false;
        return Eq(HashRegion(r,r.Length),P.SrcHash);
    }
    public static void ApplyFolder(Patch P,string target,string source,bool backup){
        Cancel=false;
        string tu=FindUsr(target); if(tu==null) throw new Exception("대상 폴더에서 PS3_GAME\\USRDIR\\LINKDATA.BIN을 찾을 수 없습니다.");
        string tb=Path.Combine(tu,"LINKDATA.BIN"), ti=Path.Combine(tu,"LINKDATA.IDX");
        string srcBin=null;
        using(var f=new FileStream(tb,FileMode.Open,FileAccess.Read,FileShare.Read,1<<20)){
            var r=new FileRegion(f);
            if(r.Length==P.DstSize){ Log("대상 파일이 이미 패치된 상태인지 확인 중..."); if(Eq(HashRegion(r,r.Length),P.DstHash)){ Log("이미 이 버전의 한글패치가 적용되어 있습니다."); return; } }
            if(CheckSrc(P,r,"대상 LINKDATA.BIN")) srcBin=tb;
        }
        if(srcBin==null){
            if(string.IsNullOrEmpty(source)) throw new Exception("대상 폴더의 LINKDATA.BIN이 원본(BLJM61308)이 아닙니다.\n수정하지 않은 원본 게임 폴더를 '원본 폴더' 칸에 함께 지정해 주세요.");
            string su=FindUsr(source); if(su==null) throw new Exception("원본 폴더에서 LINKDATA.BIN을 찾을 수 없습니다.");
            srcBin=Path.Combine(su,"LINKDATA.BIN");
            using(var f=new FileStream(srcBin,FileMode.Open,FileAccess.Read,FileShare.Read,1<<20))
                if(!CheckSrc(P,new FileRegion(f),"원본 LINKDATA.BIN")) throw new Exception("원본 LINKDATA.BIN이 지원 버전(BLJM61308 원본)과 다릅니다.");
        }
        string tmp=tb+".kr_tmp";
        Log("한글 데이터 생성 중...");
        try{
            using(var s=new FileStream(srcBin,FileMode.Open,FileAccess.Read,FileShare.Read,1<<20))
            using(var d=new FileStream(tmp,FileMode.Create,FileAccess.ReadWrite,FileShare.None,1<<20)){
                Build(P,new FileRegion(s),d);
                Log("결과 검증 중...");
                if(!Eq(HashRegion(new FileRegion(d),d.Length),P.DstHash)) throw new Exception("결과 검증 실패");
            }
        }catch{ try{File.Delete(tmp);}catch{} throw; }
        if(srcBin==tb && backup){
            if(File.Exists(tb+".orig")) File.Delete(tb);
            else File.Move(tb,tb+".orig");
            if(!File.Exists(ti+".orig")) File.Copy(ti,ti+".orig");
        } else if(File.Exists(tb)) File.Delete(tb);
        File.Move(tmp,tb);
        File.WriteAllBytes(ti,P.Idx);
        Log("완료! 한글패치가 적용되었습니다.");
    }
    public static void ApplyIso(Patch P,string iso,string outIso){
        Cancel=false;
        string work=iso;
        if(!string.IsNullOrEmpty(outIso)){
            if(File.Exists(outIso)) throw new Exception("출력 ISO 파일이 이미 있습니다: "+outIso);
            // verify source before copying
            using(var f=new FileStream(iso,FileMode.Open,FileAccess.Read,FileShare.Read,1<<20)){
                var recs=Iso.Find(f,new[]{"PS3_GAME","USRDIR","LINKDATA.BIN"});
                if(!CheckSrc(P,new ExtRegion(f,Ext(recs)),"ISO 안의 LINKDATA.BIN")) throw new Exception("ISO 안의 LINKDATA.BIN이 원본(BLJM61308)이 아닙니다.");
            }
            Log("ISO 복사 중 (약 17GB, 시간이 걸립니다)...");
            string tmpIso=outIso+".partial";
            try{
                using(var i=new FileStream(iso,FileMode.Open,FileAccess.Read,FileShare.Read,1<<22)) using(var o=new FileStream(tmpIso,FileMode.Create,FileAccess.Write,FileShare.None,1<<22)){
                    var buf=new byte[1<<22]; long done=0,len=i.Length; int n;
                    while((n=i.Read(buf,0,buf.Length))>0){ o.Write(buf,0,n); done+=n; Prog((int)(done*100/len)); CC(); } }
            }catch{ try{File.Delete(tmpIso);}catch{} throw; }
            File.Move(tmpIso,outIso); work=outIso;
        }
        using(var f=new FileStream(work,FileMode.Open,FileAccess.ReadWrite,FileShare.None,1<<20)){
            var binR=Iso.Find(f,new[]{"PS3_GAME","USRDIR","LINKDATA.BIN"});
            var idxR=Iso.Find(f,new[]{"PS3_GAME","USRDIR","LINKDATA.IDX"});
            var bin=new ExtRegion(f,Ext(binR));
            if(string.IsNullOrEmpty(outIso)){
                if(bin.Length==P.DstSize && Eq(HashRegion(bin,bin.Length),P.DstHash)){ Log("이미 이 버전의 한글패치가 적용되어 있습니다."); return; }
                if(!CheckSrc(P,bin,"ISO 안의 LINKDATA.BIN")) throw new Exception("ISO 안의 LINKDATA.BIN이 원본(BLJM61308)이 아닙니다.");
            }
            if(P.DstSize!=P.SrcSize) throw new Exception("이 패치 버전은 ISO 크기 변경이 필요해 ISO 모드를 지원하지 않습니다.");
            if(idxR.Count!=1||idxR[0].Size!=P.Idx.Length) throw new Exception("ISO 안의 LINKDATA.IDX 크기가 예상과 다릅니다.");
            string tmp=Path.Combine(Path.GetDirectoryName(Path.GetFullPath(work)),"LINKDATA_kr.tmp");
            Log("한글 데이터 생성 중 (임시 파일 약 1GB)...");
            try{
                using(var d=new FileStream(tmp,FileMode.Create,FileAccess.ReadWrite,FileShare.None,1<<20)){
                    Build(P,bin,d);
                    Log("결과 검증 중...");
                    if(!Eq(HashRegion(new FileRegion(d),d.Length),P.DstHash)) throw new Exception("결과 검증 실패");
                    Log("ISO에 기록 중...");
                    var buf=new byte[1<<22]; long done=0;
                    while(done<d.Length){ int n=(int)Math.Min(buf.Length,d.Length-done); d.Position=done; d.Read(buf,0,n); bin.Write(done,buf,0,n); done+=n; Prog((int)(done*100/d.Length)); }
                }
                f.Position=idxR[0].Lba*2048; f.Write(P.Idx,0,P.Idx.Length);
                f.Flush();
                Log("ISO 결과 검증 중...");
                if(!Eq(HashRegion(bin,bin.Length),P.DstHash)) throw new Exception("ISO 기록 결과 검증 실패");
            } finally { try{File.Delete(tmp);}catch{} }
        }
        Log("완료! ISO에 한글패치가 적용되었습니다.");
    }
    static List<long[]> Ext(List<Iso.Rec> recs){ var l=new List<long[]>(); foreach(var r in recs) l.Add(new long[]{r.Lba*2048,r.Size}); return l; }
}
static class Program {
    [STAThread]
    static int Main(string[] args){
        if(args.Length>0 && args[0].StartsWith("--")){
            try{ Console.OutputEncoding=Encoding.UTF8; }catch{}
            try{
                var P=Patch.Load();
                if(args[0]=="--apply") Engine.ApplyFolder(P,args[1],args.Length>2?args[2]:null,args.Length>3?args[3]!="nobackup":true);
                else if(args[0]=="--iso") Engine.ApplyIso(P,args[1],args.Length>2?args[2]:null);
                return 0;
            }catch(Exception e){ Console.WriteLine("오류: "+e.Message); return 1; }
        }
        Application.EnableVisualStyles();
        Application.Run(new MainForm());
        return 0;
    }
}
class MainForm:Form{
    RadioButton rF=new RadioButton(), rI=new RadioButton();
    TextBox t1=new TextBox(), t2=new TextBox(), tLog=new TextBox();
    Label l1=new Label(), l2=new Label();
    Button b1=new Button(), b2=new Button(), bGo=new Button(), bCancel=new Button();
    CheckBox cBk=new CheckBox(); ProgressBar pb=new ProgressBar();
    public MainForm(){
        Text="아르슬란 전기×무쌍 한글패치 v1.0 — 용가리"; Width=660; Height=520; FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false;
        Font=new Font("맑은 고딕",9f);
        rF.Text="게임 폴더에 적용"; rF.SetBounds(12,10,180,24); rF.Checked=true;
        rI.Text="ISO 파일에 적용"; rI.SetBounds(200,10,180,24);
        l1.SetBounds(12,40,620,20); t1.SetBounds(12,62,530,24); b1.Text="찾아보기"; b1.SetBounds(548,60,84,26);
        l2.SetBounds(12,96,620,20); t2.SetBounds(12,118,530,24); b2.Text="찾아보기"; b2.SetBounds(548,116,84,26);
        cBk.Text="원본 LINKDATA 백업 보관 (.orig)"; cBk.Checked=true; cBk.SetBounds(12,148,400,24);
        bGo.Text="한글패치 적용"; bGo.SetBounds(12,178,520,34); bCancel.Text="취소"; bCancel.SetBounds(538,178,94,34); bCancel.Enabled=false;
        pb.SetBounds(12,220,620,18);
        tLog.Multiline=true; tLog.ReadOnly=true; tLog.ScrollBars=ScrollBars.Vertical; tLog.SetBounds(12,246,620,224);
        Controls.AddRange(new Control[]{rF,rI,l1,t1,b1,l2,t2,b2,cBk,bGo,bCancel,pb,tLog});
        rF.CheckedChanged+=(s,e)=>Mode(); Mode();
        b1.Click+=(s,e)=>Pick(t1,true); b2.Click+=(s,e)=>Pick(t2,false);
        bGo.Click+=(s,e)=>Run(); bCancel.Click+=(s,e)=>{Engine.Cancel=true;};
        Engine.Log=m=>BeginInvoke((Action)(()=>{tLog.AppendText(m+"\r\n");}));
        Engine.Prog=v=>BeginInvoke((Action)(()=>{pb.Value=Math.Max(0,Math.Min(100,v));}));
        try{ var P=Patch.Load(); tLog.AppendText("패치 버전: "+P.Version+"\r\n지원 원본: 아르슬란 전기×무쌍 PS3 일본판 (BLJM61308)\r\n\r\n"+
            "· 게임 폴더: 원본을 복사한 폴더를 선택하면 그 안의 LINKDATA.BIN/IDX를 한글판으로 교체합니다.\r\n"+
            "· ISO: 원본 ISO를 고르고 출력 ISO 경로를 지정하면 복사본에 적용합니다(출력 칸을 비우면 원본 ISO에 직접 적용).\r\n"+
            "· 적용 후 RPCS3의 dev_hdd0\\game\\BLJM61308GAMEDATA 폴더가 있으면 삭제하세요(게임이 설치 데이터를 우선 읽음).\r\n"); }
        catch(Exception ex){ tLog.AppendText(ex.Message+"\r\n"); bGo.Enabled=false; }
    }
    void Mode(){
        if(rF.Checked){ l1.Text="한글패치를 적용할 게임 폴더 (원본을 복사한 폴더 권장, PS3_GAME이 있는 폴더)"; l2.Text="원본 게임 폴더 (위 폴더의 데이터가 원본이 아닐 때만 필요)"; cBk.Enabled=true; }
        else { l1.Text="원본 ISO 파일"; l2.Text="출력 ISO 파일 (비우면 원본 ISO에 직접 적용 — 백업 권장)"; cBk.Enabled=false; }
        t1.Text=""; t2.Text="";
    }
    void Pick(TextBox t,bool first){
        if(rF.Checked){ using(var d=new FolderBrowserDialog()){ d.Description="게임 폴더(PS3_GAME이 있는 폴더)를 선택하세요"; if(d.ShowDialog(this)==DialogResult.OK) t.Text=d.SelectedPath; } }
        else if(first){ using(var d=new OpenFileDialog{Filter="PS3 ISO (*.iso)|*.iso|모든 파일|*.*"}){ if(d.ShowDialog(this)==DialogResult.OK){ t.Text=d.FileName; if(t2.Text=="") t2.Text=Path.Combine(Path.GetDirectoryName(d.FileName),Path.GetFileNameWithoutExtension(d.FileName)+" [KOR].iso"); } } }
        else { using(var d=new SaveFileDialog{Filter="PS3 ISO (*.iso)|*.iso",OverwritePrompt=false}){ if(d.ShowDialog(this)==DialogResult.OK) t.Text=d.FileName; } }
    }
    void Run(){
        string a=t1.Text.Trim(), b=t2.Text.Trim(); bool bk=cBk.Checked, iso=rI.Checked;
        if(a==""){ MessageBox.Show(this,"경로를 선택하세요."); return; }
        bGo.Enabled=false; bCancel.Enabled=true;
        new Thread(()=>{
            try{ var P=Patch.Load(); if(iso) Engine.ApplyIso(P,a,b); else Engine.ApplyFolder(P,a,b,bk);
                BeginInvoke((Action)(()=>MessageBox.Show(this,"한글패치 적용이 끝났습니다.\n\nRPCS3의 dev_hdd0\\game\\BLJM61308GAMEDATA 폴더가 있다면 삭제한 뒤 실행하세요.","완료")));
            }catch(Exception ex){ Engine.Log("오류: "+ex.Message); BeginInvoke((Action)(()=>MessageBox.Show(this,ex.Message,"오류"))); }
            finally{ BeginInvoke((Action)(()=>{bGo.Enabled=true; bCancel.Enabled=false;})); }
        }){IsBackground=true}.Start();
    }
}
}
