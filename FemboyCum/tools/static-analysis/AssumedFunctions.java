// Applies byte-checked overrides to a disposable Ghidra analysis image only.
// Never run this against the sole copy of a reference program.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.nio.file.*;
public class AssumedFunctions extends GhidraScript {
 private byte[] hex(String s){byte[] r=new byte[s.length()/2];for(int k=0;k<r.length;k++)r[k]=(byte)Integer.parseInt(s.substring(k*2,k*2+2),16);return r;}
 public void run() throws Exception {
  String[] a=getScriptArgs();
  PrintWriter pw=new PrintWriter(new File(a[0],currentProgram.getName()+".assumed.ghidra.txt"),"UTF-8");
  pw.println("CONDITIONAL ANALYSIS DERIVATIVE. Runtime assumptions unverified. No target execution.");
  for(String line:Files.readAllLines(Paths.get(a[1]))){
   if(line.trim().isEmpty())continue;
   String[] p=line.split("\t",4);Address addr=toAddr(p[0]);byte[] before=hex(p[1]),after=hex(p[2]);
   if(before.length!=after.length)throw new Exception("Size mismatch at "+addr);
   for(int k=0;k<before.length;k++)if(currentProgram.getMemory().getByte(addr.add(k))!=before[k])throw new Exception("Original byte mismatch at "+addr);
   currentProgram.getMemory().setBytes(addr,after);pw.println("ANALYSIS_OVERRIDE "+line);
  }
  DecompInterface di=new DecompInterface();di.openProgram(currentProgram);
  for(int j=2;j<a.length;j++){
   Address addr=toAddr(a[j]);disassemble(addr);Function f=getFunctionAt(addr);if(f==null)f=createFunction(addr,"assumed_"+addr);
   pw.println("FUNCTION "+addr);if(f==null){pw.println("Unable to create function");continue;}
   DecompileResults dr=di.decompileFunction(f,20,monitor);
   pw.println(dr.decompileCompleted()?dr.getDecompiledFunction().getC():dr.getErrorMessage());
   InstructionIterator ii=currentProgram.getListing().getInstructions(f.getBody(),true);
   while(ii.hasNext()){Instruction i=ii.next();pw.println(i.getAddress()+" "+i);}pw.flush();
  }
  pw.close();di.dispose();
 }
}
