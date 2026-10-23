// Disassemble/decompile only explicitly selected addresses; never executes a target.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;
public class TargetedFunctions extends GhidraScript {
 public void run() throws Exception {
  String[] a=getScriptArgs();
  PrintWriter pw=new PrintWriter(new File(a[0],currentProgram.getName()+".targeted.ghidra.txt"),"UTF-8");
  DecompInterface di=new DecompInterface();di.openProgram(currentProgram);
  for(int j=1;j<a.length;j++) {
   Address addr=toAddr(a[j]);disassemble(addr);
   Function f=getFunctionAt(addr);if(f==null)f=createFunction(addr,"research_"+addr);
   pw.println("FUNCTION "+addr);
   if(f==null){pw.println("Unable to create function");continue;}
   DecompileResults dr=di.decompileFunction(f,20,monitor);
   pw.println(dr.decompileCompleted()?dr.getDecompiledFunction().getC():dr.getErrorMessage());
   InstructionIterator ii=currentProgram.getListing().getInstructions(f.getBody(),true);
   while(ii.hasNext()){Instruction i=ii.next();pw.println(i.getAddress()+" "+i);}
   pw.flush();
  }
  pw.close();di.dispose();
 }
}
