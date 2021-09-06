//Derived from #https://www.bodden.de/wordpress/wp-content/uploads/2013/01/AndroidInstrument.java_.txt
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;

import soot.Body;
import soot.BodyTransformer;
import soot.Local;
import soot.PackManager;
import soot.PatchingChain;
import soot.RefType;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.VirtualInvokeExpr;
import soot.jimple.IfStmt;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;
import soot.jimple.StringConstant;
import soot.options.Options;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;


public class AndroidInstrument {
    
    private static Local newLocal(Body body, String name, String type){
        Local tmpRef = Jimple.v().newLocal(name, RefType.v(type));
        body.getLocals().add(tmpRef);
        return tmpRef;
    }
    
    public static boolean isLibraryMethod(SootMethod method){
	String classSig = method.getDeclaringClass().getName();
	return method.isJavaLibraryMethod()||classSig.startsWith("android.")||classSig.startsWith("androidx.")||classSig.startsWith("com.google.");
    }
    
    public static void main(String[] args) {
		
	//prefer Android APK files// -src-prec apk
	Options.v().set_src_prec(Options.src_prec_apk);
		
	//output as APK, too//-f J
	Options.v().set_output_format(Options.output_format_dex);

	//allow multiple dex files//-process-multiple-dex
	Options.v().set_process_multiple_dex(true);
		
        // resolve the PrintStream and System soot-classes
	Scene.v().addBasicClass("java.io.PrintStream",SootClass.SIGNATURES);
        Scene.v().addBasicClass("java.lang.System",SootClass.SIGNATURES);

        PackManager.v().getPack("jtp").add(new Transform("jtp.myInstrumenter", new BodyTransformer() {
		@Override
		protected void internalTransform(final Body b, String phaseName, @SuppressWarnings("rawtypes") Map options) {
		    
		    if(isLibraryMethod(b.getMethod())) {
			return;
		    }
		    // At begining of each method, print the method name
			
		    Unit u = ((JimpleBody)b).getFirstNonIdentityStmt();
		    Local tmpRef = newLocal(b,"tmpRef","java.io.PrintStream");
		    Local tmpString = newLocal(b,"tmpString","java.lang.String");
		    final PatchingChain<Unit> units = b.getUnits();
		    						
		    // insert "tmpRef = java.lang.System.out;" 
		    units.insertBefore(Jimple.v().newAssignStmt(tmpRef, Jimple.v().newStaticFieldRef(Scene.v().getField("<java.lang.System: java.io.PrintStream out>").makeRef())), u);

		    // insert "tmpLong = 'HELLO';" 
		    units.insertBefore(Jimple.v().newAssignStmt(tmpString, StringConstant.v("SOOT: begin method: "+b.getMethod().toString())), u);
		        
		    // insert "tmpRef.println(tmpString);" 
		    SootMethod toCall = Scene.v().getSootClass("java.io.PrintStream").getMethod("void println(java.lang.String)");                    
		    units.insertBefore(Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(tmpRef, toCall.makeRef(), tmpString)), u);
		    
		    //check that we did not mess up the Jimple
		    b.validate();
		}
	    }));
		
	soot.Main.main(args);
    }

}

