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
import soot.Value;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.VirtualInvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.IfStmt;
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;
import soot.jimple.IntConstant;
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
        Scene.v().addBasicClass("android.view.View",SootClass.SIGNATURES);
        Scene.v().addBasicClass("android.widget.Button",SootClass.SIGNATURES);

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
		    Local tmpBuilder = newLocal(b,"tmpBuilder","java.lang.StringBuilder");
		    Local tmpInt = newLocal(b,"tmpInt","int");
		    Local tmpButton = newLocal(b,"tmpButton","android.widget.Button");

		    final PatchingChain<Unit> units = b.getUnits();
		    
		    Iterator stmtIt = units.snapshotIterator();

		    // typical while loop for iterating over each statement
		    while (stmtIt.hasNext()) {

			// cast back to a statement.
			Stmt stmt = (Stmt) stmtIt.next();

			// there are many kinds of statements, here we are only
			// interested in statements containing InvokeStatic
			// NOTE: there are two kinds of statements may contain
			// invoke expression: InvokeStmt, and AssignStmt
			if (!stmt.containsInvokeExpr()) {
			    continue;
			}

			// take out the invoke expression
			InvokeExpr expr = (InvokeExpr) stmt.getInvokeExpr();

			// now skip non-static invocations
			if (!(expr instanceof VirtualInvokeExpr)) {
			    continue;
			}

			System.out.println(expr.toString());
			System.out.println(expr.getMethod().toString());
			
			if(!(expr.getMethod().toString().equals("<android.view.View: void setOnClickListener(android.view.View$OnClickListener)>"))){
			    continue;
			}

			Local button = (Local)(((VirtualInvokeExpr)expr).getBase());
			String callbackName = expr.getArg(0).getType().toString();
			System.out.printf("FOUND onClick registration %s (%s) => %s\n",button.toString(),button.getType().toString(),expr.getArg(0).getType().toString());

			SootClass stringBuilderClass = Scene.v().getSootClass("java.lang.StringBuilder");
			//SootClass viewClass = Scene.v().getSootClass("android.view.View");

			//get button ID
			//units.insertBefore(Jimple.v().newAssignStmt(tmpButton, button), u); //This statement causes crash
			//units.insertBefore(Jimple.v().newAssignStmt(tmpInt, Jimple.v().newVirtualInvokeExpr(tmpButton, viewClass.getMethod("int getId()").makeRef())), u);


			units.insertBefore(Jimple.v().newAssignStmt(tmpInt, IntConstant.v(-1234)), u);
			
			
			//initialize StringBuilder
			units.insertBefore(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newNewExpr(RefType.v(stringBuilderClass))),u);
			units.insertBefore(Jimple.v().newInvokeStmt(Jimple.v().newSpecialInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("void <init>()").makeRef())), u);

			//build message
			units.insertBefore(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(java.lang.String)").makeRef(), StringConstant.v("SOOT: MARTHA: setOnClickListener "))),u);
			units.insertBefore(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(int)").makeRef(), tmpInt)),u);
			units.insertBefore(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(java.lang.String)").makeRef(), StringConstant.v(" to "))),u);
			units.insertBefore(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(java.lang.String)").makeRef(), StringConstant.v(callbackName))),u);

			//print message
			units.insertBefore(Jimple.v().newAssignStmt(tmpString, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.String toString()").makeRef())),u);
			units.insertBefore(Jimple.v().newAssignStmt(tmpRef, Jimple.v().newStaticFieldRef(Scene.v().getField("<java.lang.System: java.io.PrintStream out>").makeRef())), u);
			units.insertBefore(Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(tmpRef, Scene.v().getSootClass("java.io.PrintStream").getMethod("void println(java.lang.String)").makeRef(), tmpString)), u);
		    }

		    
		    //check that we did not mess up the Jimple
		    b.validate();
		}
	    }));
		
	soot.Main.main(args);
    }

}

