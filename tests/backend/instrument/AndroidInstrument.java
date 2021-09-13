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
import soot.jimple.IdentityStmt;
import soot.jimple.ThisRef;
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
        Scene.v().addBasicClass("android.content.res.Resources",SootClass.SIGNATURES);

        PackManager.v().getPack("jtp").add(new Transform("jtp.myInstrumenter", new BodyTransformer() {
		@Override
		protected void internalTransform(final Body b, String phaseName, @SuppressWarnings("rawtypes") Map options) {
		    
		    if(isLibraryMethod(b.getMethod())) {
			return;
		    }
		        
		    Local tmpRef = newLocal(b,"tmpRef","java.io.PrintStream");
		    Local tmpString = newLocal(b,"tmpString","java.lang.String");
		    Local tmpBuilder = newLocal(b,"tmpBuilder","java.lang.StringBuilder");
		    Local tmpInt = newLocal(b,"tmpInt","int");
		    Local tmpButton = newLocal(b,"tmpButton","android.widget.Button");
		    Local tmpResources = newLocal(b,"tmpResources","android.content.res.Resources");
		    Local tmpThis = null;//newLocal(b,"tmpThis",b.getMethod().getDeclaringClass().toString());

		    // Based on https://www.sable.mcgill.ca/soot/tutorial/profiler2/index.html
		    final PatchingChain<Unit> units = b.getUnits();


		    Stmt thisStmt = (Stmt) units.getFirst();
		    if(thisStmt instanceof IdentityStmt && ((IdentityStmt)thisStmt).getRightOp() instanceof ThisRef){
			tmpThis = (Local)(((IdentityStmt)thisStmt).getLeftOp());
		    }
			
		    Iterator stmtIt = units.snapshotIterator();
		    while (stmtIt.hasNext()) {
			
			Stmt stmt = (Stmt) stmtIt.next();

			// NOTE: there are two kinds of statements may contain
			// invoke expression: InvokeStmt, and AssignStmt
			if (!stmt.containsInvokeExpr()) {
			    continue;
			}

			InvokeExpr expr = (InvokeExpr) stmt.getInvokeExpr();

			// filter for setOnClickListener
			if (!(expr instanceof VirtualInvokeExpr)) {
			    continue;
			}
			if(!(expr.getMethod().toString().equals("<android.view.View: void setOnClickListener(android.view.View$OnClickListener)>"))){
			    continue;
			}

			Local button = (Local)(((VirtualInvokeExpr)expr).getBase());
			String callbackName = expr.getArg(0).getType().toString();
			//System.out.printf("FOUND onClick registration %s (%s) => %s\n",button.toString(),button.getType().toString(),expr.getArg(0).getType().toString());

			SootClass stringBuilderClass = Scene.v().getSootClass("java.lang.StringBuilder");
			SootClass viewClass = Scene.v().getSootClass("android.view.View");
			SootClass contextClass = Scene.v().getSootClass("android.content.Context");
			SootClass resourcesClass = Scene.v().getSootClass("android.content.res.Resources");

			ArrayList<Unit> instructions = new ArrayList<Unit>();
			
			//get button ID
			instructions.add(Jimple.v().newAssignStmt(tmpButton, button));
			instructions.add(Jimple.v().newAssignStmt(tmpInt, Jimple.v().newVirtualInvokeExpr(tmpButton, viewClass.getMethod("int getId()").makeRef())));
			
			instructions.add(Jimple.v().newAssignStmt(tmpResources, Jimple.v().newVirtualInvokeExpr(tmpThis, contextClass.getMethod("android.content.res.Resources getResources()").makeRef())));
			instructions.add(Jimple.v().newAssignStmt(tmpString, Jimple.v().newVirtualInvokeExpr(tmpResources, resourcesClass.getMethod("java.lang.String getResourceName(int)").makeRef(), tmpInt)));

			
		       
			//initialize StringBuilder
			instructions.add(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newNewExpr(RefType.v(stringBuilderClass))));
			instructions.add(Jimple.v().newInvokeStmt(Jimple.v().newSpecialInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("void <init>()").makeRef())));

			//build message
			instructions.add(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(java.lang.String)").makeRef(), StringConstant.v("SOOT: MARTHA: setOnClickListener "))));
			//instructions.add(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(int)").makeRef(), tmpInt)));
			instructions.add(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(java.lang.String)").makeRef(), tmpString)));
			instructions.add(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(java.lang.String)").makeRef(), StringConstant.v(" to "))));
			instructions.add(Jimple.v().newAssignStmt(tmpBuilder, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.StringBuilder append(java.lang.String)").makeRef(), StringConstant.v(callbackName))));

			//print message
			instructions.add(Jimple.v().newAssignStmt(tmpString, Jimple.v().newVirtualInvokeExpr(tmpBuilder, stringBuilderClass.getMethod("java.lang.String toString()").makeRef())));
			instructions.add(Jimple.v().newAssignStmt(tmpRef, Jimple.v().newStaticFieldRef(Scene.v().getField("<java.lang.System: java.io.PrintStream out>").makeRef())));
			instructions.add(Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(tmpRef, Scene.v().getSootClass("java.io.PrintStream").getMethod("void println(java.lang.String)").makeRef(), tmpString)));

			units.insertBefore(instructions, stmt);
		    }

		    
		    //check that we did not mess up the Jimple
		    b.validate();
		}
	    }));
		
	soot.Main.main(args);
    }

}

