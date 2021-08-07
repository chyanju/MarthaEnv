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
import soot.jimple.Jimple;
import soot.jimple.JimpleBody;
import soot.jimple.StringConstant;
import soot.options.Options;


public class AndroidInstrument {
	
	public static void main(String[] args) {
		
		//prefer Android APK files// -src-prec apk
		Options.v().set_src_prec(Options.src_prec_apk);
		
		//output as APK, too//-f J
		Options.v().set_output_format(Options.output_format_dex);
		
        // resolve the PrintStream and System soot-classes
		Scene.v().addBasicClass("java.io.PrintStream",SootClass.SIGNATURES);
        Scene.v().addBasicClass("java.lang.System",SootClass.SIGNATURES);

        PackManager.v().getPack("jtp").add(new Transform("jtp.myInstrumenter", new BodyTransformer() {
			@Override
			protected void internalTransform(final Body b, String phaseName, @SuppressWarnings("rawtypes") Map options) {
				/*
				if(!b.getMethod().toString().equals("<com.heightdev.arduinobtjoysticklite.Main: void j()>")&&
				   !b.getMethod().toString().equals("<com.vijay_tvv.star_jalsha.MainActivity: void onBackPressed()>")) {
					return;
				}
				*/
				Unit u = ((JimpleBody)b).getFirstNonIdentityStmt();
								Local tmpRef = addTmpRef(b);
								Local tmpString = addTmpString(b);
                final PatchingChain<Unit> units = b.getUnits();
								
				  // insert "tmpRef = java.lang.System.out;" 
		        units.insertBefore(Jimple.v().newAssignStmt( 
		                      tmpRef, Jimple.v().newStaticFieldRef( 
		                      Scene.v().getField("<java.lang.System: java.io.PrintStream out>").makeRef())), u);

		        // insert "tmpLong = 'HELLO';" 
		        units.insertBefore(Jimple.v().newAssignStmt(tmpString, 
		                      StringConstant.v("SOOT: begin method: "+b.getMethod().toString())), u);
		        
		        // insert "tmpRef.println(tmpString);" 
		        SootMethod toCall = Scene.v().getSootClass("java.io.PrintStream").getMethod("void println(java.lang.String)");                    
		        units.insertBefore(Jimple.v().newInvokeStmt(
		                      Jimple.v().newVirtualInvokeExpr(tmpRef, toCall.makeRef(), tmpString)), u);
		        
		        //check that we did not mess up the Jimple
		        b.validate();
			}


		}));
		
		soot.Main.main(args);
	}

    private static Local addTmpRef(Body body)
    {
        Local tmpRef = Jimple.v().newLocal("tmpRef", RefType.v("java.io.PrintStream"));
        body.getLocals().add(tmpRef);
        return tmpRef;
    }
    
    private static Local addTmpString(Body body)
    {
        Local tmpString = Jimple.v().newLocal("tmpString", RefType.v("java.lang.String")); 
        body.getLocals().add(tmpString);
        return tmpString;
    }
}

