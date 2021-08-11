//Derived from #https://www.bodden.de/wordpress/wp-content/uploads/2013/01/AndroidInstrument.java_.txt
// and https://github.com/noidsirius/SootTutorial/blob/master/src/main/java/dev/navids/soottutorial/android/AndroidCallgraph.java

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.PrintWriter;
import java.io.Writer;
import java.io.BufferedWriter;
import java.io.File;
import java.util.*;

public class AndroidCallgraph {

	//https://github.com/noidsirius/SootTutorial/blob/master/src/main/java/dev/navids/soottutorial/android/AndroidUtil.java
	public static boolean isLibraryMethod(SootMethod method){
	    String classSig = method.getDeclaringClass().getName();
	    return method.isJavaLibraryMethod()||classSig.startsWith("android.")||classSig.startsWith("com.google.");
   	} 
	public static void main(String[] args) {
		
		if(args.length<1) {
			System.out.printf("Usage: java AndroidCallgraph path-to-apk\n");
			System.exit(1);
		}

		final InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
		config.getAnalysisFileConfig().setTargetAPKFile(args[0]);
		config.getAnalysisFileConfig().setAndroidPlatformDir(System.getenv("ANDROID_SDK_ROOT")+File.separator+"platforms");
		config.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
		config.setEnableReflection(true);
		config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
		
		SetupApplication app = new SetupApplication(config);
		app.constructCallgraph();

		CallGraph callGraph = Scene.v().getCallGraph();
		//Warning: not handling null case

		try(PrintWriter writer = new PrintWriter(new File("base64.lgl"))){
		
		    Iterator<Edge> ite=callGraph.iterator();
		    while(ite.hasNext()){
			Edge edge = ite.next();
			if(isLibraryMethod(edge.src())||isLibraryMethod(edge.tgt())){
				continue;
			}
			//Base64 encode because lgl files can't have spaces in vertex names, but Soot function signatures can
			writer.printf("%s %s\n",
				      Base64.getEncoder().encodeToString(edge.src().getSignature().getBytes()),
				      Base64.getEncoder().encodeToString(edge.tgt().getSignature().getBytes()));
		    }
		}catch(Exception e){
		    e.printStackTrace();
		}
		
	}

}

