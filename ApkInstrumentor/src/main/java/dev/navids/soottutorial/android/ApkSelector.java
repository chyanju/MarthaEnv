package dev.navids.soottutorial.android;

import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.JimpleBody;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.data.AndroidMethod;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.data.SootMethodAndClass;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.TransitiveTargets;
import soot.util.dot.DotGraph;
import soot.util.queue.QueueReader;

import java.io.*;
import java.util.*;

public class ApkSelector {

    private final static String USER_HOME = System.getProperty("user.home");
    private static String androidJar = USER_HOME + "/Library/Android/sdk/platforms";
    static String androidDemoPath = System.getProperty("user.dir") + File.separator + "demo" + File.separator + "Android";
    static String dirpath;
    static String outputApkspath = USER_HOME + "/output";
    static String[] sensitiveAPIs = {"openConnection()", "sendMessage", "AdRequest()", "javax.crypto", "javax.net.ssl", "sendTextMessage"};
    static boolean candidate;

    public static void main(String[] args) throws IOException {
        if (System.getenv().containsKey("ANDROID_HOME"))
            androidJar = System.getenv("ANDROID_HOME") + File.separator + "platforms";

        if (args.length < 3) {
            System.out.println("Wrong parameters.");
            return;
        }


        if (args[0].contains("apk_selector")) {

            //start with cleanup:
            File outputDir = new File(args[2]);

            if (outputDir.isDirectory()) {
                boolean success = true;
                for (File f : outputDir.listFiles()) {
                    success = success && f.delete();
                }
                if (!success) {
                    System.err.println("Cleanup of output directory " + outputDir + " failed!");
                }
                outputDir.delete();
            }

            dirpath = args[1];
            outputApkspath = args[2];
            processApks();

        }

    }

    public static void processApks() throws IOException {
        List<String> apkFiles = new ArrayList<String>();
        File apkFile = new File(dirpath);

        if (apkFile.isDirectory()) {
            String[] dirFiles = apkFile.list(new FilenameFilter() {

                @Override
                public boolean accept(File dir, String name) {
                    return (name.endsWith(".apk"));
                }

            });

            for (String s : dirFiles)
                apkFiles.add(s);

        } else {
            //apk is a file so grab the extension
            String extension = apkFile.getName().substring(apkFile.getName().lastIndexOf("."));

            if (extension.equalsIgnoreCase(".txt")) {
                BufferedReader rdr = new BufferedReader(new FileReader(apkFile));
                String line = null;

                while ((line = rdr.readLine()) != null)
                    apkFiles.add(line);
                rdr.close();
            }
            else if (extension.equalsIgnoreCase(".apk"))
                apkFiles.add(dirpath);

            else {
                System.err.println("Invalid input file format: " + extension);
                return;
            }
        }

        for (final String fileName : apkFiles) {
            final String fullFilePath;
            System.gc();

            // Directory handling
            if (apkFiles.size() > 1) {
                if (apkFile.isDirectory())
                    fullFilePath = dirpath + File.separator + fileName;
                else
                    fullFilePath = fileName;
                System.out.println("Analyzing file " + fullFilePath + "...");

            }
            else
                fullFilePath = fileName;

            // Run the analysis
            runAnalysis(fullFilePath, androidJar);
            //checkSensitiveApis(fullFilePath);

            System.gc();
        }

    }

    private static void runAnalysis(final String fileName, final String androidJar) {
        final long beforeRun = System.nanoTime();

        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getAnalysisFileConfig().setAndroidPlatformDir(androidJar);
        config.getAnalysisFileConfig().setTargetAPKFile(fileName);
        config.getAnalysisFileConfig().setOutputFile(outputApkspath);
        config.setEnableReflection(true);
        //config.getIccConfig();
        config.setMergeDexFiles(true);

        SetupApplication analyzer = new SetupApplication(config);
        analyzer.constructCallgraph();
        drawCallGraph(Scene.v().getCallGraph());
        checkForSensitiveAPIs(fileName, analyzer);
    }

    private static void drawCallGraph(CallGraph callGraph){
        DotGraph dot = new DotGraph("callgraph");
        Iterator<Edge> iteratorEdges = callGraph.iterator();

        int i = 0;
        System.out.println("Call Graph size : "+ callGraph.size());
        while (iteratorEdges.hasNext()) {
            Edge edge = iteratorEdges.next();
            String node_src = edge.getSrc().toString();
            String node_tgt = edge.getTgt().toString();

            dot.drawEdge(node_src, node_tgt);
        }

        dot.plot("/home/priyanka/Downloads/callgraph.dot");
    }

    private static void checkForSensitiveAPIs(String fileName, SetupApplication analyzer) {
        QueueReader<MethodOrMethodContext> qr = Scene.v().getReachableMethods().listener();
        ArrayList<AndroidMethod> allMethods = new ArrayList<>();
        ArrayList<AndroidMethod> onCreateMethods = new ArrayList<>();

        while (qr.hasNext()) {
            SootMethod meth = (SootMethod) qr.next();
            if (!meth.isJavaLibraryMethod() && meth.hasActiveBody()) {
                String body = meth.getActiveBody().toString();

                for (final String apiName : sensitiveAPIs) {
                    if (body.contains(apiName)) {
                        allMethods.add(AndroidMethod.createFromSignature(meth.getSignature()));
                        System.out.println("Sensitive API: " + meth.getSignature());
                    }
                }
            }
        }
        CallGraph cg = Scene.v().getCallGraph();
        List<SootClass> entrypoints = new ArrayList<>(analyzer.getEntrypointClasses());

        for (SootClass entrylass : entrypoints) {
            SootMethod createMeth = entrylass.getMethodByName("onCreate");
            onCreateMethods.add(AndroidMethod.createFromSignature(createMeth.getSignature()));
            System.out.println("Entry point: " + createMeth.getSignature());
        }

        Set<AndroidMethod> sources = new HashSet<>(onCreateMethods);
        Set<AndroidMethod> targets = new HashSet<>(allMethods);

        InfoflowResults res = null;
        try {
            res = analyzer.runInfoflow(sources, targets);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (XmlPullParserException e) {
            e.printStackTrace();
        }

        if (res.isEmpty()) {
            System.out.println("I am here");
            PackManager.v().runPacks();
            PackManager.v().writeOutput();
        }

    }
}
