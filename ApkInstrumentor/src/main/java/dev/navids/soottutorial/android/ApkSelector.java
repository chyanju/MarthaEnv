package dev.navids.soottutorial.android;

import org.apache.commons.io.FileUtils;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.JimpleBody;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.data.AndroidMethod;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.data.SootMethodAndClass;
import soot.jimple.infoflow.methodSummary.data.provider.LazySummaryProvider;
import soot.jimple.infoflow.methodSummary.taintWrappers.SummaryTaintWrapper;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.taintWrappers.ITaintPropagationWrapper;
import soot.jimple.infoflow.taintWrappers.IdentityTaintWrapper;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.jimple.toolkits.callgraph.TransitiveTargets;
import soot.options.Options;
import soot.util.dot.DotGraph;
import soot.util.queue.QueueReader;

import java.io.*;
import java.net.URISyntaxException;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class ApkSelector {

    private final static String USER_HOME = System.getProperty("user.home");
    private static String androidJar = USER_HOME + "/Library/Android/sdk/platforms";
    static String androidDemoPath = System.getProperty("user.dir") + File.separator + "demo" + File.separator + "Android";
    static String ic3OutPath = USER_HOME + "/tmp_ic3_out";
    static String libPath = System.getProperty("user.dir") + File.separator + "lib";

    static String dirpath;
    static String outputApkspath = USER_HOME + "/output";
    static String[] sensitiveAPIs = {"openConnection()", "sendMessage", "AdRequest()", "javax.crypto", "javax.net.ssl", "sendTextMessage", "Log"};

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

            outputDir.mkdir();
            File dest = new File(ic3OutPath);
            dest.mkdir();

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

            try {
                // Run the analysis
                runIC3(fullFilePath);
                runAnalysis(fullFilePath, androidJar);
            }catch (Exception e){
                e.printStackTrace();
            }

            //checkSensitiveApis(fullFilePath);

            System.gc();
        }

    }

    private static void runIC3(final String apkPath)
    {
        // Clean the outputPath
        final File[] files = (new File(ic3OutPath)).listFiles();
        if (files != null && files.length > 0) {
            Arrays.asList(files).forEach(File::delete);
        }

        String scriptpath = System.getProperty("user.dir") + "/src/main/java/dev/navids/soottutorial/android/runIc3.sh";
        String retargaterJar = libPath + "/RetargetedApp.jar";
        String androidJar = libPath + "/android.jar";
        String ic3Jar = libPath + "/ic3-0.2.0-full.jar";

        try {
            ProcessBuilder pb = new ProcessBuilder("sh", scriptpath, apkPath, ic3OutPath, retargaterJar, androidJar, ic3Jar);
            pb.directory(new File(ic3OutPath));
            Process p = pb.start();
            BufferedReader stdInput = new BufferedReader(new
                    InputStreamReader(p.getInputStream()));

            BufferedReader stdError = new BufferedReader(new
                    InputStreamReader(p.getErrorStream()));
            StringBuffer response = new StringBuffer();
            StringBuffer errorStr = new StringBuffer();
            boolean alreadyWaited = false;
            while (p.isAlive()) {
                try {
                    if(alreadyWaited) {

                        // read the output from the command because
                        //if we don't then the buffers fill up and
                        //the command stops and doesn't return
                        String temp;

                        while ((temp = stdInput.readLine()) != null) {
                            response.append(temp);
                        }


                        String errTemp;
                        while ((errTemp = stdError.readLine()) != null) {
                            errorStr.append(errTemp);
                        }
                    }
                    Thread.sleep(1000);
                    alreadyWaited = true;
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                //System.out.println("Response is " + response);
                //System.out.println("Error is: " + errorStr);
            }

        } catch (IOException e) {
                System.out.println("Hello");
        }

    }
    private static void runAnalysis(final String fileName, final String androidJar) {
        final long beforeRun = System.nanoTime();
        final File[] files = (new File(ic3OutPath)).listFiles();


        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getAnalysisFileConfig().setAndroidPlatformDir(androidJar);
        config.getAnalysisFileConfig().setTargetAPKFile(fileName);
        config.setEnableReflection(true);
        if (files.length > 0)
            config.getIccConfig().setIccModel(files[0].getPath());
        config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
        config.setImplicitFlowMode(InfoflowConfiguration.ImplicitFlowMode.AllImplicitFlows);
        config.setMergeDexFiles(true);
        SummaryTaintWrapper wrap = null;

        try {
            wrap = new SummaryTaintWrapper(new LazySummaryProvider("summariesManual"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        SetupApplication analyzer = new SetupApplication(config);
        analyzer.setTaintWrapper(wrap);

        InfoflowResults res1 = null;
        try {
            String source_sink_file = System.getProperty("user.dir") + "/SourcesAndSinks.txt";
            res1 = analyzer.runInfoflow(source_sink_file);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (XmlPullParserException e) {
            e.printStackTrace();
        }
        //analyzer.constructCallgraph();

        checkForSensitiveAPIs(fileName, analyzer, res1);
    }

    private static DotGraph drawCallGraph(CallGraph callGraph){
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
        return dot;
    }

    private static void checkForSensitiveAPIs(String fileName, SetupApplication analyzer, InfoflowResults res1) {
        QueueReader<MethodOrMethodContext> qr = Scene.v().getReachableMethods().listener();
        ArrayList<MethodOrMethodContext> allMethods = new ArrayList<>();
        ArrayList<MethodOrMethodContext> onCreateMethods = new ArrayList<>();

        while (qr.hasNext()) {
            SootMethod meth = (SootMethod) qr.next();
            if (!meth.isJavaLibraryMethod() && meth.hasActiveBody()) {
                String body = meth.getActiveBody().toString();

                for (final String apiName : sensitiveAPIs) {
                    if (body.contains(apiName)) {
                        //allMethods.add(AndroidMethod.createFromSignature(meth.getSignature()));
                        allMethods.add(meth);
                        //System.out.println("Sensitive API: " + meth.getSignature());
                    }
                }
            }
        }

        List<SootClass> entrypoints = new ArrayList<>(analyzer.getEntrypointClasses());

        for (SootClass entrylass : entrypoints) {
            SootMethod createMeth = entrylass.getMethodByName("onCreate");
            //onCreateMethods.add(AndroidMethod.createFromSignature(createMeth.getSignature()));
            onCreateMethods.add(createMeth);
            //System.out.println("Entry point: " + createMeth.getSignature());
        }

        CallGraph cg = Scene.v().getCallGraph();
        // DotGraph dot =  drawCallGraph(cg);

        boolean isReachable = true;
        for (MethodOrMethodContext method: onCreateMethods) {
            List<MethodOrMethodContext> m = new ArrayList<>();
            m.add(method);
            ReachableMethods rm = new ReachableMethods(cg, m);
            rm.update();

            for (MethodOrMethodContext sm: allMethods){
                if (rm.contains(sm)){
                    isReachable = true;
                    //System.out.println("From: " + method.method().getSignature() + " To : " + sm.method().getSignature());
                }
                else {
                    //System.out.println("From: " + method.method().getSignature() + " To : " + sm.method().getSignature());
                    isReachable = false;
                    break;
                }
            }

            if (isReachable == false)
                break;
        }

        /*
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
        */


        if (isReachable == false) {
            File source = new File(fileName);
            File dest = new File(outputApkspath);
            try {
                //dest.mkdir();
                FileUtils.copyFileToDirectory(source, dest);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}
