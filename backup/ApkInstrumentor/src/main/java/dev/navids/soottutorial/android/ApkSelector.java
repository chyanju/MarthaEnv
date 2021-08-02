package dev.navids.soottutorial.android;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.commons.io.comparator.SizeFileComparator;
import org.apache.commons.io.FileUtils;
import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.JimpleBody;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.axml.AXmlAttribute;
import soot.jimple.infoflow.android.axml.AXmlHandler;
import soot.jimple.infoflow.android.axml.AXmlNode;
import soot.jimple.infoflow.android.data.AndroidMethod;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.jimple.infoflow.android.resources.ARSCFileParser;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

public class ApkSelector {

    private final static String USER_HOME = System.getProperty("user.home");
    private static String androidJar = USER_HOME + "/Library/Android/sdk/platforms";
    static String androidDemoPath = System.getProperty("user.dir") + File.separator + "demo" + File.separator + "Android";
    static String ic3OutPath = USER_HOME + "/tmp_ic3_out";
    static String libPath = System.getProperty("user.dir") + File.separator + "lib";

    static String dirpath;
    static String outputApkspath = USER_HOME + "/output";
    static String[] sensitiveAPIs = {"openConnection()", "AdRequest()", "javax.crypto", "javax.net.ssl", "sendTextMessage"};
    static int overSizedCallgraph = 0;
    static int sensitiveApiPresenceCount = 0;
    static int interestingApks = 0;
    static int iccMissing = 0;

    private static void fileWrited(int totalApks, int analyzedApks, int erroredApks, int timedOutApks){
        try {
            String filePath = outputApkspath + "/stats.txt";
            FileWriter myWriter = new FileWriter(filePath);
            myWriter.write("Out of " + totalApks + " apks, analyzed apks are " + analyzedApks);
            myWriter.write("\nErrored out apks: " + erroredApks);
            myWriter.write("\nTimed out apks: " + timedOutApks);
            myWriter.write("\nOversize callgraphs: " + overSizedCallgraph);
            myWriter.write("\nNo. of sensitive API present: " + sensitiveApiPresenceCount);
            myWriter.write("\nCallgraph broken: " + interestingApks);
            myWriter.write("\nICC missing: " + iccMissing);
            myWriter.close();
            System.out.println("Successfully wrote to the file.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

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
            FilenameFilter filter = new FilenameFilter() {

                @Override
                public boolean accept(File dir, String name) {
                    return (name.endsWith(".apk"));
                }

            };

            File[] files = apkFile.listFiles(filter);
            Arrays.sort(files, SizeFileComparator.SIZE_COMPARATOR);

            for (int i = 0; i < files.length; i++) {
                apkFiles.add(files[i].getName());
                //System.out.println("Size: " + files[i].length());
            }

        }else {
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


        int totalApks = apkFiles.size();
        int erroredOutApks = 0;
        int timedOutApks = 0;
        int analyzedApks = 0;

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


            final Duration timeout = Duration.ofSeconds(1800);
            ExecutorService executor = Executors.newSingleThreadExecutor();

            final Future<String> handler = executor.submit(new Callable() {
                @Override
                public String call() throws Exception {
                    analyzeApk(fullFilePath);
                    return "completed";
                }
            });

            try {
                handler.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                handler.cancel(true);
                System.out.println("Time out has reached, move on to the next apk");
                timedOutApks = timedOutApks + 1;

            } catch (Exception e) {
                e.printStackTrace();
                erroredOutApks = erroredOutApks + 1;
            }

            executor.shutdownNow();
            analyzedApks = analyzedApks + 1;

            fileWrited(totalApks, analyzedApks, erroredOutApks, timedOutApks);
            System.gc();
        }

    }

    private static void analyzeApk(final String fullFilePath) throws Exception{
        try {
            // Run the analysis
            runIC3(fullFilePath);
            runAnalysis(fullFilePath, androidJar);
        }catch (Exception e){
            throw e;
        }

    }


    private static void runIC3(final String apkPath) throws Exception
    {
        // Clean the outputPath
        final File[] files = (new File(ic3OutPath)).listFiles();
        if (files != null && files.length > 0) {
            Arrays.asList(files).forEach(File::delete);
        }

        //System.out.println(libPath);
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
                } catch (Exception e) {
                    throw e;
                }
                //System.out.println("Response is " + response);
                //System.out.println("Error is: " + errorStr);
            }

        } catch (Exception e) {
                throw e;
        }
    }

    private static void runAnalysis(final String fileName, final String androidJar) throws Exception{
        final long beforeRun = System.nanoTime();
        final File[] files = (new File(ic3OutPath)).listFiles();
        System.out.println("Here");

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
        } catch (Exception e) {
            throw e;
        }

        SetupApplication analyzer = new SetupApplication(config);
        analyzer.setTaintWrapper(wrap);

        InfoflowResults res1 = null;

        String source_sink_file = System.getProperty("user.dir") + "/SourcesAndSinks.txt";
        analyzer.constructCallgraph();

        //analyzer.constructCallgraph();

        CallGraph cg = Scene.v().getCallGraph();

        if (cg.size() < 10000) {
            drawCallGraph(cg);
            checkForSensitiveAPIs(fileName, analyzer);
        } else {
            overSizedCallgraph = overSizedCallgraph + 1;
        }

        /*
        if (files.length > 0)

        {
        }
        else{
            iccMissing += 1;
        }*/
    }

    private static DotGraph drawCallGraph(CallGraph callGraph) throws Exception{
        DotGraph dot = new DotGraph("callgraph");
        Iterator<Edge> iteratorEdges = callGraph.iterator();

        int i = 0;
        System.out.println("Call Graph size : "+ callGraph.size());
        while (iteratorEdges.hasNext()) {
            try {
                Edge edge = iteratorEdges.next();
                String node_src = edge.getSrc().toString();
                String node_tgt = edge.getTgt().toString();

                dot.drawEdge(node_src, node_tgt);
            }catch (Exception e){
                throw e;
            }
        }

        //dot.plot("/home/priyanka/Downloads/callgraph.dot");
        return dot;
    }

    public static String getMainActivityName(String apkFileLocation) throws Exception{
        String mainActivityName = null;

            ProcessManifest pm = null;
            try {
                pm = new ProcessManifest(apkFileLocation);
            } catch (Exception e) {
                throw e;
            }

            AXmlHandler axmlh = pm.getAXml();
            // Find main activity and remove main intent-filter
            List<AXmlNode> anodes = axmlh.getNodesWithTag("activity");
            for (AXmlNode an : anodes) {
                boolean hasMain = false;
                boolean hasLauncher = false;
                AXmlNode filter = null;
                AXmlAttribute aname = an.getAttribute("name");
                String aval = (String) aname.getValue();
                //System.out.println("activity: " + aval);

                List<AXmlNode> fnodes = an.getChildrenWithTag("intent-filter");
                for (AXmlNode fn : fnodes) {
                    hasMain = false;
                    hasLauncher = false;
                    // check action
                    List<AXmlNode> acnodes = fn.getChildrenWithTag("action");
                    for (AXmlNode acn : acnodes) {
                        AXmlAttribute acname = acn.getAttribute("name");
                        String acval = (String) acname.getValue();
                        //System.out.println("action: " + acval);
                        if (acval.equals("android.intent.action.MAIN")) {
                            hasMain = true;
                        }
                    }
                    // check category
                    List<AXmlNode> catnodes = fn.getChildrenWithTag("category");
                    for (AXmlNode catn : catnodes) {
                        AXmlAttribute catname = catn.getAttribute("name");
                        String catval = (String) catname.getValue();
                        //System.out.println("category: " + catval);
                        if (catval.equals("android.intent.category.LAUNCHER")) {
                            hasLauncher = true;
                            filter = fn;
                        }
                    }
                    if (hasLauncher && hasMain) {
                        break;
                    }
                }
                if (hasLauncher && hasMain) {
                    // replace name with the activity waiting for the connection to the PDP
                    //System.out.println("main activity is: " + aval);
                    //System.out.println("excluding filter: " + filter);
                    filter.exclude();
                    mainActivityName = aval;
                    break;
                }
            }
        //mainActivityName = pm.getPackageName() + mainActivityName;
        return mainActivityName;
    }

    private static void jsonWriter(String filePath, Map<String, String> outPutList)
    {
        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
        try(FileWriter writer = new FileWriter(filePath))
        {
            gson.toJson(outPutList,writer);

            writer.close();
        }
        catch(IOException e)
        {
            e.printStackTrace();
        }
    }

    private static void checkForSensitiveAPIs(String fileName, SetupApplication analyzer) throws Exception {
        QueueReader<MethodOrMethodContext> qr = Scene.v().getReachableMethods().listener();
        ArrayList<MethodOrMethodContext> allMethods = new ArrayList<>();
        ArrayList<MethodOrMethodContext> onCreateMethods = new ArrayList<>();

        boolean isAPI = false;
        while (qr.hasNext()) {
            SootMethod meth = (SootMethod) qr.next();


            if (!meth.isJavaLibraryMethod() && meth.hasActiveBody()) {
                String body = meth.getActiveBody().toString();

                for (final String apiName : sensitiveAPIs) {
                    if (body.contains(apiName)) {
                        //allMethods.add(AndroidMethod.createFromSignature(meth.getSignature()));
                        isAPI = true;

                        allMethods.add(meth);
                        System.out.println("Sensitive API: " + apiName);
                    }
                }
            }
        }


        if (isAPI)
            sensitiveApiPresenceCount += 1;


        Map<String, String> allMethodsRechability = new HashMap<>();
        List<SootClass> entrypoints = new ArrayList<>(analyzer.getEntrypointClasses());

        String mainActivityName = null;
        try {
            mainActivityName = getMainActivityName(fileName);

        } catch (Exception e) {
            throw e;
        }

        for (SootClass entrylass : entrypoints) {
            SootMethod createMeth = entrylass.getMethodByName("onCreate");
            if (createMeth.getSignature().contains(mainActivityName))
                onCreateMethods.add(createMeth);
        }

        CallGraph cg = Scene.v().getCallGraph();

        boolean isReachable = true;
        for (MethodOrMethodContext method: onCreateMethods) {
            List<MethodOrMethodContext> m = new ArrayList<>();
            m.add(method);


            Iterator<Edge> allEdges = cg.edgesInto(method);
            SootMethod mainMethod = null;


            while (allEdges.hasNext()) {
                Edge edge = allEdges.next();

                if (edge.getSrc().method().getSignature().contains("android.content.Intent") && edge.getSrc().method().getSignature().contains("dummyMainMethod")) {
                    mainMethod = edge.getSrc().method();
                }
            }

            if (mainMethod != null)
                m.add(mainMethod);

            ReachableMethods rm = new ReachableMethods(cg, m);
            rm.update();


            for (MethodOrMethodContext sm: allMethods){
                if (rm.contains(sm)){
                    allMethodsRechability.put(sm.method().getSignature(), "yes");
                    //sSystem.out.println("From: " + method.method().getSignature() + " To: " + sm.method().getSignature());
                }
            }

        }


        for (MethodOrMethodContext sm: allMethods){
            if (!allMethodsRechability.containsKey(sm.method().getSignature())){
                isReachable = false;
                System.out.println("To: " + sm.method().getSignature());
            }
        }


        if (isReachable == false) {
            File source = new File(fileName);
            interestingApks =+ 1;
            //System.out.println("Out put path: " + outputApkspath);
            File dest = new File(outputApkspath);
            try {
                //dest.mkdir();
                FileUtils.copyFileToDirectory(source, dest);
            } catch (Exception e) {
                throw e;
            }
        }

    }
}
