package dev.navids.soottutorial.android;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import soot.*;
import soot.jimple.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.methodSummary.data.provider.LazySummaryProvider;
import soot.jimple.infoflow.methodSummary.taintWrappers.SummaryTaintWrapper;
import soot.jimple.infoflow.results.InfoflowResults;
import org.xmlpull.v1.XmlPullParserException;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.ReachableMethods;
import soot.util.queue.QueueReader;



public class AndroidLogger {

    private final static String USER_HOME = System.getProperty("user.home");
    private static String androidJar = USER_HOME + "/Library/Android/sdk/platforms";
    static String androidDemoPath = System.getProperty("user.dir") + File.separator + "demo" + File.separator + "Android";
    static String apkPath = androidDemoPath + File.separator + "/opensudoku-sdk-22.apk";
    static String outputPath = androidDemoPath + File.separator + "/Instrumented";
    static String idFilePath = outputPath + File.separator + "/JimpleIR.id";
    private static Map<String, List<String>> methodDetailsList = new HashMap<>();
    private static Map<String, List<String>> instrumentationDetails = new HashMap<>();
    static boolean dump = false;
    static boolean instrument = false;
    static boolean auto_instrument = false;
    //static String[] sensitiveAPIs = {"openConnection()", "AdRequest()", "javax.crypto", "javax.net.ssl", "sendTextMessage"};
    static String[] sensitiveAPIs = {"openConnection()"};
    static boolean app_select = false;
    static Map<String, String> trainingData = new HashMap<String, String>();
    static Map<String, String> testingData = new HashMap<String, String>();
    static boolean candidate;


    public static void jsonWriter(String filePath, Map<String, List<String>> outPutList) {
        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(filePath)) {
            gson.toJson(outPutList, writer);

            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void dumpGoalJson(String filePath, Map<String, String> outPutList) {
        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
        try (FileWriter writer = new FileWriter(filePath)) {
            gson.toJson(outPutList, writer);

            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void dumpGoalMethods(String apkPath, CallGraph cg, ArrayList<MethodOrMethodContext> sensitiveMethods, ArrayList<MethodOrMethodContext> dummyMainMethods) {
        List<MethodOrMethodContext> callback_methods = new ArrayList<>();

        for (MethodOrMethodContext method : dummyMainMethods) {
            Iterator<Edge> allEdges = cg.edgesOutOf(method);

            while (allEdges.hasNext()) {
                Edge edge = allEdges.next();
                callback_methods.add(edge.getTgt());
            }

        }

        Map<String, String> goalMethods = new HashMap<>();

        int count = 0;
        for (MethodOrMethodContext callbackMethod : callback_methods) {
            List<MethodOrMethodContext> m = new ArrayList<>();
            m.add(callbackMethod);
            ReachableMethods reachableMethods = new ReachableMethods(cg, m);
            reachableMethods.update();

            for (MethodOrMethodContext sensitiveMethod : sensitiveMethods) {
                if (reachableMethods.contains(sensitiveMethod))
                    goalMethods.put(String.valueOf(count), callbackMethod.method().getSignature());
            }
        }

        String outPath = outputPath + "/goals_caller.json";
        dumpGoalJson(outPath, goalMethods);
    }

    private static void getSensitiveApiCallerMethods(String apkPath, SetupApplication analyzer) throws Exception {
        QueueReader<MethodOrMethodContext> qr = Scene.v().getReachableMethods().listener();
        ArrayList<MethodOrMethodContext> allMethods = new ArrayList<>();
        ArrayList<MethodOrMethodContext> allOnCreateMethods = new ArrayList<>();
        CallGraph cg = Scene.v().getCallGraph();

        while (qr.hasNext()) {
            SootMethod meth = (SootMethod) qr.next();

            if (meth.getSignature().contains("android.content.Intent") && meth.getSignature().contains("dummyMainMethod"))
                allOnCreateMethods.add(meth);

            if (!meth.isJavaLibraryMethod() && meth.hasActiveBody()) {
                String body = meth.getActiveBody().toString();

                for (final String apiName : sensitiveAPIs) {
                    if (body.contains(apiName))
                        allMethods.add(meth);

                }
            }
        }

        dumpGoalMethods(apkPath, cg, allMethods, allOnCreateMethods);
    }

    private static void runAnalysis(final String filePath, final String androidJar) throws Exception{
        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getAnalysisFileConfig().setAndroidPlatformDir(androidJar);
        config.getAnalysisFileConfig().setTargetAPKFile(filePath);
        config.setEnableReflection(true);
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
        analyzer.constructCallgraph();
        getSensitiveApiCallerMethods(filePath, analyzer);
    }

    public static void jsonReader(String filePath, String dataType) {
        try {
            // create Gson instance
            Gson gson = new Gson();

            // create a reader
            Reader reader = Files.newBufferedReader(Paths.get(filePath));

            // convert JSON file to map
            if (dataType.equals("training"))
                trainingData = gson.fromJson(reader, new TypeToken<Map<String, String>>() {
                }.getType());
            else
                testingData = gson.fromJson(reader, new TypeToken<Map<String, String>>() {
                }.getType());

            // close reader
            reader.close();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static List<Unit> generateInstrumentedString(String instrumentationTAG, String hashMapKey, JimpleBody body, String id) {
        String content;
        List<Unit> generatedUnits = new ArrayList<>();

        if (instrumentationTAG.equals("TEST DATA")) {
            String goalState = hashMapKey + " : " + id;
            content = String.format("TEST DATA : Goal instruction in %s reached\n", goalState);
        } else {
            String goalState = hashMapKey + " : " + id;
            content = String.format("TRAIN DATA : Goal instruction in %s reached\n", goalState);
        }

        if (auto_instrument == true) {
            String goalState = hashMapKey + " : " + id;
            content = String.format("TRAIN DATA : Goal instruction in %s reached\n", goalState);
        }

        // In order to call "System.out.println" we need to create a local containing "System.out" value
        Local psLocal = InstrumentUtil.generateNewLocal(body, RefType.v("java.io.PrintStream"));
        // Now we assign "System.out" to psLocal
        SootField sysOutField = Scene.v().getField("<java.lang.System: java.io.PrintStream out>");
        AssignStmt sysOutAssignStmt = Jimple.v().newAssignStmt(psLocal, Jimple.v().newStaticFieldRef(sysOutField.makeRef()));
        generatedUnits.add(sysOutAssignStmt);

        // Create println method call and provide its parameter
        SootMethod printlnMethod = Scene.v().grabMethod("<java.io.PrintStream: void println(java.lang.String)>");
        Value printlnParamter = StringConstant.v(content);
        InvokeStmt printlnMethodCallStmt = Jimple.v().newInvokeStmt(Jimple.v().newVirtualInvokeExpr(psLocal, printlnMethod.makeRef(), printlnParamter));
        generatedUnits.add(printlnMethodCallStmt);

        return generatedUnits;

    }


    public static void main(String[] args) throws IOException {
        if (System.getenv().containsKey("ANDROID_HOME"))
            androidJar = System.getenv("ANDROID_HOME") + File.separator + "platforms";

        if (args[0].contains("dump"))
        {
            dump = true;
            apkPath = args[1];

            if (args.length > 3)
                outputPath = args[2];
        }

        else if (args[0].equals("instrument"))
        {
            instrument = true;
            apkPath = args[1];
            jsonReader(args[2], "training");
            jsonReader(args[3], "testing");

            if (args.length > 4)
                outputPath = args[4];
        }
        else if (args[0].equals("auto_instrument"))
        {
            auto_instrument = true;

            apkPath = args[1];
            if (args.length > 2)
                outputPath = args[2];
        }

        Path path = Paths.get(apkPath);
        String tempFileName = path.getFileName().toString();
        String outDirName = tempFileName.split(".apk")[0];
        outputPath = outputPath + "/" + outDirName;
        File outdir = new File(outputPath);

        String package_name = InstrumentUtil.getPackageName(apkPath);

        // Clean the outputPath
        final File[] files = outdir.listFiles();
        if (files != null && files.length > 0) {
            Arrays.asList(files).forEach(File::delete);
        }

        if (!outdir.exists())
            outdir.mkdir();

        try {
            runAnalysis(apkPath, androidJar);
        } catch (Exception e) {
            e.printStackTrace();
        }

        InstrumentUtil.setupSoot(androidJar, apkPath, outputPath);
        // Add a transformation pack in order to add the statement "System.out.println(<content>) at the beginning of each Application method
        PackManager.v().getPack("jtp").add(new Transform("jtp.myLogger", new BodyTransformer() {
            @Override
            protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
                String instrumentationTAG;

                // First we filter out Android framework methods
                if (InstrumentUtil.isAndroidMethod(b.getMethod()))
                    return;

                JimpleBody body = (JimpleBody) b;

                String declaring_class = body.getMethod().getDeclaringClass().toString();
                String methodName = body.getMethod().getName();
                String methodSignature = body.getMethod().getSignature();


                if (!declaring_class.contains(package_name) || methodName.contains("init") || methodName.contains(".R"))
                    return;


                if (dump) {

                    if (methodDetailsList.get(methodSignature) == null)
                        methodDetailsList.put(methodSignature, new ArrayList<String>());

                    Iterator<Unit> i = body.getUnits().snapshotIterator();
                    int id = 0;

                    while (i.hasNext()) {
                        if (methodSignature.contains("com.github.cetoolbox.fragments.tabs.ViscosityActivity$2"))
                            System.out.println("Id: " + id);
                        Stmt stmt = (Stmt) i.next();
                        String stmtString = Integer.toString(id) + ":" + stmt.toString();
                        methodDetailsList.get(methodSignature).add(stmtString);
                        id = id + 1;
                    }
                }

                if (instrument == true || auto_instrument == true) {

                    String hashMapKey = methodSignature;

                    if (trainingData.containsKey(hashMapKey))
                        instrumentationTAG = "TRAIN DATA";

                    else if (testingData.containsKey(hashMapKey))
                        instrumentationTAG = "TEST DATA";
                    else
                        instrumentationTAG = "NO INSTRUMENT";


                    if (instrumentationTAG.equals("TEST DATA") || instrumentationTAG.equals("TRAIN DATA") || auto_instrument == true) {

                        UnitPatchingChain units = body.getUnits();
                        //List<Unit> generatedUnits = new ArrayList<>();

                        Iterator<Unit> i = body.getUnits().snapshotIterator();
                        Stmt firstNonIdentityStatement = body.getFirstNonIdentityStmt();

                        boolean flag = false;
                        double dbl_targetId;
                        int targetId = -1;
                        int id = 0;

                        while (i.hasNext()) {
                            Stmt stmt = (Stmt) i.next();

                            if (auto_instrument == true) {
                                if (stmt.toString().contains("openConnection(") || stmt.toString().contains("javax.net.ssl") || stmt.toString().contains("AdRequest(") || stmt.toString().contains("sendTextMessage") ||stmt.toString().contains("javax.crypto")) {
                                    List<Unit> generatedUnits = generateInstrumentedString("auto", hashMapKey, body, Integer.toString(id));
                                    units.insertBefore(generatedUnits, stmt);

                                    if (instrumentationDetails.get(hashMapKey) == null)
                                        instrumentationDetails.put(hashMapKey, new ArrayList<String>());

                                    String stmtString = Integer.toString(id) + ":" + stmt.toString();
                                    instrumentationDetails.get(hashMapKey).add(stmtString);
                                }
                            } else {

                                if (stmt == firstNonIdentityStatement)
                                    flag = true;

                                if (trainingData.containsKey(hashMapKey)) {
                                    targetId = Integer.parseInt(trainingData.get(hashMapKey));
                                }

                                if (testingData.containsKey(hashMapKey)) {
                                    targetId = Integer.parseInt(testingData.get(hashMapKey));
                                }

                                if (id == targetId && flag == false) {
                                    //System.out.println(firstNonIdentityStatement);
                                    List<Unit> generatedUnits = generateInstrumentedString(instrumentationTAG, hashMapKey, body, Integer.toString(id));
                                    units.insertBefore(generatedUnits, firstNonIdentityStatement);
                                    break;
                                }

                                if (id == targetId && flag == true) {
                                    //System.out.println(stmt);
                                    List<Unit> generatedUnits = generateInstrumentedString(instrumentationTAG, hashMapKey, body, Integer.toString(id));
                                    units.insertBefore(generatedUnits, stmt);
                                    break;
                                }
                            }

                            id = id + 1;
                        }

                        // Validate the body to ensure that our code injection does not introduce any problem (at least statically)
                        //System.out.println(b);
                        b.validate();

                    }
                }
            }
        }));
        // Run Soot packs (note that our transformer pack is added to the phase "jtp")
        PackManager.v().runPacks();
        // Write the result of packs in outputPath
        PackManager.v().writeOutput();
        if (dump)
            jsonWriter(idFilePath, methodDetailsList);

        if (auto_instrument) {
            String jsonFilePath = outputPath + File.separator + "/goal_statements.json";
            jsonWriter(jsonFilePath, instrumentationDetails);
        }
    }

}