package dev.navids.soottutorial.android;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import soot.*;
import soot.jimple.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;



public class AndroidLogger {

    private final static String USER_HOME = System.getProperty("user.home");
    private static String androidJar = USER_HOME + "/Library/Android/sdk/platforms";
    static String androidDemoPath = System.getProperty("user.dir") + File.separator + "demo" + File.separator + "Android";
    static String apkPath = androidDemoPath + File.separator + "/opensudoku-sdk-22.apk";
    static String outputPath = androidDemoPath + File.separator + "/Instrumented";
    static String idFilePath = outputPath + File.separator + "/JimpleIR.id";
    private static Map<String, List<String>> methodDetailsList = new HashMap<>();
    static boolean dump = false;
    static boolean instrument = false;
    static Map<String, String> trainingData = new HashMap<String, String>();
    static Map<String, String> testingData = new HashMap<String, String>();



    public static void jsonWriter()
    {
        Gson gson = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
        try(FileWriter writer = new FileWriter(idFilePath))
        {
            gson.toJson(methodDetailsList,writer);

            writer.close();
        }
        catch(IOException e)
        {
            e.printStackTrace();
        }
    }

    public static void jsonReader(String filePath, String dataType){
        try {
            // create Gson instance
            Gson gson = new Gson();

            // create a reader
            Reader reader = Files.newBufferedReader(Paths.get(filePath));

            // convert JSON file to map
            if (dataType.equals("training"))
                trainingData = gson.fromJson(reader, new TypeToken<Map<String, String>>(){}.getType());
            else
                testingData = gson.fromJson(reader, new TypeToken<Map<String, String>>(){}.getType());

            // close reader
            reader.close();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static void main(String[] args){
        if(System.getenv().containsKey("ANDROID_HOME"))
            androidJar = System.getenv("ANDROID_HOME")+ File.separator+"platforms";

        for (String s: args) {
            if (s.equals("dump"))
                dump = true;

            if (s.equals("instrument"))
                instrument = true;
            if (s.contains(".apk"))
                apkPath = s;
            if (s.contains("train.json")){
                jsonReader(s, "training");
            }
            if (s.contains("test.json")){
                jsonReader(s, "testing");
            }
        }


        String package_name = InstrumentUtil.getPackageName(apkPath);
        // Clean the outputPath
        final File[] files = (new File(outputPath)).listFiles();
        if (files != null && files.length > 0) {
            Arrays.asList(files).forEach(File::delete);
        }
        // Initialize Soot
        InstrumentUtil.setupSoot(androidJar, apkPath, outputPath);


        // Add a transformation pack in order to add the statement "System.out.println(<content>) at the beginning of each Application method
        PackManager.v().getPack("jtp").add(new Transform("jtp.myLogger", new BodyTransformer() {
            @Override
            protected void internalTransform(Body b, String phaseName, Map<String, String> options) {
                // First we filter out Android framework methods
                if(InstrumentUtil.isAndroidMethod(b.getMethod()))
                    return;

                JimpleBody body = (JimpleBody) b;

                String declaring_class = b.getMethod().getDeclaringClass().toString();
                String methodName = b.getMethod().getName();
                String methodSignature = body.getMethod().getSignature();


                if (!declaring_class.contains(package_name) || methodName.contains("init") || methodName.contains(".R"))
                    return;


                if (dump){

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

                if (instrument == true) {
                    UnitPatchingChain units = b.getUnits();
                    List<Unit> generatedUnits = new ArrayList<>();

                    // The message that we want to log

                    String hashMapKey = methodSignature;
                    if (trainingData.containsKey(hashMapKey))
                        InstrumentUtil.TAG = "TRAIN DATA";

                    else if (testingData.containsKey(hashMapKey))
                        InstrumentUtil.TAG = "TEST DATA";
                    else
                        InstrumentUtil.TAG = "NO INSTRUMENT";


                    if (InstrumentUtil.TAG.equals("TEST DATA") || InstrumentUtil.TAG.equals("TRAIN DATA")) {
                        String content;
                        if (InstrumentUtil.TAG.equals("TEST DATA")) {
                            String goalState = hashMapKey + " : " + testingData.get(hashMapKey);
                            content = String.format("%s : Goal instruction in %s reached\n", "TEST DATA", goalState);
                        }
                        else{
                            String goalState = hashMapKey + " : " + testingData.get(hashMapKey);
                            content = String.format("%s : Goal instruction in %s reached\n", "TRAIN DATA", goalState);
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

                        Iterator<Unit> i = body.getUnits().snapshotIterator();
                        Stmt firstNonIdentityStatement = body.getFirstNonIdentityStmt();

                        boolean flag = false;
                        double dbl_targetId;
                        int targetId = -1;
                        int id = 0;
                        while (i.hasNext()) {
                            Stmt stmt = (Stmt) i.next();

                            if (stmt == firstNonIdentityStatement)
                                flag = true;

                            if (trainingData.containsKey(hashMapKey)) {
                                targetId = Integer.parseInt(trainingData.get(hashMapKey));
                            }

                            if (testingData.containsKey(hashMapKey)) {
                                targetId = Integer.parseInt(testingData.get(hashMapKey));
                            }

                            if (id == targetId && flag == false) {
                                System.out.println(firstNonIdentityStatement);
                                units.insertBefore(generatedUnits, firstNonIdentityStatement);
                                break;
                            }

                            if (id == targetId && flag == true) {
                                System.out.println(stmt);
                                units.insertBefore(generatedUnits, stmt);
                                break;
                            }

                            id = id + 1;
                        }

                        // Validate the body to ensure that our code injection does not introduce any problem (at least statically)
                        System.out.println(b);
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
            jsonWriter();
    }

}