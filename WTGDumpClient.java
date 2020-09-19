/**
 * JM- modified version of WTGDemoClient that just dumps WTG to dot file
*/

package presto.android.gui.clients;

import presto.android.Configs;
import presto.android.Logger;
import presto.android.gui.GUIAnalysisClient;
import presto.android.gui.GUIAnalysisOutput;
import presto.android.gui.clients.energy.VarUtil;
import presto.android.gui.wtg.EventHandler;
import presto.android.gui.wtg.StackOperation;
import presto.android.gui.wtg.WTGAnalysisOutput;
import presto.android.gui.wtg.WTGBuilder;
import presto.android.gui.wtg.ds.WTG;
import presto.android.gui.wtg.ds.WTGEdge;
import presto.android.gui.wtg.ds.WTGNode;
import soot.SootMethod;
import java.util.Collection;

public class WTGDumpClient implements GUIAnalysisClient {
  @Override
  public void run(GUIAnalysisOutput output) {
    VarUtil.v().guiOutput = output;
    WTGBuilder wtgBuilder = new WTGBuilder();
    wtgBuilder.build(output);
    WTGAnalysisOutput wtgAO = new WTGAnalysisOutput(output, wtgBuilder);
    WTG wtg = wtgAO.getWTG();

    Collection<WTGEdge> edges = wtg.getEdges();
    Collection<WTGNode> nodes = wtg.getNodes();


    Logger.verb("DEMO", "Application: " + Configs.benchmarkName);
    Logger.verb("DEMO", "Launcher Node: " + wtg.getLauncherNode());

   
    Logger.verb("DEMO", "FINALLY");
    wtg.dump();
    Logger.verb("DEMO", "DUMPED");

  }
}
