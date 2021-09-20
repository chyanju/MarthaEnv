import java.io.File;
import java.io.InputStream;
import java.util.Enumeration;

import java.util.zip.ZipFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;

import org.apache.commons.io.IOUtils;
import java.nio.charset.StandardCharsets;

import pxb.android.axml.AxmlReader;
import pxb.android.axml.AxmlVisitor;
import pxb.android.axml.NodeVisitor;

class MyVisitor extends AxmlVisitor{
    private String level;
    public MyVisitor(String level){
	this.level=level;
    }
    @Override
    public void attr(String ns, String name, int resourceId, int type, Object obj) {
	super.attr(ns, name, resourceId, type, obj);
	System.out.printf("%s ATTR %s %s %d %d\n",level,ns,name,resourceId,type);
    }
    @Override
    public void line(int ln) {
	super.line(ln);
	System.out.printf("%s LINE %d\n",level,ln);
    }
    @Override
				    
    public void text(int lineNumber, String value) {
	super.text(lineNumber,value);
	System.out.printf("%s TEXT %d %s\n",level,lineNumber,value);
    }
    @Override
    public void end(){
	System.out.printf("%s END\n",level);
    }
    @Override
    public NodeVisitor child(String ns, String name) {
	System.out.printf("%sCHILD %s:%s\n",level,ns,name);
	super.child(ns,name);
	return new MyVisitor(this.level+">");
    }
}

public class AndroidLayout {

	public static void main(String[] args) {
		
		if(args.length<1) {
		    System.out.printf("Usage: java AndroidLayout path-to-apk\n");
		    System.exit(1);
		}
		String apkPath = args[0];
		File apkFile = new File(apkPath);
		if(!apkFile.exists()){
		    throw new RuntimeException("file '"+apkPath+"' not found\n");
		}
		try(ZipFile zipFile = new ZipFile(apkFile)){
		    Enumeration<? extends ZipEntry> entries = zipFile.entries();
		    while(entries.hasMoreElements()){
			ZipEntry entry = entries.nextElement();
			String fileName = entry.getName();
			if(fileName.startsWith("res/layout")&&fileName.endsWith(".xml")){
			    System.out.println(fileName);
			    InputStream stream = zipFile.getInputStream(entry);
			    //String str = IOUtils.toString(stream,StandardCharsets.UTF_8);
			    byte[] byteArray = IOUtils.toByteArray(stream);
			    System.out.printf("Length: %d bytes\n",byteArray.length);
			    //System.out.printf("%s\n",new String(byteArray));
			    AxmlReader xmlReader = new AxmlReader(byteArray);
			    //System.out.println(str);
			    //Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stream);
			    //Element root = doc.getDocumentElement();
			    //System.out.println(root);
			    xmlReader.accept(new MyVisitor(""));
			}
		    }
		}catch(Exception e){
		    e.printStackTrace();
		}
	}

}
