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

class ClickVisitor extends AxmlVisitor{
    private String file;
    private int id;
    private boolean setId;
    private String onClick;
    private boolean setOnClick;
    public ClickVisitor(String file){
	this.file=file;
	this.setId=false;
	this.setOnClick=false;
    }
    @Override
    public void attr(String ns, String name, int resourceId, int type, Object obj) {
	//super.attr(ns, name, resourceId, type, obj);
	if(ns!=null&&ns.equals("http://schemas.android.com/apk/res/android")){
	    if(name.equals("onClick")){
		this.onClick=(String)obj;
		this.setOnClick=true;
	    }else if(name.equals("id")){
		this.id=(Integer)obj;
		this.setId=true;
	    }
	}
	//System.out.printf("%s ATTR %s %s %d %d %s\n",level,ns,name,resourceId,type,obj.toString());
    }
    @Override
    public void end(){
	if(this.setOnClick){
	    if(!this.setId){
		System.err.printf("ERROR: onClick set without ID in %s\n",this.file);
	    }else{
		System.out.printf("%s %d %s\n",this.file,this.id,this.onClick);
	    }
	}
	//System.out.printf("%s ATTR %s %s %d %d %s\n",level,ns,name,resourceId,type,obj.toString());
    }
    @Override
    public NodeVisitor child(String ns, String name) {
	return new ClickVisitor(this.file);
    }
}

public class AndroidLayoutOnClick {

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
			if((fileName.startsWith("res/layout")||fileName.contains("AndroidManifest"))&&fileName.endsWith(".xml")){
			    System.out.println(fileName);
			    InputStream stream = zipFile.getInputStream(entry);
			    //String str = IOUtils.toString(stream,StandardCharsets.UTF_8);
			    byte[] byteArray = IOUtils.toByteArray(stream);
			    //System.out.printf("Length: %d bytes\n",byteArray.length);
			    //System.out.printf("%s\n",new String(byteArray));
			    AxmlReader xmlReader = new AxmlReader(byteArray);
			    //System.out.println(str);
			    //Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(stream);
			    //Element root = doc.getDocumentElement();
			    //System.out.println(root);
			    xmlReader.accept(new ClickVisitor(fileName));
			}
		    }
		}catch(Exception e){
		    e.printStackTrace();
		}
	}

}
