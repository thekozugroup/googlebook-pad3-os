import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.Map;

public final class FeatureConfigBoundaryTest {
    static final List<String> events=new ArrayList<>();
    static boolean enter=true,reset=true,failWrite=false;
    static String label;
    static int checks;
    interface Checked {void run()throws Exception;}
    static void require(boolean ok){if(!ok)throw new AssertionError();checks++;}
    static Throwable rejected(Checked action)throws Exception {
        try{action.run();}catch(Exception expected){checks++;return expected;}
        throw new AssertionError("expected refusal");
    }
    public static final class Labels {
        public static String getFileContext(String path){events.add("read");return label;}
        public static boolean setFSCreateContext(String value){events.add(value==null?"reset":"enter");return value==null?reset:enter;}
    }
    public static final class MissingLabels {}
    public static final class Writer {
        public void publish(){events.add("write");if(failWrite)throw new IllegalStateException("injected writer failure");}
    }
    public static final class FlagValue {
        final String name,value;
        final int type,marker,source;
        public FlagValue(String name,String value,int type,int marker,int source) {
            this.name=name;this.value=value;this.type=type;this.marker=marker;this.source=source;
        }
    }
    public static final class ReadTransaction {}
    public static final class Token {
        public long i=42;
    }
    static final Token token=new Token();
    static final Map<String,Object> effectiveValues=new HashMap<>();
    public static final class Tokens {
        public static String d(String config,String account,ReadTransaction tx,boolean committed){return "fixture-token";}
        public static Token a(String value,boolean strict){return token;}
    }
    public static final class EffectiveValues {
        public static Map<String,Object> g(ReadTransaction tx,String config,long state){return effectiveValues;}
    }
    static final ClassLoader nativeFixture=new ClassLoader() {
        @Override public Class<?> loadClass(String name)throws ClassNotFoundException {
            if(name.equals("fyvx"))return Tokens.class;
            if(name.equals("fyua"))return EffectiveValues.class;
            return super.loadClass(name);
        }
    };
    static void ensureBoundaries(NativeConfigRepair repair,Object flags)throws Exception {
        int n=repair.FLAGS.length;
        require(repair.stagingRequired("ensure",0,0,0));
        for(String mode:new String[]{"rehearse","stage-publish"}) {
            require(repair.stagingRequired(mode,0,0,0));
            rejected(()->repair.stagingRequired(mode,n,n,n));
        }
        for(int count=1;count<n;count++) {
            final int partial=count;
            rejected(()->repair.stagingRequired("ensure",partial,partial,partial));
        }
        rejected(()->repair.stagingRequired("ensure",n,n,n-1)); // Duplicate name, missing flag.
        rejected(()->repair.stagingRequired("ensure",n+1,n+1,n));
        for(int count=0;count<n;count++) {
            final int valid=count;
            rejected(()->repair.stagingRequired("ensure",n,valid,n));
        }
        effectiveValues.clear();
        for(int i=0;i<n;i++)effectiveValues.put(repair.FLAGS[i],java.lang.reflect.Array.get(flags,i));
        for(int run=0;run<3;run++) {
            require(!repair.stagingRequired("ensure",n,n,n));
            repair.effective(nativeFixture,ReadTransaction.class,new ReadTransaction(),flags);
        }
        for(String name:repair.FLAGS) {
            Object value=effectiveValues.remove(name);
            // Complete active rows cannot authorize publication when the selected state's links were dropped.
            require(!repair.stagingRequired("ensure",n,n,n));
            rejected(()->repair.effective(nativeFixture,ReadTransaction.class,new ReadTransaction(),flags));
            effectiveValues.put(name,new FlagValue(name,"false",2,0,0));
            rejected(()->repair.effective(nativeFixture,ReadTransaction.class,new ReadTransaction(),flags));
            effectiveValues.put(name,value);
        }
        effectiveValues.put("45811904",new Object());
        rejected(()->repair.effective(nativeFixture,ReadTransaction.class,new ReadTransaction(),flags));
        effectiveValues.remove("45811904");
        token.i=0;
        try {rejected(()->repair.effective(nativeFixture,ReadTransaction.class,new ReadTransaction(),flags));}
        finally {token.i=42;}
    }
    static void publish(Class<?> api)throws Exception {
        NativeConfigRepair.publishWithFileContext(api,"fixture.db",Writer.class.getMethod("publish"),new Writer());
    }
    static void baseline(){events.clear();enter=true;reset=true;failWrite=false;label="u:object_r:privapp_data_file:s0:c100,c200";}
    public static void main(String[] args)throws Exception {
        NativeConfigRepair ambient=new NativeConfigRepair("ambient"),receiver=new NativeConfigRepair("receiver-settings");
        require(ambient.CONFIG.equals("com.google.ambient.streaming#com.google.ambient.streaming"));
        require(ambient.OWNER.equals("com.google.ambient.streaming"));
        require(Arrays.equals(ambient.FLAGS,new String[]{"45788784","45726908","45794909","45805241"}));
        require(receiver.CONFIG.equals("com.google.android.gms.multidevice#com.google.android.gms"));
        require(receiver.OWNER.equals("com.google.android.gms"));
        require(Arrays.equals(receiver.FLAGS,new String[]{"45742359","45784133"}));
        for(String profile:new String[]{"ambient","receiver-settings"}) {
            NativeConfigRepair repair=new NativeConfigRepair(profile);
            for(String mode:new String[]{"rehearse","stage-publish","publish","ensure"})
                require(Arrays.equals(NativeConfigRepair.arguments(new String[]{"10","1012345",profile,mode}),new int[]{10,1012345}));
            Object flags=repair.flags(FlagValue.class);
            ensureBoundaries(repair,flags);
            require(java.lang.reflect.Array.getLength(flags)==repair.FLAGS.length);
            for(int i=0;i<repair.FLAGS.length;i++) {
                FlagValue flag=(FlagValue)java.lang.reflect.Array.get(flags,i);
                require(flag.name.equals(repair.FLAGS[i]) && flag.value.equals("true") && flag.type==2 && flag.marker==0 && flag.source==0);
            }
            require(repair.flagPlaceholders().equals(profile.equals("ambient")?"?,?,?,?":"?,?"));
            String[] scope=repair.scopeArguments("max-id","config-id");
            require(scope.length==repair.FLAGS.length+2 && scope[0].equals("max-id") && scope[1].equals("config-id"));
            require(Arrays.equals(Arrays.copyOfRange(scope,2,scope.length),repair.FLAGS));
            require(Arrays.equals(repair.scopeArguments("config-id"),
                    profile.equals("ambient")?new String[]{"config-id","45788784","45726908","45794909","45805241"}
                            :new String[]{"config-id","45742359","45784133"}));
            for(String forbidden:new String[]{"45811904","45815974","45742360","45768040","45784134","45748174","45748175"})
                require(!Arrays.asList(repair.FLAGS).contains(forbidden));
        }
        for(String[] invalid:new String[][]{{},{"1012345","publish"},{"10","1012345","publish"},
                {"0","12345","ambient","publish"},{"10","112345","ambient","publish"},
                {"10","0","ambient","publish"},{"10","1099000","ambient","publish"},
                {"-1","1012345","ambient","publish"},{"10","1012345","ambient","unknown"},
                {"10","1012345","unknown","publish"},{"10","1012345","","publish"},
                {"10","1012345","receiver-settings' OR 1=1","publish"},
                {"10","1012345","ambient","publish","extra"}})
            rejected(()->NativeConfigRepair.arguments(invalid));
        rejected(()->new NativeConfigRepair("unknown"));
        File input=File.createTempFile("unsupported-gms-",".apk");
        try {Files.write(input.toPath(),new byte[]{1,2,3});rejected(()->NativeConfigRepair.verifyArtifact(input));}
        finally {Files.delete(input.toPath());}
        baseline();publish(Labels.class);require(events.equals(Arrays.asList("read","enter","write","reset")));
        baseline();enter=false;rejected(()->publish(Labels.class));require(events.equals(Arrays.asList("read","enter","reset")));
        baseline();failWrite=true;rejected(()->publish(Labels.class));require(events.equals(Arrays.asList("read","enter","write","reset")));
        baseline();reset=false;rejected(()->publish(Labels.class));require(events.get(events.size()-1).equals("reset"));
        baseline();reset=false;failWrite=true;Throwable failure=rejected(()->publish(Labels.class));require(failure.getSuppressed().length==1);
        baseline();label=null;rejected(()->publish(Labels.class));require(events.equals(Arrays.asList("read")));
        baseline();label="u:object_r:privapp_data_file:s0";rejected(()->publish(Labels.class));require(events.equals(Arrays.asList("read")));
        baseline();label="u:object_r:unrelated_file:s0:c100";rejected(()->publish(Labels.class));require(events.equals(Arrays.asList("read")));
        baseline();rejected(()->publish(MissingLabels.class));require(events.isEmpty());
        System.out.println("FEATURE_CONFIG_BOUNDARIES_PASS checks="+checks);
    }
}
