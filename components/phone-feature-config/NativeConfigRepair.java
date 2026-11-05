import android.content.Context;
import android.content.ContextWrapper;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.Looper;
import android.system.Os;
import java.io.*;
import java.lang.reflect.*;
import java.security.MessageDigest;
import java.util.*;

public final class NativeConfigRepair {
    final String CONFIG,OWNER;
    final String[] FLAGS;
    NativeConfigRepair(String profile) {
        switch(profile) {
            case "ambient":
                CONFIG="com.google.ambient.streaming#com.google.ambient.streaming";
                OWNER="com.google.ambient.streaming";
                FLAGS=new String[]{"45788784","45726908","45794909","45805241"};
                break;
            case "receiver-settings":
                CONFIG="com.google.android.gms.multidevice#com.google.android.gms";
                OWNER="com.google.android.gms";
                FLAGS=new String[]{"45742359","45784133"};
                break;
            default:throw new IllegalStateException("unsupported profile");
        }
    }
    static final long GMS_VERSION=264330035L;
    static final String GMS_SHA256="8395c70a5e4ffbe2712aea7e1045d700b282f0a67d19b80686c595c991f12112";
    static int[] arguments(String[] args) {
        check(args.length==4 && Arrays.asList("ambient","receiver-settings").contains(args[2])
                && Arrays.asList("rehearse","stage-publish","publish","ensure").contains(args[3]),
                "usage: Android-user actual-GMS-UID ambient|receiver-settings rehearse|stage-publish|publish|ensure");
        int user=Integer.parseInt(args[0]),uid=Integer.parseInt(args[1]);
        check(user>0 && uid>0 && uid/100000==user && uid%100000>=10000 && uid%100000<20000,
                "explicit secondary Android user and matching application UID required");
        return new int[]{user,uid};
    }
    static String fileHash(File file)throws Exception {
        MessageDigest hash=MessageDigest.getInstance("SHA-256");
        try(InputStream input=new FileInputStream(file)) {
            byte[] buffer=new byte[65536];int size;
            while((size=input.read(buffer))!=-1)hash.update(buffer,0,size);
        }
        StringBuilder text=new StringBuilder();for(byte b:hash.digest())text.append(String.format("%02x",b&255));
        return text.toString();
    }
    static void verifyArtifact(File file)throws Exception {
        check(fileHash(file).equals(GMS_SHA256),"unsupported GMS base SHA-256");
    }
    static void publishWithFileContext(Class<?> selinux,String database,Method publish,Object writer)throws Exception {
        Method get=selinux.getMethod("getFileContext",String.class);
        Method set=selinux.getMethod("setFSCreateContext",String.class);
        String label=(String)get.invoke(null,database);
        check(label!=null && label.matches("u:object_r:privapp_data_file:s0:c[0-9]+(,c[0-9]+)*"),
                "existing GMS database object label required");
        Throwable failure=null;
        try {
            check(Boolean.TRUE.equals(set.invoke(null,label)),"file creation context rejected");
            publish.invoke(writer);
        }catch(Exception|Error error){failure=error;throw error;}
        finally {
            try {check(Boolean.TRUE.equals(set.invoke(null,(Object)null)),"file creation context reset failed");}
            catch(Exception|Error reset){if(failure!=null)failure.addSuppressed(reset);else throw reset;}
        }
    }
    String flagPlaceholders(){return String.join(",",Collections.nCopies(FLAGS.length,"?"));}
    String[] scopeArguments(String... prefix) {
        String[] args=Arrays.copyOf(prefix,prefix.length+FLAGS.length);
        System.arraycopy(FLAGS,0,args,prefix.length,FLAGS.length);return args;
    }
    boolean stagingRequired(String mode,long active,long valid,long names) {
        if(mode.equals("ensure") && active!=0) {
            check(active==FLAGS.length && valid==active && names==active,"existing anonymous overrides need review");
            return false;
        }
        check(active==0,"existing anonymous overrides need review");return true;
    }
    boolean stagingRequired(SQLiteDatabase db,String id,String mode) {
        try(Cursor c=db.rawQuery("SELECT count(*),coalesce(sum(CASE WHEN type=2 AND value=1 AND typeof(value)='integer' AND source=0 THEN 1 ELSE 0 END),0),count(DISTINCT name) FROM flag_overrides WHERE config_package_id=? AND account_id=0 AND active=1 AND name IN ("+flagPlaceholders()+")",scopeArguments(id))) {
            check(c.moveToFirst(),"missing override counts");return stagingRequired(mode,c.getLong(0),c.getLong(1),c.getLong(2));
        }
    }
    static final class UserContext extends ContextWrapper {
        UserContext(Context base){super(base);}
        @Override public Context getApplicationContext(){return this;}
    }
    static void check(boolean ok,String message){if(!ok)throw new IllegalStateException(message);}
    static long number(SQLiteDatabase db,String sql,String... args) {
        try(Cursor c=db.rawQuery(sql,args)){check(c.moveToFirst(),"missing scalar");return c.getLong(0);}
    }
    static String fingerprint(SQLiteDatabase db,String sql,String... args)throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(Cursor c=db.rawQuery(sql,args)) {
            while(c.moveToNext()) {
                ByteArrayOutputStream bytes=new ByteArrayOutputStream();DataOutputStream out=new DataOutputStream(bytes);
                out.writeInt(c.getColumnCount());
                for(int i=0;i<c.getColumnCount();i++) {
                    int type=c.getType(i);out.writeInt(type);
                    if(type==Cursor.FIELD_TYPE_NULL)continue;
                    byte[] value=type==Cursor.FIELD_TYPE_BLOB?c.getBlob(i):c.getString(i).getBytes(java.nio.charset.StandardCharsets.UTF_8);
                    out.writeInt(value.length);out.write(value);
                }
                byte[] row=bytes.toByteArray();digest.update(java.nio.ByteBuffer.allocate(4).putInt(row.length).array());digest.update(row);
            }
        }
        StringBuilder text=new StringBuilder();for(byte b:digest.digest())text.append(String.format("%02x",b&255));return text.toString();
    }
    long state(ClassLoader loader,Class<?> qo,Object tx)throws Exception {
        Class<?> vx=loader.loadClass("fyvx");
        Object token=vx.getMethod("d",String.class,String.class,qo,boolean.class).invoke(null,CONFIG,"",tx,false);
        check(token instanceof String && !((String)token).isEmpty(),"genuine token missing");
        Object parsed=vx.getMethod("a",String.class,boolean.class).invoke(null,token,true);
        check(parsed!=null,"genuine token invalid");return parsed.getClass().getField("i").getLong(parsed);
    }
    Object flags(Class<?> flag)throws Exception {
        Object values=Array.newInstance(flag,FLAGS.length);
        Constructor<?> constructor=flag.getConstructor(String.class,String.class,int.class,int.class,int.class);
        for(int i=0;i<FLAGS.length;i++)Array.set(values,i,constructor.newInstance(FLAGS[i],"true",2,0,0));return values;
    }
    void effective(ClassLoader loader,Class<?> qo,Object tx,Object expected)throws Exception {
        long state=state(loader,qo,tx);check(state>0,"anonymous state absent");
        Map<?,?> values=(Map<?,?>)loader.loadClass("fyua").getMethod("g",qo,String.class,long.class).invoke(null,tx,CONFIG,state);
        for(int i=0;i<FLAGS.length;i++)check(Array.get(expected,i).equals(values.get(FLAGS[i])),"effective flag mismatch "+FLAGS[i]);
        check(!values.containsKey("45811904"),"diagnostic unexpectedly persisted");
        System.out.println("NATIVE_EFFECTIVE_FEATURES_PASS state="+state);
    }
    Object request(ClassLoader loader)throws Exception {
        Class<?> nested=loader.loadClass("insq"),outer=loader.loadClass("inrx");
        Object builder=nested.getMethod("w").invoke(nested.getField("a").get(null));builder.getClass().getMethod("O").invoke(builder);
        Object message=builder.getClass().getField("b").get(builder);nested.getField("b").setInt(message,nested.getField("b").getInt(message)|1);nested.getField("c").set(message,CONFIG);
        Object config=builder.getClass().getMethod("J").invoke(builder);
        builder=outer.getMethod("w").invoke(outer.getField("a").get(null));builder.getClass().getMethod("O").invoke(builder);
        message=builder.getClass().getField("b").get(builder);outer.getField("b").setInt(message,outer.getField("b").getInt(message)|1);outer.getField("c").set(message,config);
        return builder.getClass().getMethod("J").invoke(builder);
    }
    public static void main(String[] args) {
        try {
            int[] identity=arguments(args);
            NativeConfigRepair repair=new NativeConfigRepair(args[2]);
            Os.setgid(identity[1]);Os.setuid(identity[1]);repair.run(identity[0],identity[1],args[3]);System.exit(0);
        }catch(Throwable e){while(e instanceof InvocationTargetException && e.getCause()!=null)e=e.getCause();
            System.err.println("NATIVE_CONFIG_REPAIR_ERROR "+e.getClass().getName());System.exit(1);}
    }
    String registeredConfig(SQLiteDatabase db) {
        try(Cursor c=db.rawQuery("SELECT c.config_package_id,a.name,length(a.secret) FROM config_packages c JOIN android_packages a USING(android_package_id) WHERE c.name=?",new String[]{CONFIG})) {
            check(c.moveToFirst() && c.getString(1).equals(OWNER) && c.getInt(2)>0,"registered owner/secret missing");
            String id=c.getString(0);check(!c.moveToNext(),"ambiguous namespace");
            check(number(db,"SELECT account_id FROM accounts WHERE name='' ")==0,"anonymous account mismatch");
            check(number(db,"SELECT count(*) FROM experiment_states WHERE config_package_id=? AND account_id=0",id)>0,"existing anonymous state required");
            return id;
        }
    }
    void run(int userId,int expectedUid,String mode)throws Exception {
        String DB="/data/user/"+userId+"/com.google.android.gms/databases/phenotype.db";
        Looper.prepareMainLooper();Object thread=Class.forName("android.app.ActivityThread").getMethod("systemMain").invoke(null);
        Context system=(Context)thread.getClass().getMethod("getSystemContext").invoke(thread);
        Class<?> handle=Class.forName("android.os.UserHandle");Object user=handle.getMethod("of",int.class).invoke(null,userId);
        Context context=new UserContext((Context)Context.class.getMethod("createPackageContextAsUser",String.class,int.class,handle)
                .invoke(system,"com.google.android.gms",Context.CONTEXT_INCLUDE_CODE|Context.CONTEXT_IGNORE_SECURITY,user));
        check(context.getPackageName().equals("com.google.android.gms") && Os.getuid()==context.getApplicationInfo().uid && Os.getuid()==expectedUid,"real GMS identity required");
        check(!context.isDeviceProtectedStorage() && context.getDatabasePath("phenotype.db").getCanonicalPath().equals(DB),"exact CE context required");
        check(context.getPackageManager().getPackageInfo("com.google.android.gms",0).getLongVersionCode()==GMS_VERSION,"unsupported GMS version");
        verifyArtifact(new File(context.getApplicationInfo().sourceDir));
        ClassLoader loader=context.getClassLoader();loader.loadClass("hjmc").getMethod("d",Context.class).invoke(null,context);
        Class<?> qz=loader.loadClass("fyqz"),rt=loader.loadClass("fyrt"),ru=loader.loadClass("fyru"),qo=loader.loadClass("fyqo"),qx=loader.loadClass("fyqx"),flag=loader.loadClass("com.google.android.gms.phenotype.Flag");
        Object expected=flags(flag);
        try(SQLiteDatabase db=SQLiteDatabase.openDatabase(DB,null,SQLiteDatabase.OPEN_READWRITE)) {
            check(db.getVersion()==1036,"unsupported schema");db.setForeignKeyConstraintsEnabled(true);
            try(Cursor c=db.rawQuery("PRAGMA foreign_key_check",null)){check(!c.moveToFirst(),"foreign key violation before operation");}
            Object wrapper=qz.getConstructor(SQLiteDatabase.class,rt,ru).newInstance(db,loader.loadClass("fyrs").getConstructor().newInstance(),ru.getConstructor().newInstance());
            if(!mode.equals("publish")) {
                Object tx=qz.getMethod("c").invoke(wrapper);String before=null;String id=null;boolean staged=false;
                try {
                    id=registeredConfig(db);
                    staged=stagingRequired(db,id,mode);
                    if(staged) {
                        long maxOverride=number(db,"SELECT coalesce(max(override_id),0) FROM flag_overrides");
                        long maxState=number(db,"SELECT coalesce(max(experiment_state_id),0) FROM experiment_states");
                        String packages=fingerprint(db,"SELECT * FROM config_packages ORDER BY config_package_id");
                        String registrations=fingerprint(db,"SELECT * FROM android_packages ORDER BY android_package_id");
                        String accounts=fingerprint(db,"SELECT * FROM accounts ORDER BY account_id");
                        String overrides=fingerprint(db,"SELECT * FROM flag_overrides WHERE override_id<=? ORDER BY override_id",String.valueOf(maxOverride));
                        String states=fingerprint(db,"SELECT * FROM experiment_states WHERE config_package_id=? AND experiment_state_id<=? ORDER BY experiment_state_id",id,String.valueOf(maxState));
                        before=fingerprint(db,"SELECT * FROM experiment_states WHERE config_package_id=? ORDER BY experiment_state_id",id)
                                +fingerprint(db,"SELECT * FROM flag_overrides WHERE config_package_id=? ORDER BY override_id",id);
                        loader.loadClass("fyvs").getMethod("a",qx,String.class,String.class,expected.getClass(),boolean.class).invoke(null,tx,CONFIG,"",expected,false);
                        check(packages.equals(fingerprint(db,"SELECT * FROM config_packages ORDER BY config_package_id")),"config pointers changed");
                        check(registrations.equals(fingerprint(db,"SELECT * FROM android_packages ORDER BY android_package_id")),"registrations changed");
                        check(accounts.equals(fingerprint(db,"SELECT * FROM accounts ORDER BY account_id")),"accounts changed");
                        check(overrides.equals(fingerprint(db,"SELECT * FROM flag_overrides WHERE override_id<=? ORDER BY override_id",String.valueOf(maxOverride))),"old overrides changed");
                        check(states.equals(fingerprint(db,"SELECT * FROM experiment_states WHERE config_package_id=? AND experiment_state_id<=? ORDER BY experiment_state_id",id,String.valueOf(maxState))),"old states changed");
                        check(number(db,"SELECT count(*) FROM flag_overrides WHERE override_id>?",String.valueOf(maxOverride))==FLAGS.length,"unexpected override insert count");
                        check(number(db,"SELECT count(*) FROM flag_overrides WHERE override_id>? AND config_package_id=? AND account_id=0 AND active=1 AND type=2 AND value=1 AND typeof(value)='integer' AND source=0 AND name IN ("+flagPlaceholders()+")",scopeArguments(String.valueOf(maxOverride),id))==FLAGS.length,"override scope/type/source mismatch");
                        check(number(db,"SELECT count(*) FROM experiment_states WHERE experiment_state_id>? AND NOT(config_package_id=? AND account_id=0)",String.valueOf(maxState),id)==0,"unexpected account state created");
                    }
                    // Active rows without current-state links must fail; the native setter deduplicates them.
                    effective(loader,qo,tx,expected);
                    try(Cursor c=db.rawQuery("PRAGMA foreign_key_check",null)){check(!c.moveToFirst(),"foreign key violation after operation");}
                    if(staged && !mode.equals("rehearse"))qo.getMethod("e").invoke(tx);
                }finally{qo.getMethod("close").invoke(tx);}
                if(staged && !mode.equals("rehearse"))System.out.println("NATIVE_PROFILE_STAGE_COMMITTED flags="+FLAGS.length);
                if(!staged)System.out.println("NATIVE_PROFILE_ALREADY_STAGED flags="+FLAGS.length);
                if(mode.equals("rehearse")) {
                    String after=fingerprint(db,"SELECT * FROM experiment_states WHERE config_package_id=? ORDER BY experiment_state_id",id)
                            +fingerprint(db,"SELECT * FROM flag_overrides WHERE config_package_id=? ORDER BY override_id",id);
                    check(before!=null && before.equals(after),"rollback fingerprint mismatch");System.out.println("NATIVE_REHEARSAL_ROLLBACK_PASS");return;
                }
            }
            Object read=qz.getMethod("a").invoke(wrapper);
            try {
                String id=registeredConfig(db);
                if(mode.equals("ensure"))check(!stagingRequired(db,id,mode),"staged overrides absent before publication");
                effective(loader,qo,read,expected);
                Object writer=loader.loadClass("fyxs").getConstructor(Context.class,long.class).newInstance(context,0L);
                try {
                    writer.getClass().getMethod("b",loader.loadClass("inrx"),String.class,String.class,qo)
                            .invoke(writer,request(loader),OWNER,"",read);
                    publishWithFileContext(Class.forName("android.os.SELinux"),DB,writer.getClass().getMethod("c"),writer);
                    System.out.println("NATIVE_PUBLISH_CALL_COMPLETED_VERIFY_SNAPSHOT_SEPARATELY");
                }finally{((AutoCloseable)writer).close();}
            }finally{qo.getMethod("close").invoke(read);}
        }
    }
}
