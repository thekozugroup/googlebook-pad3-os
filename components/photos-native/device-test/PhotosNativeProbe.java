package org.googlebook.pad3.probe;
import android.os.Build;
import android.content.pm.ApplicationInfo;
import com.android.internal.util.googlebook.PhotosCompat;
import java.lang.reflect.Field;
import org.json.JSONObject;
public final class PhotosNativeProbe {
 private static Field field(Class<?> c,String n)throws Exception {Field f=c.getDeclaredField(n);f.setAccessible(true);return f;}
 public static void main(String[] args) throws Exception {
  String model=Build.MODEL,release=Build.VERSION.RELEASE,patch=Build.VERSION.SECURITY_PATCH;
  int sdk=Build.VERSION.SDK_INT;String mode=args[0];boolean photos=mode.equals("photos");
  Class<?> uc=Class.forName("sun.misc.Unsafe");Object unsafe;
  try{unsafe=field(uc,"theUnsafe").get(null);}catch(NoSuchFieldException e){unsafe=field(uc,"THE_ONE").get(null);}
  Class<?> at=Class.forName("android.app.ActivityThread"),bd=Class.forName("android.app.ActivityThread$AppBindData");
  Object thread=uc.getMethod("allocateInstance",Class.class).invoke(unsafe,at),data=uc.getMethod("allocateInstance",Class.class).invoke(unsafe,bd);
  ApplicationInfo app=new ApplicationInfo();app.packageName=photos?"com.google.android.apps.photos":"org.googlebook.pad3.probe";
  field(bd,"appInfo").set(data,app);field(at,"mBoundApplication").set(thread,data);field(at,"sCurrentActivityThread").set(null,thread);
  PhotosCompat.onBind(photos||mode.equals("forged")?"com.google.android.apps.photos":app.packageName);
  boolean preserved=sdk==Build.VERSION.SDK_INT&&release.equals(Build.VERSION.RELEASE)&&patch.equals(Build.VERSION.SECURITY_PATCH);
  boolean expected=photos?Build.MODEL.equals("Pixel XL")&&Boolean.TRUE.equals(PhotosCompat.feature("com.google.android.apps.photos.NEXUS_PRELOAD",0)):model.equals(Build.MODEL)&&PhotosCompat.feature("com.google.android.apps.photos.NEXUS_PRELOAD",0)==null;
  boolean boot=PhotosCompat.class.getClassLoader()==Build.class.getClassLoader();
  String maps=new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("/proc/self/maps")),java.nio.charset.StandardCharsets.UTF_8);
  boolean images=maps.contains("/system/framework/arm64/boot.art")&&maps.contains("/system/framework/arm64/boot-framework-adservices.art");
  boolean packageManager=true;
  if(photos&&boot){Class<?> pm=Class.forName("android.app.ApplicationPackageManager");Object manager=uc.getMethod("allocateInstance",Class.class).invoke(unsafe,pm);packageManager=Boolean.TRUE.equals(pm.getMethod("hasSystemFeature",String.class,int.class).invoke(manager,"com.google.android.apps.photos.NEXUS_PRELOAD",0));}
  JSONObject result=new JSONObject().put("isolated_process_mode",mode).put("before_model",model).put("direct_model",Build.MODEL).put("reflected_model",Build.class.getDeclaredField("MODEL").get(null)).put("sdk",sdk).put("release",release).put("security_patch",patch).put("version_fields_preserved",preserved).put("scope_and_profile_pass",expected).put("helper_from_boot_classloader",boot);
  result.put("coherent_boot_images_mapped",images).put("real_package_manager_hook",packageManager);
  System.out.println(result.toString());
  if(!preserved||!expected||(args.length>1&&(!boot||!images||!packageManager)))throw new AssertionError("ART profile, scope or boot helper probe failed");
 }
}
