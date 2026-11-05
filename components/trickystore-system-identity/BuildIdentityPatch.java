import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;
import com.android.tools.smali.dexlib2.*;
import com.android.tools.smali.dexlib2.iface.*;
import com.android.tools.smali.dexlib2.immutable.*;
import com.android.tools.smali.baksmali.*;
import com.android.tools.smali.baksmali.Adaptors.ClassDefinition;
import com.android.tools.smali.baksmali.formatter.BaksmaliWriter;
import com.android.tools.smali.smali.*;

public final class BuildIdentityPatch {
    static final String INPUT_SHA = "47d2350898e50696a653f5a5d0ee199b1b147053d253f832c84f55d08d80376e";
    static final String TARGET = "Lw6;";
    static final String HELPER = "Lorg/googlebook/pad3/compat/SystemIdentityAppId;";
    static final String SIGNATURE = ".method public static c(Ljava/security/KeyPair;Lv6;Lo90;IILjava/security/KeyPair;)Ljava/security/cert/X509Certificate;";
    static final List<String> PARAMS = Arrays.asList("Ljava/security/KeyPair;", "Lv6;", "Lo90;", "I", "I", "Ljava/security/KeyPair;");

    static void check(boolean ok, String message) {
        if (!ok) throw new IllegalArgumentException(message);
    }

    static String sha(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }

    static boolean target(Method method) {
        return method.getName().equals("c") && method.getParameterTypes().equals(PARAMS)
                && method.getReturnType().equals("Ljava/security/cert/X509Certificate;");
    }

    static String text(ClassDef cls) throws IOException {
        BaksmaliOptions options = new BaksmaliOptions();
        options.apiLevel = 28;
        options.sequentialLabels = true;
        options.accessorComments = false;
        StringWriter text = new StringWriter();
        BaksmaliWriter writer = new BaksmaliWriter(text);
        ClassDefinition definition = new ClassDefinition(options, cls);
        definition.writeTo(writer);
        writer.flush();
        check(!definition.hadValidationErrors(), "disassembly validation " + cls.getType());
        return text.toString();
    }

    static int methodStart(String text) {
        int start = text.indexOf(SIGNATURE);
        check(start >= 0 && text.indexOf(SIGNATURE, start + 1) < 0, "unique target method");
        return start;
    }

    static int methodEnd(String text, int start) {
        int end = text.indexOf(".end method", start);
        check(end > start, "target end");
        return end + ".end method".length();
    }

    static String withoutTarget(String text) {
        int start = methodStart(text);
        return text.substring(0, start) + text.substring(methodEnd(text, start));
    }

    static Matcher unique(String expression, String text, String message) {
        Matcher first = Pattern.compile(expression).matcher(text);
        check(first.find(), message + " missing");
        Matcher second = Pattern.compile(expression).matcher(text);
        check(second.find() && !second.find(), message + " ambiguous");
        return first;
    }

    static String inject(String original) {
        int start = methodStart(original), end = methodEnd(original, start);
        String method = original.substring(start, end);
        check(!method.contains(HELPER) && !method.contains(":pad3_"), "already patched");
        check(method.contains("    .registers 49\n"), "target register layout");
        Matcher join = unique("    move-object/from16 v4, v17\\n\\n    (:goto_[0-9a-f]+)\\n    iget-object v0, v1, Lv6;->N:Ljava/lang/Boolean;", method, "identity continuation");
        String continuation = join.group(1);
        Matcher site = unique("    if-eqz v13, :cond_[0-9a-f]+\\n\\n(?=    sget-object v5, Lgx;->a:Lgx;)", method, "identity branch");
        String branch = "    invoke-static {v2}, " + HELPER + "->forUid(I)[B\n\n"
                + "    move-result-object v5\n\n"
                + "    if-eqz v5, :pad3_ordinary_uid\n\n"
                + "    move/from16 v33, v0\n\n"
                + "    move-object/from16 v35, v4\n\n"
                + "    move-object/from16 v29, v6\n\n"
                + "    move-object/from16 v28, v13\n\n"
                + "    new-instance v4, Li9;\n\n"
                + "    invoke-direct {v4, v5}, Ll0;-><init>([B)V\n\n"
                + "    const/4 v12, 0x0\n\n"
                + "    goto/16 " + continuation + "\n\n"
                + "    :pad3_ordinary_uid\n";
        String patched = method.substring(0, site.end()) + branch + method.substring(site.end());
        return original.substring(0, start) + patched + original.substring(end);
    }

    public static void main(String[] args) throws Exception {
        check(args.length == 3, "expected input DEX, helper DEX, output directory");
        Path input = Paths.get(args[0]), helperPath = Paths.get(args[1]), root = Paths.get(args[2]);
        check(sha(input).equals(INPUT_SHA), "unsupported module input SHA-256");
        check(Arrays.equals(Arrays.copyOf(Files.readAllBytes(input), 8), new byte[]{100,101,120,10,48,51,57,0}), "input must be DEX039");
        DexFile original = DexFileFactory.loadDexFile(input.toFile(), Opcodes.forApi(28));
        ClassDef originalTarget = null;
        for (ClassDef cls : original.getClasses()) {
            check(!cls.getType().equals(HELPER), "helper collision");
            if (cls.getType().equals(TARGET)) {
                check(originalTarget == null, "duplicate target class");
                originalTarget = cls;
            }
        }
        check(originalTarget != null && original.getClasses().size() == 3308, "exact original class layout");
        Path smali = root.resolve("w6.smali");
        Files.writeString(smali, inject(text(originalTarget)));
        SmaliOptions assemble = new SmaliOptions();
        assemble.apiLevel = 28;
        assemble.jobs = 2;
        assemble.verboseErrors = true;
        assemble.outputDexFile = root.resolve("patched-method.dex").toString();
        check(Smali.assemble(assemble, smali.toString()), "assemble patched class");
        DexFile patch = DexFileFactory.loadDexFile(root.resolve("patched-method.dex").toFile(), original.getOpcodes());
        DexFile helper = DexFileFactory.loadDexFile(helperPath.toFile(), original.getOpcodes());
        check(patch.getClasses().size() == 1, "patch class count");
        check(helper.getClasses().size() == 1 && helper.getClasses().iterator().next().getType().equals(HELPER), "helper exact scope");
        ClassDef patchClass = patch.getClasses().iterator().next();
        check(patchClass.getType().equals(TARGET), "patch class type");
        Method replacement = null;
        for (Method method : patchClass.getMethods()) if (target(method)) {
            check(replacement == null, "duplicate patch method");
            replacement = method;
        }
        check(replacement != null, "patch method exists");
        List<ClassDef> classes = new ArrayList<>();
        int replaced = 0;
        for (ClassDef cls : original.getClasses()) {
            if (!cls.getType().equals(TARGET)) { classes.add(cls); continue; }
            List<Method> methods = new ArrayList<>();
            for (Method method : cls.getMethods()) {
                if (!target(method)) { methods.add(method); continue; }
                replaced++;
                check(method.getImplementation().getRegisterCount() == 49 && replacement.getImplementation().getRegisterCount() == 49, "no register movement");
                methods.add(new ImmutableMethod(method.getDefiningClass(), method.getName(), method.getParameters(),
                        method.getReturnType(), method.getAccessFlags(), method.getAnnotations(), method.getHiddenApiRestrictions(), replacement.getImplementation()));
            }
            classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(), cls.getInterfaces(),
                    cls.getSourceFile(), cls.getAnnotations(), cls.getFields(), methods));
        }
        check(replaced == 1, "one replacement");
        classes.add(helper.getClasses().iterator().next());
        Path output = root.resolve("classes.dex");
        DexFileFactory.writeDexFile(output.toString(), new ImmutableDexFile(original.getOpcodes(), classes));
        check(Arrays.equals(Arrays.copyOf(Files.readAllBytes(output), 8), new byte[]{100,101,120,10,48,51,57,0}), "output must be DEX039");
        DexFile result = DexFileFactory.loadDexFile(output.toFile(), original.getOpcodes());
        Map<String, ClassDef> resultClasses = new HashMap<>();
        for (ClassDef cls : result.getClasses()) check(resultClasses.put(cls.getType(), cls) == null, "duplicate type");
        int unchanged = 0;
        for (ClassDef cls : original.getClasses()) {
            ClassDef actual = resultClasses.get(cls.getType());
            check(actual != null, "missing original class");
            String before = text(cls), after = text(actual);
            if (cls.getType().equals(TARGET)) {
                check(withoutTarget(before).equals(withoutTarget(after)), "other w6 metadata/methods changed");
                unique(Pattern.quote(HELPER + "->forUid(I)[B"), after, "helper call");
            } else {
                check(before.equals(after), "unexpected change: " + cls.getType());
                unchanged++;
            }
        }
        check(unchanged == 3307 && result.getClasses().size() == original.getClasses().size() + 1, "only helper added");
        Files.writeString(root.resolve("validation.json"), "{\n"
                + "  \"input_sha256\": \"" + sha(input) + "\",\n"
                + "  \"patched_sha256\": \"" + sha(output) + "\",\n"
                + "  \"output_format\": \"DEX039\",\n"
                + "  \"changed_method\": \"w6.c(KeyPair,v6,o90,int,int,KeyPair)\",\n"
                + "  \"ordinary_classes_unchanged\": " + unchanged + ",\n"
                + "  \"other_target_methods_and_metadata_unchanged\": true,\n"
                + "  \"helper_classes_added\": 1,\n"
                + "  \"device_deployed\": false\n}\n");
        System.out.println("PASS: one method changed; 3307 other classes and other w6 methods identical; DEX039");
    }
}
