import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.builder.BuilderInstruction;
import com.android.tools.smali.dexlib2.builder.BuilderOffsetInstruction;
import com.android.tools.smali.dexlib2.builder.BuilderSwitchPayload;
import com.android.tools.smali.dexlib2.builder.Label;
import com.android.tools.smali.dexlib2.builder.MutableMethodImplementation;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction11x;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction22c;
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction35c;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Field;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.WideLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction35c;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableFieldReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Guarded grafts; the caller pins the original framework and appends the helper DEX. */
public final class GraftFramework {
    private static final String HELPER = "Lcom/android/internal/util/googlebook/PhotosCompat;";
    private static final String THREAD = "Landroid/app/ActivityThread;";
    private static final String BIND_DATA = "Landroid/app/ActivityThread$AppBindData;";
    private static final String APP_INFO = "Landroid/content/pm/ApplicationInfo;";
    private static final String PACKAGE_MANAGER = "Landroid/app/ApplicationPackageManager;";
    private static final String STRING = "Ljava/lang/String;";
    private static final String BOOLEAN = "Ljava/lang/Boolean;";
    private static final String BIND = THREAD + "->handleBindApplication(" + BIND_DATA + ")V";
    private static final String FEATURE = PACKAGE_MANAGER + "->hasSystemFeature(" + STRING + "I)Z";

    private static void require(boolean value, String message) {
        if (!value) throw new IllegalArgumentException(message);
    }

    private static String signature(MethodReference method) {
        StringBuilder out = new StringBuilder(method.getDefiningClass()).append("->")
                .append(method.getName()).append('(');
        for (CharSequence type : method.getParameterTypes()) out.append(type);
        return out.append(')').append(method.getReturnType()).toString();
    }

    private static boolean registers(Instruction instruction, Opcode opcode, int first, int second) {
        return instruction.getOpcode() == opcode
                && ((TwoRegisterInstruction) instruction).getRegisterA() == first
                && ((TwoRegisterInstruction) instruction).getRegisterB() == second;
    }

    private static BuilderInstruction35c call(String name, List<String> arguments, String result,
            int count, int first, int second) {
        return new BuilderInstruction35c(Opcode.INVOKE_STATIC, count, first, second, 0, 0, 0,
                new ImmutableMethodReference(HELPER, name, arguments, result));
    }

    private static Method graft(Method original) {
        String sig = signature(original);
        require(original.getImplementation() != null, "missing implementation: " + sig);
        MutableMethodImplementation code = new MutableMethodImplementation(original.getImplementation());
        List<BuilderInstruction> body = code.getInstructions();
        require(!body.isEmpty(), "empty implementation: " + sig);
        Instruction first = body.get(0);
        Label continuation = code.newLabelForIndex(0);
        List<BuilderInstruction> prefix = new ArrayList<>();
        Set<Label> inbound = new LinkedHashSet<>();
        int insertion = 0;
        if (sig.equals(BIND)) {
            require(code.getRegisterCount() == 28 && (original.getAccessFlags() & 8) == 0
                    && body.size() >= 3
                    && registers(first, Opcode.MOVE_OBJECT_FROM16, 1, 26)
                    && registers(body.get(1), Opcode.MOVE_OBJECT_FROM16, 9, 27)
                    && registers(body.get(2), Opcode.IGET_OBJECT, 0, 1)
                    && ((ReferenceInstruction) body.get(2)).getReference().equals(
                            new ImmutableFieldReference(THREAD, "mDdmSyncStageUpdater",
                                    "Landroid/os/DdmSyncStageUpdater;")),
                    "bind signature/register/entry drift: " + sig);
            ImmutableMethodReference anchor = new ImmutableMethodReference("Landroid/app/Instrumentation;",
                    "basicInit", Collections.singletonList(THREAD), "V");
            int anchors = 0;
            for (int i = 0; i < body.size(); i++) {
                Instruction instruction = body.get(i);
                if (instruction instanceof ReferenceInstruction
                        && ((ReferenceInstruction) instruction).getReference().equals(anchor)) {
                    require(instruction.getOpcode() == Opcode.INVOKE_VIRTUAL
                            && ((Instruction35c) instruction).getRegisterCount() == 2
                            && ((Instruction35c) instruction).getRegisterC() == 0
                            && ((Instruction35c) instruction).getRegisterD() == 1,
                            "basicInit call/register drift");
                    insertion = i + 1;
                    anchors++;
                }
            }
            require(anchors == 1 && insertion + 1 < body.size()
                    && registers(body.get(insertion), Opcode.IGET_OBJECT, 0, 9)
                    && ((ReferenceInstruction) body.get(insertion)).getReference().equals(
                            new ImmutableFieldReference(BIND_DATA, "appInfo", APP_INFO))
                    && registers(body.get(insertion + 1), Opcode.IGET, 0, 0)
                    && ((ReferenceInstruction) body.get(insertion + 1)).getReference().equals(
                            new ImmutableFieldReference(APP_INFO, "flags", "I")),
                    "unique basicInit continuation drift");
            continuation = code.newLabelForIndex(insertion);
            for (BuilderInstruction instruction : body) {
                if (instruction instanceof BuilderOffsetInstruction) {
                    Label target = ((BuilderOffsetInstruction) instruction).getTarget();
                    if (target.getLocation() == continuation.getLocation()) inbound.add(target);
                }
                if (instruction instanceof BuilderSwitchPayload) {
                    for (var element : ((BuilderSwitchPayload) instruction).getSwitchElements()) {
                        Label target = element.getTarget();
                        if (target.getLocation() == continuation.getLocation()) inbound.add(target);
                    }
                }
            }
            require(!inbound.isEmpty(), "common bind continuation has no inbound branches");
            prefix.add(new BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 9,
                    new ImmutableFieldReference(BIND_DATA, "appInfo", APP_INFO)));
            prefix.add(new BuilderInstruction22c(Opcode.IGET_OBJECT, 0, 0,
                    new ImmutableFieldReference(APP_INFO, "packageName", STRING)));
            prefix.add(call("onBind", Collections.singletonList(STRING), "V", 1, 0, 0));
        } else {
            require(sig.equals(FEATURE) && code.getRegisterCount() == 6
                    && (original.getAccessFlags() & 8) == 0
                    && first.getOpcode() == Opcode.CONST_4
                    && ((OneRegisterInstruction) first).getRegisterA() == 0
                    && ((WideLiteralInstruction) first).getWideLiteral() == 0,
                    "feature signature/register/entry drift: " + sig);
            prefix.add(call("feature", Arrays.asList(STRING, "I"), BOOLEAN, 2, 4, 5));
            prefix.add(new BuilderInstruction11x(Opcode.MOVE_RESULT_OBJECT, 0));
            prefix.add(new BuilderInstruction21t(Opcode.IF_EQZ, 0, continuation));
            prefix.add(new BuilderInstruction35c(Opcode.INVOKE_VIRTUAL, 1, 0, 0, 0, 0, 0,
                    new ImmutableMethodReference(BOOLEAN, "booleanValue", Collections.emptyList(), "Z")));
            prefix.add(new BuilderInstruction11x(Opcode.MOVE_RESULT, 0));
            prefix.add(new BuilderInstruction11x(Opcode.RETURN, 0));
        }
        Instruction originalEntry = body.get(insertion);
        for (int i = 0; i < prefix.size(); i++) code.addInstruction(insertion + i, prefix.get(i));
        // Retarget control flow only; original try boundaries and debug items keep their locations.
        for (Label label : inbound) {
            label.getLocation().getLabels().remove(label);
            prefix.get(0).getLocation().getLabels().add(label);
        }
        require(code.getInstructions().get(insertion + prefix.size()) == originalEntry
                && continuation.getLocation().getIndex() == insertion + prefix.size(),
                "continuation no longer points to original entry: " + sig);
        return new ImmutableMethod(original.getDefiningClass(), original.getName(), original.getParameters(),
                original.getReturnType(), original.getAccessFlags(), original.getAnnotations(),
                original.getHiddenApiRestrictions(), code);
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 3 && args[2].equals("app"),
                "usage: GraftFramework input.dex output.dex app");
        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        require(!input.toRealPath().equals(output.toAbsolutePath().normalize())
                && (!Files.exists(output) || !Files.isSameFile(input, output)), "input/output must differ");
        Set<String> targets = new LinkedHashSet<>(Arrays.asList(BIND, FEATURE));
        DexFile original = DexFileFactory.loadDexFile(args[0], null);
        List<ClassDef> classes = new ArrayList<>();
        Set<String> changed = new LinkedHashSet<>();
        Set<String> changedClasses = new LinkedHashSet<>();
        for (ClassDef cls : original.getClasses()) {
            require(!cls.getType().equals(HELPER), "helper must be in a separate appended DEX");
            List<Method> methods = new ArrayList<>();
            boolean modified = false;
            for (Method method : cls.getMethods()) {
                String sig = signature(method);
                if (targets.contains(sig)) {
                    require(changed.add(sig), "duplicate target: " + sig);
                    methods.add(graft(method));
                    modified = true;
                } else {
                    methods.add(method);
                }
            }
            if (modified) {
                changedClasses.add(cls.getType());
                // Materialize once: dex-backed field iterables share hidden-API readers.
                List<Field> fields = new ArrayList<>();
                for (Field field : cls.getFields()) fields.add(field);
                classes.add(new ImmutableClassDef(cls.getType(), cls.getAccessFlags(), cls.getSuperclass(),
                        cls.getInterfaces(), cls.getSourceFile(), cls.getAnnotations(), fields, methods));
            } else {
                classes.add(cls);
            }
        }
        require(changed.equals(targets), "exact two-method target set drift: " + changed);
        DexPool.writeTo(args[1], new ImmutableDexFile(original.getOpcodes(), classes));
        System.out.println("{\"changed_signatures\":[\"" + String.join("\",\"", changed)
                + "\"],\"changed_classes\":[\"" + String.join("\",\"", changedClasses)
                + "\"],\"changed_count\":" + changed.size() + "}");
    }
}
