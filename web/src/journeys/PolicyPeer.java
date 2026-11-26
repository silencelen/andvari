import io.silencelen.andvari.cli.HeldSession;
import io.silencelen.andvari.cli.Host;
import io.silencelen.andvari.core.client.MemoryDeviceState;
import io.silencelen.andvari.core.client.account.Fetched;
import io.silencelen.andvari.core.client.account.Reauthed;
import io.silencelen.andvari.core.client.account.WireOperatorRoutes;
import io.silencelen.andvari.core.client.link.RecipientStep;
import io.silencelen.andvari.core.client.onboard.KitConfirm;
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind;
import io.silencelen.andvari.core.client.onboard.Registration;
import io.silencelen.andvari.core.client.onboard.RegistrationAuth;
import io.silencelen.andvari.core.client.onboard.RegistrationForm;
import io.silencelen.andvari.core.client.onboard.RevealedKit;
import io.silencelen.andvari.core.client.onboard.WireOnboarding;
import io.silencelen.andvari.core.client.pin.GateEntry;
import io.silencelen.andvari.core.crypto.CryptoProvider_jvmKt;
import io.silencelen.andvari.core.crypto.KdfParams;
import io.silencelen.andvari.core.model.wire.AdminPolicy;
import io.silencelen.andvari.core.model.wire.WireJson;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.BuildersKt;

/**
 * The operator who writes the server's policy while a web journey runs: enrols through the setup link (signing card 0)
 * exactly as OperatorBootstrap.java does, keeps that native session, and then writes the policy on each command, through
 * the shared code's own operator call (PUT /admin/policy, re-authenticated with the master password). The web cannot do
 * this: the server refuses a browser's operator session, and the web has no operator console.
 *
 *   java -cp "tools/andvari-cli/build/install/andvari-cli/lib/*" PolicyPeer.java ORIGIN SETUP_LINK OPERATOR_EMAIL CLOCK_FILE
 *
 * The operator's master password is the first line of standard input. Then one command per line, one JSON line back:
 *   offline-cache on|off   (the policy's offlineCacheAllowed)
 *   kdf OPS MEM_BYTES      (the policy's password-hashing cost)
 *   quit
 * Every other field of the policy is written back as the server served it.
 */
public class PolicyPeer {
    @SuppressWarnings("unchecked")
    static <T> T await(Function1<Continuation<? super T>, Object> call) throws InterruptedException {
        return (T) BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE, (scope, cont) -> call.invoke((Continuation<? super T>) cont));
    }

    static String q(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }

    public static void main(String[] args) throws Exception {
        String origin = args[0];
        String link = args[1];
        String email = args[2];
        Path clockFile = Path.of(args[3]);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String password = in.readLine();
        kotlin.jvm.functions.Function0<Long> clock = () -> {
            try {
                return Long.parseLong(Files.readString(clockFile).trim());
            } catch (Exception e) {
                return System.currentTimeMillis();
            }
        };
        Host operator = new Host(new MemoryDeviceState(), new MemoryDeviceState(), clock, Host.Companion.defaultHttp(), CryptoProvider_jvmKt.createCryptoProvider(), "cli", "operator");

        // The operator enrols through the setup link and signs card 0 (OperatorBootstrap.java's steps).
        RecipientStep step = PolicyPeer.<RecipientStep>await(c -> operator.getLinks().open(link, GateEntry.PASTE_INVITE, c));
        if (!(step instanceof RecipientStep.Confirm)) throw new IllegalStateException("the setup link did not open to its sign-up form: " + step);
        WireOnboarding onboarding = operator.onboarding(origin, KdfParams.Companion.getDEFAULT());
        RegistrationForm form = new RegistrationForm(email, "Operator", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "cli", "cli", null, false);
        Registration reg = PolicyPeer.<Registration>await(c -> onboarding.register(new RegistrationAuth.SetupLink((RecipientStep.Confirm) step), form, c));
        if (!(reg instanceof Registration.Registered)) throw new IllegalStateException("operator registration refused: " + reg);
        RevealedKit kit = ((Registration.Registered) reg).getKit();
        List<Integer> asked = onboarding.kitChallenge(kit);
        Map<Integer, String> typed = new HashMap<>();
        for (Integer n : asked) typed.put(n, kit.getGroups().get(n - 1));
        KitConfirm confirmed = PolicyPeer.<KitConfirm>await(c -> onboarding.confirmKit(kit, typed, c));
        if (!(confirmed instanceof KitConfirm.Confirmed)) throw new IllegalStateException("the kit confirmation was not recorded: " + confirmed);
        HeldSession held = operator.session(origin);
        // The session's own role, which is what the tool's call takes when a Kotlin caller leaves the argument out.
        WireOperatorRoutes op = operator.operator(held, held.getSession().getRole());
        System.out.println("{\"operator\":" + q(((Registration.Registered) reg).getUserId()) + "}");

        for (String line; (line = in.readLine()) != null; ) {
            String[] a = line.trim().split(" ");
            try {
                switch (a[0]) {
                    case "quit" -> System.exit(0);
                    case "offline-cache" -> {
                        boolean allowed = switch (a[1]) {
                            case "on" -> true;
                            case "off" -> false;
                            default -> throw new IllegalArgumentException("offline-cache on|off, not " + a[1]);
                        };
                        AdminPolicy now = write(op, password, json -> json.replaceFirst("\"offlineCacheAllowed\":(true|false)", "\"offlineCacheAllowed\":" + allowed));
                        System.out.println("{\"offlineCacheAllowed\":" + now.getOfflineCacheAllowed() + "}");
                    }
                    case "kdf" -> {
                        KdfParams kdf = new KdfParams(1, "argon2id13", Long.parseLong(a[1]), Long.parseLong(a[2]));
                        String kdfJson = WireJson.INSTANCE.getJson().encodeToString(KdfParams.Companion.serializer(), kdf);
                        AdminPolicy now = write(op, password, json -> json.replaceFirst("\"kdfParams\":\\{[^}]*\\}", Matcher.quoteReplacement("\"kdfParams\":" + kdfJson)));
                        System.out.println("{\"ops\":" + now.getKdfParams().getOps() + ",\"memBytes\":" + now.getKdfParams().getMemBytes() + "}");
                    }
                    default -> System.out.println("{\"error\":" + q("unknown command " + a[0]) + "}");
                }
            } catch (Exception e) {
                System.out.println("{\"error\":" + q(String.valueOf(e)) + "}");
            }
        }
    }

    /** Reads the policy as served, changes one field in its JSON, and writes it back through the operator's call. */
    static AdminPolicy write(WireOperatorRoutes op, String password, java.util.function.UnaryOperator<String> edit) throws InterruptedException {
        Fetched<AdminPolicy> f = PolicyPeer.<Fetched<AdminPolicy>>await(c -> op.policy(c));
        if (!(f instanceof Fetched.Ok)) throw new IllegalStateException("policy: " + f);
        String json = WireJson.INSTANCE.getJson().encodeToString(AdminPolicy.Companion.serializer(), ((Fetched.Ok<AdminPolicy>) f).getValue());
        String edited = edit.apply(json);
        AdminPolicy next = WireJson.INSTANCE.getJson().decodeFromString(AdminPolicy.Companion.serializer(), edited);
        Reauthed<AdminPolicy> r = PolicyPeer.<Reauthed<AdminPolicy>>await(c -> op.setPolicy(next, password.toCharArray(), c));
        if (!(r instanceof Reauthed.Done)) throw new IllegalStateException("set policy: " + r);
        return ((Reauthed.Done<AdminPolicy>) r).getValue();
    }
}
