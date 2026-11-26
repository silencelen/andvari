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
import io.silencelen.andvari.core.client.recovery.AssistedStep;
import io.silencelen.andvari.core.crypto.CryptoProvider_jvmKt;
import io.silencelen.andvari.core.crypto.KdfParams;
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse;
import io.silencelen.andvari.core.model.wire.AdminPolicy;
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest;
import io.silencelen.andvari.core.model.wire.WireJson;
import io.silencelen.andvari.core.trust.AnswerRead;
import io.silencelen.andvari.core.trust.AnswerToken;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
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
 * The two native sides of operator-assisted recovery, for the web journey that helps an account made in the browser
 * (spec 04 §7): the operator, who enrols through the setup link (signing card 0) exactly as OperatorBootstrap.java does
 * and then lists requests, downloads the recovery copy and uploads the answer token; and the person's NEW native
 * device, which asks for help, proves the address, picks up the answer, checks the account and commits a new password.
 * Everything is the engine's own code from the command-line module. The web has no operator console and no assisted
 * flow of its own (the server refuses its operator sessions; no route of the person's side has a caller in the web).
 *
 *   java -cp "tools/andvari-cli/build/install/andvari-cli/lib/*" AssistPeer.java ORIGIN SETUP_LINK OPERATOR_EMAIL CLOCK_FILE
 *
 * The operator's master password is the first line of standard input. Then one command per line, one JSON line back:
 *   requests | escrow USER_ID FILE | fulfil REQUEST_ID FILE (the tool's whole output) | policy OPS MEM_BYTES |
 *   ask EMAIL | code CODE | poll | commit NEW_PASSWORD | quit
 */
public class AssistPeer {
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
        Host phone = new Host(new MemoryDeviceState(), new MemoryDeviceState(), clock, Host.Companion.defaultHttp(), CryptoProvider_jvmKt.createCryptoProvider(), "cli", "new phone");

        // The operator enrols through the setup link and signs card 0 (OperatorBootstrap.java's steps).
        RecipientStep step = AssistPeer.<RecipientStep>await(c -> operator.getLinks().open(link, GateEntry.PASTE_INVITE, c));
        if (!(step instanceof RecipientStep.Confirm)) throw new IllegalStateException("the setup link did not open to its sign-up form: " + step);
        WireOnboarding onboarding = operator.onboarding(origin, KdfParams.Companion.getDEFAULT());
        RegistrationForm form = new RegistrationForm(email, "Operator", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "cli", "cli", null, false);
        Registration reg = AssistPeer.<Registration>await(c -> onboarding.register(new RegistrationAuth.SetupLink((RecipientStep.Confirm) step), form, c));
        if (!(reg instanceof Registration.Registered)) throw new IllegalStateException("operator registration refused: " + reg);
        confirmKit(onboarding, ((Registration.Registered) reg).getKit());
        HeldSession held = operator.session(origin);
        // The session's own role, which is what the tool's call takes when a Kotlin caller leaves the argument out.
        WireOperatorRoutes op = operator.operator(held, held.getSession().getRole());
        System.out.println("{\"operator\":" + q(((Registration.Registered) reg).getUserId()) + "}");

        AssistedStep at = null;
        for (String line; (line = in.readLine()) != null; ) {
            String[] a = line.trim().split(" ", 3);
            try {
                switch (a[0]) {
                    case "quit" -> System.exit(0);
                    case "requests" -> {
                        Fetched<List<AdminRecoveryRequest>> f = requests(op);
                        if (!(f instanceof Fetched.Ok)) throw new IllegalStateException("requests: " + f);
                        StringBuilder sb = new StringBuilder("{\"requests\":[");
                        boolean first = true;
                        for (AdminRecoveryRequest r : ((Fetched.Ok<List<AdminRecoveryRequest>>) f).getValue()) {
                            if (!first) sb.append(",");
                            first = false;
                            sb.append("{\"requestId\":").append(q(r.getRequestId())).append(",\"userId\":").append(q(r.getUserId())).append(",\"email\":").append(q(r.getEmail())).append(",\"rPub\":").append(q(r.getRPub())).append("}");
                        }
                        System.out.println(sb.append("]}"));
                    }
                    case "escrow" -> {
                        Reauthed<AdminEscrowResponse> r = AssistPeer.<Reauthed<AdminEscrowResponse>>await(c -> op.escrow(a[1], password.toCharArray(), c));
                        if (!(r instanceof Reauthed.Done)) throw new IllegalStateException("escrow: " + r);
                        AdminEscrowResponse e = ((Reauthed.Done<AdminEscrowResponse>) r).getValue();
                        Files.writeString(Path.of(a[2]), WireJson.INSTANCE.getJson().encodeToString(AdminEscrowResponse.Companion.serializer(), e));
                        System.out.println("{\"escrow\":" + q(a[2]) + ",\"sealedB64\":" + q(e.getSealed()) + "}");
                    }
                    case "fulfil" -> {
                        Fetched<List<AdminRecoveryRequest>> f = requests(op);
                        AdminRecoveryRequest row = ((Fetched.Ok<List<AdminRecoveryRequest>>) f).getValue().stream().filter(x -> x.getRequestId().equals(a[1])).findFirst().orElseThrow();
                        String text = Files.readString(Path.of(a[2]), StandardCharsets.UTF_8);
                        AnswerRead read = AnswerToken.INSTANCE.read(text, row.getRequestId(), row.getRPub(), row.getEmail());
                        if (!(read instanceof AnswerRead.Ok)) {
                            System.out.println("{\"fulfil\":\"refused\",\"read\":" + q(String.valueOf(read)) + "}");
                            break;
                        }
                        Reauthed<?> r = AssistPeer.<Reauthed<?>>await(c -> op.fulfil(row.getRequestId(), (AnswerRead.Ok) read, password.toCharArray(), c));
                        System.out.println("{\"fulfil\":" + q(r instanceof Reauthed.Done ? "done" : String.valueOf(r)) + "}");
                    }
                    case "policy" -> {
                        // The operator sets the policy's password-hashing cost (PUT /admin/policy, re-authenticated): OPS MEM_BYTES.
                        Fetched<AdminPolicy> f = AssistPeer.<Fetched<AdminPolicy>>await(c -> op.policy(c));
                        if (!(f instanceof Fetched.Ok)) throw new IllegalStateException("policy: " + f);
                        String json = WireJson.INSTANCE.getJson().encodeToString(AdminPolicy.Companion.serializer(), ((Fetched.Ok<AdminPolicy>) f).getValue());
                        KdfParams kdf = new KdfParams(1, "argon2id13", Long.parseLong(a[1]), Long.parseLong(a[2].trim()));
                        String kdfJson = WireJson.INSTANCE.getJson().encodeToString(KdfParams.Companion.serializer(), kdf);
                        String edited = json.replaceFirst("\"kdfParams\":\\{[^}]*\\}", Matcher.quoteReplacement("\"kdfParams\":" + kdfJson));
                        AdminPolicy next = WireJson.INSTANCE.getJson().decodeFromString(AdminPolicy.Companion.serializer(), edited);
                        Reauthed<AdminPolicy> r = AssistPeer.<Reauthed<AdminPolicy>>await(c -> op.setPolicy(next, password.toCharArray(), c));
                        if (!(r instanceof Reauthed.Done)) throw new IllegalStateException("set policy: " + r);
                        KdfParams now = ((Reauthed.Done<AdminPolicy>) r).getValue().getKdfParams();
                        System.out.println("{\"policy\":\"done\",\"ops\":" + now.getOps() + ",\"memBytes\":" + now.getMemBytes() + "}");
                    }
                    case "ask" -> {
                        AssistedStep s = AssistPeer.<AssistedStep>await(c -> phone.getAssisted().start(a[1], origin, c));
                        if (!(s instanceof AssistedStep.ConfirmTarget)) throw new IllegalStateException("start: " + s);
                        AssistedStep t = s;
                        // No mailbox value: the request is one of the address's ordinary five of the day.
                        at = AssistPeer.<AssistedStep>await(c -> phone.getAssisted().request((AssistedStep.ConfirmTarget) t, null, c));
                        if (!(at instanceof AssistedStep.Requested)) throw new IllegalStateException("request: " + at);
                        System.out.println("{\"requestCode\":" + q(((AssistedStep.Requested) at).getRequestCode()) + "}");
                    }
                    case "code" -> {
                        AssistedStep t = at;
                        at = AssistPeer.<AssistedStep>await(c -> phone.getAssisted().verifyCode((AssistedStep.Requested) t, a[1], c));
                        System.out.println("{\"step\":" + q(at.getClass().getSimpleName()) + (at instanceof AssistedStep.Waiting ? ",\"state\":" + q(((AssistedStep.Waiting) at).getState()) : "") + "}");
                    }
                    case "poll" -> {
                        AssistedStep t = at;
                        at = AssistPeer.<AssistedStep>await(c -> phone.getAssisted().poll(t, c));
                        String extra = at instanceof AssistedStep.CheckAccount ? ",\"accountId\":" + q(((AssistedStep.CheckAccount) at).getAccountId()) : at instanceof AssistedStep.Stopped ? ",\"reason\":" + q(((AssistedStep.Stopped) at).getReason()) : "";
                        System.out.println("{\"step\":" + q(at.getClass().getSimpleName()) + extra + "}");
                    }
                    case "commit" -> {
                        AssistedStep t = at;
                        AssistedStep choose = AssistPeer.<AssistedStep>await(c -> phone.getAssisted().confirmAccount((AssistedStep.CheckAccount) t, true, c));
                        String newPassword = line.trim().substring("commit ".length());
                        at = AssistPeer.<AssistedStep>await(c -> phone.getAssisted().commit((AssistedStep.ChoosePassword) choose, newPassword.toCharArray(), c));
                        if (at instanceof AssistedStep.Recovered) confirmKit(phone.onboarding(origin, KdfParams.Companion.getDEFAULT()), ((AssistedStep.Recovered) at).getNewKit());
                        System.out.println("{\"step\":" + q(at.getClass().getSimpleName()) + (at instanceof AssistedStep.Stopped ? ",\"reason\":" + q(((AssistedStep.Stopped) at).getReason()) : "") + "}");
                    }
                    default -> System.out.println("{\"error\":" + q("unknown command " + a[0]) + "}");
                }
            } catch (Exception e) {
                System.out.println("{\"error\":" + q(String.valueOf(e)) + "}");
            }
        }
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    static Fetched<List<AdminRecoveryRequest>> requests(WireOperatorRoutes op) throws InterruptedException {
        return (Fetched<List<AdminRecoveryRequest>>) AssistPeer.<Object>await((Function1) (Function1<Continuation, Object>) c -> op.recoveryRequests(c));
    }

    static void confirmKit(WireOnboarding onboarding, RevealedKit kit) throws InterruptedException {
        List<Integer> asked = onboarding.kitChallenge(kit);
        Map<Integer, String> typed = new HashMap<>();
        for (Integer n : asked) typed.put(n, kit.getGroups().get(n - 1));
        KitConfirm confirmed = AssistPeer.<KitConfirm>await(c -> onboarding.confirmKit(kit, typed, c));
        if (!(confirmed instanceof KitConfirm.Confirmed)) throw new IllegalStateException("the kit confirmation was not recorded: " + confirmed);
    }
}
