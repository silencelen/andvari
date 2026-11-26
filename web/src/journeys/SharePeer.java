import io.silencelen.andvari.cli.AccountSession;
import io.silencelen.andvari.cli.Host;
import io.silencelen.andvari.cli.PlainItem;
import io.silencelen.andvari.core.client.MemoryDeviceState;
import io.silencelen.andvari.core.client.link.CompareResult;
import io.silencelen.andvari.core.client.link.CreateOutcome;
import io.silencelen.andvari.core.client.link.CreatorStep;
import io.silencelen.andvari.core.client.link.RecipientStep;
import io.silencelen.andvari.core.client.log.Adoption;
import io.silencelen.andvari.core.client.log.AppendOutcome;
import io.silencelen.andvari.core.client.log.LogAction;
import io.silencelen.andvari.core.client.log.VaultLogStatus;
import io.silencelen.andvari.core.client.onboard.KitConfirm;
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind;
import io.silencelen.andvari.core.client.onboard.Registration;
import io.silencelen.andvari.core.client.onboard.RegistrationAuth;
import io.silencelen.andvari.core.client.onboard.RegistrationForm;
import io.silencelen.andvari.core.client.onboard.RevealedKit;
import io.silencelen.andvari.core.client.onboard.WireOnboarding;
import io.silencelen.andvari.core.client.pin.GateEntry;
import io.silencelen.andvari.core.crypto.CryptoProvider_jvmKt;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.BuildersKt;
import kotlinx.serialization.json.JsonElement;
import kotlinx.serialization.json.JsonElementKt;
import kotlinx.serialization.json.JsonObject;
import kotlinx.serialization.json.JsonPrimitive;

/**
 * Two native accounts for the web's shared-vault journey (design §3, §6): alice and bob register through enrol links
 * and connect through a connect link, each typing the other's code, all with the engine's own code from the
 * command-line module. Alice then creates the vault "Family", adds bob as a writer and saves an item into it. The web
 * cannot make contacts (§13), so the journey's browser signs in as bob afterwards.
 *
 * Run by the journey as a long-lived child on the command-line module's class path:
 *   java -cp "tools/andvari-cli/build/install/andvari-cli/lib/*" SharePeer.java ORIGIN CLOCK_FILE ENROL_A ENROL_B
 * The master password of both accounts is the first line of standard input. The first output line is
 * {"alice": ..., "bob": ..., "vault": ...}. Then one command per input line, one JSON answer line each, as alice:
 *   sync                 -> {"items": [names], "members": [userIds]}
 *   add writer|reader    -> {"ok": true} or {"error": "..."}
 *   remove               -> {"ok": true} or {"error": "..."}
 *   accept VAULT         -> {"adopted": bool, "owner": userId, "name": "..."} or {"error": "..."}: answers the share of VAULT
 *   vault VAULT          -> {"items": [names], "members": [userIds], "status": "...", "writable": bool}
 *   put VAULT NAME       -> {"ok": true} or {"error": "..."}: alice saves an item of her own named NAME into VAULT
 *   quit
 */
public class SharePeer {
    @SuppressWarnings("unchecked")
    static <T> T await(Function1<Continuation<? super T>, Object> call) throws InterruptedException {
        return (T) BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE, (scope, cont) -> call.invoke((Continuation<? super T>) cont));
    }

    static void fail(String why) {
        System.err.println(why);
        System.exit(1);
    }

    static String q(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    static String register(Host h, String origin, String link, String email, String name, String password) throws Exception {
        RecipientStep step = SharePeer.<RecipientStep>await(c -> h.getLinks().open(link, GateEntry.PASTE_INVITE, c));
        if (step instanceof RecipientStep.TrustGate) {
            final RecipientStep gate = step;
            step = SharePeer.<RecipientStep>await(c -> h.getLinks().proceed(gate, c));
        }
        if (!(step instanceof RecipientStep.Confirm)) fail("the enrol link did not open to its sign-up form: " + step);
        RecipientStep.Confirm confirm = (RecipientStep.Confirm) step;
        WireOnboarding o = h.onboarding(origin, io.silencelen.andvari.core.crypto.KdfParams.Companion.getDEFAULT());
        RegistrationForm form = new RegistrationForm(email, name, password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "cli", "cli", null, false);
        Registration reg = SharePeer.<Registration>await(c -> o.register(new RegistrationAuth.EnrolLink(confirm), form, c));
        if (!(reg instanceof Registration.Registered)) fail("registration of " + email + " was refused: " + reg);
        Registration.Registered ok = (Registration.Registered) reg;
        h.rememberName(origin, ok.getUserId(), name);
        RevealedKit kit = ok.getKit();
        Map<Integer, String> typed = new HashMap<>();
        for (Integer n : o.kitChallenge(kit)) typed.put(n, kit.getGroups().get(n - 1));
        KitConfirm k = SharePeer.<KitConfirm>await(c -> o.confirmKit(kit, typed, c));
        if (!(k instanceof KitConfirm.Confirmed)) fail("the kit of " + email + " was not confirmed: " + k);
        return ok.getUserId();
    }

    static String appendAs(AccountSession a, String vaultId, LogAction action) throws Exception {
        AppendOutcome r = SharePeer.<AppendOutcome>await(c -> a.getLogs().append(vaultId, action, c));
        if (!(r instanceof AppendOutcome.Appended)) return null;
        return ((AppendOutcome.Appended) r).getState().getVaultId();
    }

    static JsonObject doc(String name) {
        Map<String, JsonElement> login = new HashMap<>();
        login.put("username", JsonElementKt.JsonPrimitive("u"));
        login.put("password", JsonElementKt.JsonPrimitive("p-" + name));
        Map<String, JsonElement> m = new HashMap<>();
        m.put("type", JsonElementKt.JsonPrimitive("login"));
        m.put("name", JsonElementKt.JsonPrimitive(name));
        m.put("login", new JsonObject(login));
        return new JsonObject(m);
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) fail("usage: SharePeer ORIGIN CLOCK_FILE ENROL_A ENROL_B  (the password on stdin)");
        String origin = args[0];
        Path clockFile = Path.of(args[1]);
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String password = in.readLine();
        if (password == null || password.isEmpty()) fail("no password on stdin");
        kotlin.jvm.functions.Function0<Long> clock = () -> {
            try {
                return Long.parseLong(Files.readString(clockFile).trim());
            } catch (Exception e) {
                return System.currentTimeMillis();
            }
        };
        Host ah = new Host(new MemoryDeviceState(), new MemoryDeviceState(), clock, Host.Companion.defaultHttp(), CryptoProvider_jvmKt.createCryptoProvider(), "cli", "alice");
        Host bh = new Host(new MemoryDeviceState(), new MemoryDeviceState(), clock, Host.Companion.defaultHttp(), CryptoProvider_jvmKt.createCryptoProvider(), "cli", "bob");
        String aliceId = register(ah, origin, args[2], "alice@example.org", "Alice", password);
        String bobId = register(bh, origin, args[3], "bob@example.org", "Bob", password);

        // Connect (design §6): alice creates a connect link, bob answers, both type the other side's code.
        CreateOutcome created = SharePeer.<CreateOutcome>await(c -> ah.getLinks().create("connect", 86_400_000L, List.of(), c));
        if (!(created instanceof CreateOutcome.Created)) fail("no connect link: " + created);
        String url = ((CreateOutcome.Created) created).getLink().getUrl();
        RecipientStep opened = SharePeer.<RecipientStep>await(c -> bh.getLinks().open(url, GateEntry.PASTE_INVITE, c));
        if (!(opened instanceof RecipientStep.Confirm)) fail("the connect link did not open to its confirm step: " + opened);
        RecipientStep answered = SharePeer.<RecipientStep>await(c -> bh.getLinks().confirm((RecipientStep.Confirm) opened, c));
        if (!(answered instanceof RecipientStep.Answered)) fail("the answer was not posted: " + answered);
        List<?> processed = SharePeer.<List<?>>await(c -> ah.getLinks().processAnswers(c));
        if (processed.size() != 1 || !(processed.get(0) instanceof CreatorStep.Processed)) fail("alice did not process the answer: " + processed);
        RecipientStep revealed = SharePeer.<RecipientStep>await(c -> bh.getLinks().awaitReveal((RecipientStep.Answered) answered, c));
        if (!(revealed instanceof RecipientStep.CodeReady)) fail("the reveal did not open: " + revealed);
        String codeA = ah.getLinks().code(bobId);
        String codeB = bh.getLinks().code(aliceId);
        CompareResult ma = SharePeer.<CompareResult>await(c -> ah.getLinks().typeCode(bobId, codeB, c));
        CompareResult mb = SharePeer.<CompareResult>await(c -> bh.getLinks().typeCode(aliceId, codeA, c));
        if (!(ma instanceof CompareResult.Matched) || !(mb instanceof CompareResult.Matched)) fail("the codes did not match: " + ma + " " + mb);

        AccountSession a = ah.account(origin);
        SharePeer.<Object>await(c -> a.sync(c));
        String vault = appendAs(a, null, new LogAction.Create("Family", null));
        if (vault == null) fail("alice could not create the vault");
        if (appendAs(a, vault, new LogAction.Add(bobId, "writer", false, false)) == null) fail("alice could not add bob");
        SharePeer.<Object>await(c -> a.sync(c));
        final String v = vault;
        Object saved = SharePeer.<Object>await(c -> a.putItem(v, doc("from alice"), null, c));
        if (((kotlin.Pair<?, ?>) saved).getSecond() != null) fail("alice's item was refused: " + saved);
        System.out.println("{\"alice\":" + q(aliceId) + ",\"bob\":" + q(bobId) + ",\"vault\":" + q(vault) + "}");
        System.out.flush();

        String line;
        while ((line = in.readLine()) != null) {
            String[] cmd = line.trim().split(" ");
            String out;
            switch (cmd[0]) {
                case "sync": {
                    Object r = SharePeer.<Object>await(c -> a.sync(c));
                    List<String> names = new ArrayList<>();
                    for (PlainItem it : a.items(v)) names.add(q(((JsonPrimitive) it.getDoc().get("name")).getContent()));
                    List<String> members = new ArrayList<>();
                    VaultLogStatus st = a.getLogs().status(v);
                    if (st instanceof VaultLogStatus.Verified) for (String m : ((VaultLogStatus.Verified) st).getState().getMembers().keySet()) members.add(q(m));
                    out = "{\"sync\":" + q(String.valueOf(r)) + ",\"items\":" + names + ",\"members\":" + members + "}";
                    break;
                }
                case "add":
                    out = appendAs(a, v, new LogAction.Add(bobId, cmd[1], false, false)) != null ? "{\"ok\":true}" : "{\"error\":\"add\"}";
                    break;
                case "remove":
                    out = appendAs(a, v, new LogAction.Remove(bobId)) != null ? "{\"ok\":true}" : "{\"error\":\"remove\"}";
                    break;
                case "accept": {
                    // accept VAULT: the share of VAULT is asked (§3.6) and alice accepts it.
                    final String id = cmd[1];
                    SharePeer.<Object>await(c -> a.sync(c));
                    Adoption ad = SharePeer.<Adoption>await(c -> a.getLogs().adoption(id, c));
                    if (!(ad instanceof Adoption.AskAccept)) {
                        out = "{\"error\":" + q("not asked: " + ad) + "}";
                        break;
                    }
                    final Adoption.AskAccept ask = (Adoption.AskAccept) ad;
                    Adoption r = SharePeer.<Adoption>await(c -> a.getLogs().answerIncoming(ask, true, c));
                    SharePeer.<Object>await(c -> a.sync(c));
                    out = "{\"adopted\":" + (r instanceof Adoption.Adopted) + ",\"owner\":" + q(ask.getOwner()) + ",\"name\":" + q(ask.getVaultName()) + "}";
                    break;
                }
                case "vault": {
                    // vault VAULT: alice's view of VAULT after a sync: its items, its verified members, and its log status.
                    final String id = cmd[1];
                    SharePeer.<Object>await(c -> a.sync(c));
                    List<String> names = new ArrayList<>();
                    for (PlainItem it : a.items(id)) names.add(q(((JsonPrimitive) it.getDoc().get("name")).getContent()));
                    VaultLogStatus st = SharePeer.<VaultLogStatus>await(c -> a.getLogs().refresh(id, null, null, true, c));
                    List<String> members = new ArrayList<>();
                    if (st instanceof VaultLogStatus.Verified) for (String m : ((VaultLogStatus.Verified) st).getState().getMembers().keySet()) members.add(q(m));
                    out = "{\"items\":" + names + ",\"members\":" + members + ",\"status\":" + q(st.getClass().getSimpleName()) + ",\"writable\":" + a.writeAllowed(id) + "}";
                    break;
                }
                case "put": {
                    // put VAULT NAME: alice saves an item of her own, named NAME (one word), into VAULT.
                    final String id = cmd[1];
                    final String name = cmd[2];
                    SharePeer.<Object>await(c -> a.sync(c));
                    Object put = SharePeer.<Object>await(c -> a.putItem(id, doc(name), null, c));
                    Object refused = ((kotlin.Pair<?, ?>) put).getSecond();
                    out = refused == null ? "{\"ok\":true}" : "{\"error\":" + q(String.valueOf(refused)) + "}";
                    break;
                }
                case "quit":
                    System.exit(0);
                    return;
                default:
                    out = "{\"error\":" + q("unknown command " + cmd[0]) + "}";
            }
            System.out.println(out);
            System.out.flush();
        }
        System.exit(0);
    }
}
