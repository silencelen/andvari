import io.silencelen.andvari.cli.Host;
import io.silencelen.andvari.core.client.MemoryDeviceState;
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
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.EmptyCoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.BuildersKt;

/**
 * The first operator of a test instance, for the web journeys (design §6.7, §9.5): opens the setup link, registers
 * the operator account, signs card 0 and confirms the kit, all with the engine's own code from the command-line
 * module. The web client has no link flow and never signs a card (§13), so the journeys cannot do this themselves.
 *
 * Run by harness.ts as a single-file program on the command-line module's class path:
 *   java -cp "tools/andvari-cli/build/install/andvari-cli/lib/*" OperatorBootstrap.java ORIGIN SETUP_LINK EMAIL CLOCK_FILE
 * The master password is read from the first line of standard input, never from the command line. Prints one JSON
 * line: {"userId": "..."}.
 */
public class OperatorBootstrap {
    @SuppressWarnings("unchecked")
    static <T> T await(Function1<Continuation<? super T>, Object> call) throws InterruptedException {
        return (T) BuildersKt.runBlocking(EmptyCoroutineContext.INSTANCE, (scope, cont) -> call.invoke((Continuation<? super T>) cont));
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("usage: OperatorBootstrap ORIGIN SETUP_LINK EMAIL CLOCK_FILE  (the password on stdin)");
            System.exit(2);
        }
        String origin = args[0];
        String link = args[1];
        String email = args[2];
        Path clockFile = Path.of(args[3]);
        String password = new BufferedReader(new InputStreamReader(System.in)).readLine();
        if (password == null || password.isEmpty()) {
            System.err.println("no password on stdin");
            System.exit(2);
        }

        // The device shares the server's test clock, as the engine's own journeys do.
        kotlin.jvm.functions.Function0<Long> clock = () -> {
            try {
                return Long.parseLong(Files.readString(clockFile).trim());
            } catch (Exception e) {
                return System.currentTimeMillis();
            }
        };
        // The module's own HTTP client and crypto provider, the platform "cli"; the device is named "operator".
        Host host = new Host(new MemoryDeviceState(), new MemoryDeviceState(), clock, Host.Companion.defaultHttp(), CryptoProvider_jvmKt.createCryptoProvider(), "cli", "operator");

        RecipientStep step = OperatorBootstrap.<RecipientStep>await(c -> host.getLinks().open(link, GateEntry.PASTE_INVITE, c));
        if (!(step instanceof RecipientStep.Confirm)) {
            System.err.println("the setup link did not open to its sign-up form: " + step);
            System.exit(1);
        }
        RecipientStep.Confirm confirm = (RecipientStep.Confirm) step;
        WireOnboarding onboarding = host.onboarding(origin, KdfParams.Companion.getDEFAULT());
        RegistrationForm form = new RegistrationForm(email, "Operator", password.toCharArray(), true, RecoveryChoiceKind.PRIVATE, "cli", "cli", null, false);
        Registration reg = OperatorBootstrap.<Registration>await(c -> onboarding.register(new RegistrationAuth.SetupLink(confirm), form, c));
        if (!(reg instanceof Registration.Registered)) {
            String why = reg instanceof Registration.Refused ? ((Registration.Refused) reg).getCode() : String.valueOf(reg);
            System.err.println("registration through the setup link was refused: " + why);
            System.exit(1);
        }
        Registration.Registered ok = (Registration.Registered) reg;
        if (ok.getCardPending()) {
            System.err.println("card 0 was not stored");
            System.exit(1);
        }
        RevealedKit kit = ok.getKit();
        List<Integer> asked = onboarding.kitChallenge(kit);
        Map<Integer, String> typed = new HashMap<>();
        for (Integer n : asked) typed.put(n, kit.getGroups().get(n - 1));
        KitConfirm confirmed = OperatorBootstrap.<KitConfirm>await(c -> onboarding.confirmKit(kit, typed, c));
        if (!(confirmed instanceof KitConfirm.Confirmed)) {
            System.err.println("the kit confirmation was not recorded: " + confirmed);
            System.exit(1);
        }
        System.out.println("{\"userId\":\"" + ok.getUserId() + "\"}");
        System.exit(0);
    }
}
