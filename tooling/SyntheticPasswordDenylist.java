import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.keycloak.policy.DenylistPasswordPolicyProviderFactory;
import org.keycloak.policy.DenylistPasswordPolicyProviderFactory.FileBasedPasswordDenylist;

/** Hosted fixture preflight using the exact distribution's native matcher, without a server. */
public final class SyntheticPasswordDenylist {
    public static void main(String[] args) {
        try {
            if (args.length != 1) throw new IllegalArgumentException();
            byte[] input = System.in.readNBytes(16385);
            if (input.length == 0 || input.length > 16384) throw new IllegalArgumentException();
            String[] values = new String(input, StandardCharsets.UTF_8).split("\n", -1);
            if (values.length < 2 || values.length > 65 || !values[values.length - 1].isEmpty()) {
                throw new IllegalArgumentException();
            }
            var denylist = new FileBasedPasswordDenylist(Path.of(args[0]), "password-blacklist.txt",
                    DenylistPasswordPolicyProviderFactory.DEFAULT_FALSE_POSITIVE_PROBABILITY, 0L);
            var output = new StringBuilder();
            for (int i = 0; i < values.length - 1; i++) {
                String value = values[i];
                if (value.isEmpty() || value.length() > 128 || value.chars().anyMatch(c -> c < 32 || c > 126)) {
                    throw new IllegalArgumentException();
                }
                output.append(denylist.contains(DenylistPasswordPolicyProviderFactory.normalizePassword(value))
                        ? "REJECT\n" : "ACCEPT\n");
            }
            System.out.print(output);
        } catch (Throwable refused) {
            String category = refused instanceof LinkageError ? "LINKAGE"
                    : refused instanceof java.io.IOException ? "IO"
                    : refused instanceof IllegalArgumentException ? "ARGUMENT" : "OTHER";
            System.err.println("PREFLIGHT_ERROR:" + category);
            System.exit(2);
        }
    }
}
